//! Findings aggregator + reporting outputs (M10).
//!
//! During a run, workers/session/kerberoast append findings here (thread-safe).
//! At the end the CLI renders: an end-of-run summary, optional structured files
//! (`<base>.json` / `.grep.txt` / `.raw.txt` / `.cred.hc<mode>`), an always-on
//! auto-saved JSON under the user data dir, and an optional webhook POST.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const secret_file = @import("../util/secret_file.zig");
const net = std.Io.net;
const krb5 = @import("krb5");
const SpinLock = @import("../util/spinlock.zig").SpinLock;
const Logger = @import("../util/log.zig").Logger;

/// What a finding represents.
pub const Kind = enum {
    valid_user, // enumeration hit
    valid_cred, // working username+password
    expired_win, // valid cred whose password is expired (still a win)
    asrep_roast, // captured $krb5asrep$ hash
    tgs_roast, // captured $krb5tgs$ hash
    locked, // account locked out during the run

    pub fn label(self: Kind) []const u8 {
        return switch (self) {
            .valid_user => "valid-user",
            .valid_cred => "valid-cred",
            .expired_win => "expired-cred",
            .asrep_roast => "asrep-roast",
            .tgs_roast => "tgs-roast",
            .locked => "locked",
        };
    }
};

/// One finding. All slices are OWNED by the Report.
pub const Finding = struct {
    kind: Kind,
    user: []const u8,
    /// Password (creds) or hash (roasts), when applicable. OWNED.
    secret: ?[]const u8 = null,
    /// Free-text note (e.g. SPN, expiry). OWNED.
    note: ?[]const u8 = null,
    hashcat_mode: ?u32 = null,
};

/// The Windows event-log footprint this tool generates, shown in the summary
/// and --help so the operator knows what blue-team will see.
pub const footprint_note =
    "Windows footprint: failed pre-auth -> Event 4771; AS-REQ/TGT -> 4768; TGS-REQ (kerberoast) -> 4769.";

pub const Report = struct {
    allocator: Allocator,
    lock: SpinLock = .{},
    realm: []const u8,
    domain: []const u8,
    dc: []const u8,
    command: []const u8,
    findings: std.ArrayListUnmanaged(Finding) = .empty,

    pub fn init(allocator: Allocator, command: []const u8, domain: []const u8, realm: []const u8, dc: []const u8) Report {
        return .{ .allocator = allocator, .command = command, .domain = domain, .realm = realm, .dc = dc };
    }

    pub fn deinit(self: *Report) void {
        for (self.findings.items) |f| {
            self.allocator.free(f.user);
            if (f.secret) |s| self.allocator.free(s);
            if (f.note) |n| self.allocator.free(n);
        }
        self.findings.deinit(self.allocator);
    }

    fn add(self: *Report, kind: Kind, user: []const u8, secret: ?[]const u8, note: ?[]const u8, mode: ?u32) void {
        self.lock.lock();
        defer self.lock.unlock();
        const u = self.allocator.dupe(u8, user) catch return;
        const s = if (secret) |x| (self.allocator.dupe(u8, x) catch null) else null;
        const n = if (note) |x| (self.allocator.dupe(u8, x) catch null) else null;
        self.findings.append(self.allocator, .{ .kind = kind, .user = u, .secret = s, .note = n, .hashcat_mode = mode }) catch {
            self.allocator.free(u);
            if (s) |x| self.allocator.free(x);
            if (n) |x| self.allocator.free(x);
        };
    }

    pub fn addValidUser(self: *Report, user: []const u8) void {
        self.add(.valid_user, user, null, null, null);
    }
    pub fn addValidCred(self: *Report, user: []const u8, password: []const u8, note: ?[]const u8) void {
        self.add(.valid_cred, user, password, note, null);
    }
    pub fn addExpiredWin(self: *Report, user: []const u8, password: []const u8) void {
        self.add(.expired_win, user, password, "password expired", null);
    }
    pub fn addAsrepRoast(self: *Report, user: []const u8, hash: []const u8, mode: ?u32) void {
        self.add(.asrep_roast, user, hash, null, mode);
    }
    pub fn addTgsRoast(self: *Report, user: []const u8, hash: []const u8, spn: []const u8, mode: ?u32) void {
        self.add(.tgs_roast, user, hash, spn, mode);
    }
    pub fn addLocked(self: *Report, user: []const u8) void {
        self.add(.locked, user, null, null, null);
    }

    pub const Counts = struct {
        valid_users: u32 = 0,
        valid_creds: u32 = 0,
        expired: u32 = 0,
        asrep: u32 = 0,
        tgs: u32 = 0,
        locked: u32 = 0,
    };

    pub fn counts(self: *Report) Counts {
        var c = Counts{};
        for (self.findings.items) |f| switch (f.kind) {
            .valid_user => c.valid_users += 1,
            .valid_cred => c.valid_creds += 1,
            .expired_win => c.expired += 1,
            .asrep_roast => c.asrep += 1,
            .tgs_roast => c.tgs += 1,
            .locked => c.locked += 1,
        };
        return c;
    }

    pub fn hasFindings(self: *Report) bool {
        return self.findings.items.len > 0;
    }

    /// Print a findings breakdown + the Windows footprint note to the logger.
    pub fn summary(self: *Report, logger: *Logger) void {
        const c = self.counts();
        logger.info("Findings: {d} valid user(s), {d} working cred(s) ({d} expired-but-valid), {d} AS-REP + {d} TGS hash(es), {d} locked", .{ c.valid_users, c.valid_creds, c.expired, c.asrep, c.tgs, c.locked });
        logger.info("{s}", .{footprint_note});
    }

    // -- serializers --

    /// success-only "grep" lines: `<kind>\t<user>[\t<secret>]`.
    pub fn writeGrep(self: *Report, w: *std.Io.Writer) !void {
        for (self.findings.items) |f| {
            try w.writeAll(f.kind.label());
            try w.writeByte('\t');
            try writeGrepField(w, f.user);
            try w.print("@{s}", .{self.domain});
            if (f.secret) |s| {
                try w.writeByte('\t');
                try writeGrepField(w, s);
            }
            try w.writeByte('\n');
        }
    }

    /// Human-readable raw report.
    pub fn writeRaw(self: *Report, w: *std.Io.Writer) !void {
        try w.print("kerbrutez report — command={s} realm={s} dc={s}\n", .{ self.command, self.realm, self.dc });
        const c = self.counts();
        try w.print("valid_users={d} valid_creds={d} expired={d} asrep={d} tgs={d} locked={d}\n\n", .{ c.valid_users, c.valid_creds, c.expired, c.asrep, c.tgs, c.locked });
        for (self.findings.items) |f| {
            try w.print("[{s}] {s}@{s}", .{ f.kind.label(), f.user, self.domain });
            if (f.note) |n| try w.print(" ({s})", .{n});
            if (f.secret) |s| {
                if (f.hashcat_mode) |m| {
                    try w.print(" -m {d}\n  {s}\n", .{ m, s });
                } else {
                    try w.print(" : {s}\n", .{s});
                }
            } else {
                try w.writeByte('\n');
            }
        }
    }

    /// JSON document: `{ "meta": {...}, "findings": [ {...} ] }`.
    pub fn writeJson(self: *Report, w: *std.Io.Writer) !void {
        try w.print("{{\"meta\":{{\"command\":\"{s}\",\"realm\":\"", .{self.command});
        try writeJsonString(w, self.realm);
        try w.print("\",\"dc\":\"", .{});
        try writeJsonString(w, self.dc);
        const c = self.counts();
        try w.print("\",\"counts\":{{\"valid_users\":{d},\"valid_creds\":{d},\"expired\":{d},\"asrep\":{d},\"tgs\":{d},\"locked\":{d}}}}},\"findings\":[", .{ c.valid_users, c.valid_creds, c.expired, c.asrep, c.tgs, c.locked });
        for (self.findings.items, 0..) |f, i| {
            if (i > 0) try w.writeByte(',');
            try w.print("{{\"kind\":\"{s}\",\"user\":\"", .{f.kind.label()});
            try writeJsonString(w, f.user);
            try w.writeByte('"');
            if (f.secret) |s| {
                try w.print(",\"secret\":\"", .{});
                try writeJsonString(w, s);
                try w.writeByte('"');
            }
            if (f.note) |n| {
                try w.print(",\"note\":\"", .{});
                try writeJsonString(w, n);
                try w.writeByte('"');
            }
            if (f.hashcat_mode) |m| try w.print(",\"hashcat_mode\":{d}", .{m});
            try w.writeByte('}');
        }
        try w.writeAll("]}");
    }

    /// Write captured hashes that hashcat cannot crack in any mode to
    /// `<base>.cred.nomode` (today: AES AS-REPs — see util/hash.asRepHashcatMode).
    /// Crack these with John the Ripper's krb5asrep format, or re-capture with
    /// `--etype rc4`.
    fn writeNoModeHashFile(self: *Report, io: Io, base: []const u8) !void {
        var any = false;
        for (self.findings.items) |f| {
            if (f.hashcat_mode != null) continue;
            if (f.secret == null) continue;
            if (f.kind != .asrep_roast and f.kind != .tgs_roast) continue;
            any = true;
            break;
        }
        if (!any) return;

        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}.cred.nomode", .{base}) catch return;
        const file = secret_file.create(io, path, .{ .truncate = true }) catch return;
        defer file.close(io);
        var wbuf: [8192]u8 = undefined;
        var fw = file.writerStreaming(io, &wbuf);
        for (self.findings.items) |f| {
            if (f.hashcat_mode != null) continue;
            const s = f.secret orelse continue;
            if (f.kind != .asrep_roast and f.kind != .tgs_roast) continue;
            fw.interface.print("{s}\n", .{s}) catch {};
        }
        fw.interface.flush() catch {};
    }

    /// Write captured hashes grouped by hashcat mode to `<base>.cred.hc<mode>`
    /// (one file per mode), ready for `hashcat -m <mode>`.
    pub fn writeCredHashFiles(self: *Report, io: Io, base: []const u8) !void {
        // Captured hashes that have NO hashcat mode (AES AS-REPs — hashcat has
        // no mode that cracks them) still go to a file of their own. Otherwise
        // they would appear only on the console and inside the json/grep/raw
        // reports, and an operator whose workflow is `hashcat <base>.cred.hc*`
        // would silently never see them.
        try self.writeNoModeHashFile(io, base);

        // Collect distinct modes present.
        var modes = std.ArrayListUnmanaged(u32).empty;
        defer modes.deinit(self.allocator);
        for (self.findings.items) |f| {
            const m = f.hashcat_mode orelse continue;
            if (f.secret == null) continue;
            var seen = false;
            for (modes.items) |x| {
                if (x == m) seen = true;
            }
            if (!seen) try modes.append(self.allocator, m);
        }
        for (modes.items) |m| {
            var path_buf: [512]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}.cred.hc{d}", .{ base, m }) catch continue;
            const file = secret_file.create(io, path, .{ .truncate = true }) catch continue;
            defer file.close(io);
            var wbuf: [8192]u8 = undefined;
            var fw = file.writerStreaming(io, &wbuf);
            for (self.findings.items) |f| {
                if (f.hashcat_mode != m) continue;
                const s = f.secret orelse continue;
                fw.interface.print("{s}\n", .{s}) catch {};
            }
            fw.interface.flush() catch {};
        }
    }
};

/// Minimal JSON string escaping for the manual serializer.
/// Write one tab-separated field, escaping anything that would break the
/// format's "one record per line, tab-delimited" contract.
///
/// Passwords come from the operator's wordlist, and a wordlist line may contain
/// TABS (only \r is stripped when lines are split). An unescaped tab silently
/// splits the password into extra columns — `cut -f3` on
/// `valid-cred<TAB>alice@corp<TAB>pa<TAB>ss` yields "pa", so the operator
/// records a credential that does not work and discards a real finding.
/// Escaping is lossless and unambiguous, so the original value is recoverable.
fn writeGrepField(w: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '\t' => try w.writeAll("\\t"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        else => try w.writeByte(c),
    };
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) !void {
    for (s) |c| switch (c) {
        '"' => try w.writeAll("\\\""),
        '\\' => try w.writeAll("\\\\"),
        '\n' => try w.writeAll("\\n"),
        '\r' => try w.writeAll("\\r"),
        '\t' => try w.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try w.print("\\u{x:0>4}", .{c}),
        else => try w.writeByte(c),
    };
}

/// POST `body` (JSON) to a plain-HTTP webhook URL ("http://host[:port]/path").
/// Best-effort, fire-and-forget; HTTPS is not yet supported (returns an error).
pub fn postWebhook(io: Io, allocator: Allocator, url: []const u8, body: []const u8) !void {
    if (std.mem.startsWith(u8, url, "https://")) return error.HttpsWebhookUnsupported;
    const rest = if (std.mem.startsWith(u8, url, "http://")) url[7..] else url;
    const slash = std.mem.indexOfScalar(u8, rest, '/');
    const authority = if (slash) |i| rest[0..i] else rest;
    const path = if (slash) |i| rest[i..] else "/";
    var host = authority;
    var port: u16 = 80;
    if (std.mem.lastIndexOfScalar(u8, authority, ':')) |ci| {
        host = authority[0..ci];
        port = std.fmt.parseInt(u16, authority[ci + 1 ..], 10) catch 80;
    }

    // net.IpAddress.resolve only parses IP literals (no DNS). Fall back the same
    // way the KDC path does: hosts file first (an operator who pinned the name
    // meant it), then a DNS A lookup via /etc/resolv.conf.
    const addr = net.IpAddress.resolve(io, host, port) catch
        krb5.dns.lookupHostsFile(allocator, io, host, port) orelse
        krb5.dns.resolveHost(allocator, io, host, port, null) catch return error.WebhookResolveFailed;
    var stream = net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp }) catch return error.WebhookConnectFailed;
    defer stream.close(io);

    const req = try std.fmt.allocPrint(allocator, "POST {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: kerbrutez\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ path, host, body.len, body });
    defer allocator.free(req);

    var wbuf: [1024]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    w.interface.writeAll(req) catch return error.WebhookWriteFailed;
    w.interface.flush() catch return error.WebhookWriteFailed;
    // Drain a little of the response so the server completes the request.
    var rbuf: [512]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    _ = r.interface.discardRemaining() catch {};
}

const testing = std.testing;

test "report aggregates counts and renders json/grep" {
    // Synthetic fixtures only — never real credentials (see test_integration.zig
    // for live checks that read creds from a gitignored .env).
    const a = testing.allocator;
    var rep = Report.init(a, "passwordspray", "example.local", "EXAMPLE.LOCAL", "dc:88");
    defer rep.deinit();
    rep.addValidCred("alice", "P@ssw0rd-fixture", null);
    rep.addValidUser("bob");
    rep.addTgsRoast("svc_db", "$krb5tgs$18$svc_db$...", "MSSQLSvc/db.example.local:1433", 19700);
    rep.addLocked("carol");

    const c = rep.counts();
    try testing.expectEqual(@as(u32, 1), c.valid_creds);
    try testing.expectEqual(@as(u32, 1), c.valid_users);
    try testing.expectEqual(@as(u32, 1), c.tgs);
    try testing.expectEqual(@as(u32, 1), c.locked);

    var buf: [2048]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try rep.writeJson(&w);
    const json = w.buffered();
    try testing.expect(std.mem.indexOf(u8, json, "\"valid_creds\":1") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"kind\":\"tgs-roast\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"hashcat_mode\":19700") != null);

    var gbuf: [1024]u8 = undefined;
    var gw = std.Io.Writer.fixed(&gbuf);
    try rep.writeGrep(&gw);
    try testing.expect(std.mem.indexOf(u8, gw.buffered(), "valid-cred\talice@example.local\tP@ssw0rd-fixture") != null);
}

test "json escaping" {
    var buf: [128]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeJsonString(&w, "a\"b\\c\n");
    try testing.expectEqualStrings("a\\\"b\\\\c\\n", w.buffered());
}


// REGRESSION TEST. The .grep.txt format promises one record per line, tab
// separated. Passwords come from the operator's wordlist and a wordlist line may
// contain a TAB (line splitting only strips \r), which used to be emitted raw:
// `valid-cred<TAB>alice@corp.example.com<TAB>pa<TAB>ss` — four fields, so
// `cut -f3` returned "pa" and the operator would record a credential that does
// not work, discarding a real finding.
test "writeGrep keeps one record per line and three fields, whatever the secret contains" {
    const a = testing.allocator;
    var rep = Report.init(a, "passwordspray", "corp.example.com", "CORP.EXAMPLE.COM", "dc:88");
    defer rep.deinit();
    rep.addValidCred("alice", "pa\tss", null);
    rep.addValidCred("bob", "line1\nline2", null);
    rep.addValidCred("carol", "back\\slash", null);

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try rep.writeGrep(&w);
    const out = w.buffered();

    var records: usize = 0;
    var it = std.mem.tokenizeScalar(u8, out, '\n');
    while (it.next()) |line| {
        records += 1;
        var fields: usize = 0;
        var ft = std.mem.splitScalar(u8, line, '\t');
        while (ft.next()) |_| fields += 1;
        try testing.expectEqual(@as(usize, 3), fields); // label, user@domain, secret
    }
    try testing.expectEqual(@as(usize, 3), records); // one per finding, not more

    // Escapes are lossless: the original bytes are recoverable.
    try testing.expect(std.mem.indexOf(u8, out, "pa\\tss") != null);
    try testing.expect(std.mem.indexOf(u8, out, "line1\\nline2") != null);
    try testing.expect(std.mem.indexOf(u8, out, "back\\\\slash") != null);
}

test "captured hashes with no hashcat mode still reach a file" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rep = Report.init(a, "userenum", "corp.example.com", "CORP.EXAMPLE.COM", "dc:88");
    defer rep.deinit();
    // An RC4 AS-REP (crackable, mode 18200) and an AES one (no hashcat mode).
    rep.addAsrepRoast("rc4user", "$krb5asrep$23$rc4user@CORP:aa$bb", 18200);
    rep.addAsrepRoast("aesuser", "$krb5asrep$18$aesuser@CORP:cc$dd", null);

    const base = "test_report_modes";
    defer {
        Io.Dir.cwd().deleteFile(io, base ++ ".cred.hc18200") catch {};
        Io.Dir.cwd().deleteFile(io, base ++ ".cred.nomode") catch {};
    }
    try rep.writeCredHashFiles(io, base);

    // The AES hash must not vanish just because hashcat has no mode for it.
    const nomode = try readAll(a, io, base ++ ".cred.nomode");
    defer a.free(nomode);
    try testing.expect(std.mem.indexOf(u8, nomode, "$krb5asrep$18$aesuser") != null);
    try testing.expect(std.mem.indexOf(u8, nomode, "rc4user") == null);

    // And the crackable one still lands in its mode file.
    const hc = try readAll(a, io, base ++ ".cred.hc18200");
    defer a.free(hc);
    try testing.expect(std.mem.indexOf(u8, hc, "$krb5asrep$23$rc4user") != null);
}

fn readAll(a: Allocator, io: Io, path: []const u8) ![]u8 {
    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.reader(io, &buf);
    return r.interface.allocRemaining(a, .unlimited);
}
