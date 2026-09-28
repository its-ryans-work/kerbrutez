//! Ingest a user list produced by NetExec / CrackMapExec (`nxc`).
//!
//! An operator on a black-box engagement gets their target user list from nxc,
//! typically one of:
//!
//!   nxc smb  <dc> -u U -p P --users-export users.txt   # clean file, 1 name/line
//!   nxc ldap <dc> -u U -p P --users-export users.txt   # clean file, 1 name/line
//!   nxc smb  <dc> -u U -p P --users        | tee cap    # CONSOLE table, tee'd
//!   nxc ldap <dc> -u U -p P --active-users | tee cap    # CONSOLE table, tee'd
//!
//! The clean `--users-export` file is just bare sAMAccountNames, one per line —
//! trivial. The catch is `--active-users`: NetExec prints active-only to the
//! CONSOLE but `--users-export` still writes ALL users (enabled + disabled) to
//! the file, so the ONLY way to get an active-only list is to capture the
//! console (`| tee`, `| cat`, redirect). That console output looks like:
//!
//!   SMB   10.0.0.10   445   DC01   [*] Windows Server 2022 ...          <- banner
//!   SMB   10.0.0.10   445   DC01   [+] corp.local\svc-scan:Passw0rd!     <- CRED (operator's own pw!)
//!   LDAP  10.0.0.10   389   DC01   [*] Total records returned: 12 ...   <- info
//!   SMB   10.0.0.10   445   DC01   -Username-   -Last PW Set-  -BadPW-  <- header
//!   SMB   10.0.0.10   445   DC01   alice.admin  2024-01-15 ..  0  desc  <- DATA ROW
//!
//! Feeding that straight into a spray is the footgun this parser exists to
//! neutralise. It MUST:
//!   * extract only the real sAMAccountName from a data row (the first content
//!     token after the `PROTO IP PORT HOST` prefix),
//!   * NEVER emit a banner/status/`[+]` line — the `[+]` line carries the
//!     operator's OWN password, which would otherwise be sprayed as a username,
//!   * drop anything that isn't a plausible account name rather than spray it
//!     (a mis-parsed token sprayed as a username is a wasted bad-password guess;
//!     worse, a token that reduces to a REAL account name would burn that
//!     account's lockout budget from a file the operator only meant to inspect),
//!   * collapse case-insensitive duplicates (AD is case-insensitive; one account
//!     must not get two spray budgets — see engine/budget.zig).
//!
//! The parser is format-agnostic and classifies PER LINE, so a mixed capture
//! (banners + table + a few hand-added names) still yields a clean roster.

const std = @import("std");
const Allocator = std.mem.Allocator;
const username_util = @import("../util/username.zig");

/// NetExec protocol tags as they appear in the log-line prefix (`PROTO  IP  PORT
/// HOST  ...`). Matched case-insensitively. A capture whose protocol isn't here
/// simply isn't recognised as a console line — its rows then fail the bare-name
/// validation and are dropped, which fails safe (drop, never spray garbage).
const known_protos = [_][]const u8{
    "SMB", "SMB3", "LDAP", "LDAPS", "WINRM", "RDP", "SSH", "FTP", "MSSQL", "WMI", "NFS", "VNC", "NBSS",
};

/// Well-known accounts that are never useful spray targets. Kept in the roster
/// (the operator may want to see them) but counted so the caller can warn.
const well_known_nontargets = [_][]const u8{ "krbtgt", "guest" };

pub const Result = struct {
    allocator: Allocator,
    /// Deduped usernames, first-seen spelling preserved. OWNED (each + the slice).
    users: [][]const u8,
    /// Lines that looked like content but weren't a plausible account name.
    dropped: usize = 0,
    /// nxc banner / status / `[+]` credential / header lines skipped.
    banners: usize = 0,
    /// Duplicate names collapsed (case-insensitive).
    duplicates: usize = 0,
    /// True if any line matched the nxc console-log prefix (operator fed a
    /// tee'd/redirected console capture rather than a clean --users-export file).
    console_format: bool = false,
    /// How many emitted names are well-known non-targets (krbtgt/Guest).
    well_known: usize = 0,

    pub fn deinit(self: *Result) void {
        for (self.users) |u| self.allocator.free(u);
        self.allocator.free(self.users);
    }
};

/// Is `name` a plausible sAMAccountName? Deliberately strict: it is the last
/// gate before a token becomes a spray target, so it rejects the reserved
/// characters AD forbids in a sAMAccountName (which also rejects a leaked
/// `user:password` token — the `:` fails here — and IP:port fragments), anything
/// with embedded whitespace, and anything with no alphanumerics (e.g. the
/// `-Username-` header). Length is capped generously at 256; AD caps
/// sAMAccountName at 20, but rejecting a slightly-longer real name is worse than
/// accepting a too-long one (the KDC just answers PRINCIPAL_UNKNOWN).
pub fn plausibleSam(name: []const u8) bool {
    if (name.len == 0 or name.len > 256) return false;
    var has_alnum = false;
    for (name) |c| {
        switch (c) {
            // Characters AD disallows in a sAMAccountName, plus whitespace.
            '"', '/', '\\', '[', ']', ':', ';', '|', '=', ',', '+', '*', '?', '<', '>', '@', ' ', '\t', '\r', '\n' => return false,
            else => {},
        }
        if (std.ascii.isAlphanumeric(c)) has_alnum = true;
    }
    return has_alnum;
}

fn isKnownProto(tok: []const u8) bool {
    for (known_protos) |p| if (std.ascii.eqlIgnoreCase(tok, p)) return true;
    return false;
}

/// Does this line match the nxc console-log prefix `PROTO IP PORT HOST ...`?
/// Used both to classify a data row and to REJECT such a line when it is fed
/// straight to a spray (it must be ingested with `ldapenum --nxc` first).
pub fn isConsoleLine(line_in: []const u8) bool {
    const line = std.mem.trim(u8, line_in, " \t\r\n");
    var it = std.mem.tokenizeAny(u8, line, " \t");
    const f0 = it.next() orelse return false;
    const f1 = it.next() orelse return false;
    _ = f1;
    const f2 = it.next() orelse return false;
    _ = it.next() orelse return false; // host
    _ = it.next() orelse return false; // some content
    return isKnownProto(f0) and allDigits(f2);
}

/// Is this line nxc chrome that must NEVER be treated as a spray target — a
/// console-prefixed line (banner, `[+] dom\user:pass` credential, `-Username-`
/// header, or a data row that belongs in an ingest, not a raw spray), or a
/// bare-pasted banner/header? Feeding such lines to passwordspray/bruteforce
/// otherwise sprays a space-filled bogus principal (silent no-op) or, worse,
/// reduces `[+] dom\svc-scan:pass` to the operator's OWN account and sprays it.
pub fn isIngestArtifact(line_in: []const u8) bool {
    const line = std.mem.trim(u8, line_in, " \t\r\n");
    if (line.len == 0) return false;
    if (line[0] == '[') return true;
    if (std.mem.startsWith(u8, line, "-Username-")) return true;
    return isConsoleLine(line);
}

fn allDigits(tok: []const u8) bool {
    if (tok.len == 0) return false;
    for (tok) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

fn isWellKnown(name: []const u8) bool {
    for (well_known_nontargets) |w| if (std.ascii.eqlIgnoreCase(name, w)) return true;
    return false;
}

/// Classification of one input line.
const Line = union(enum) {
    /// A blank/whitespace-only line (counted as nothing).
    blank,
    /// A recognised nxc banner / status / `[+]` credential / `-Username-` header
    /// line — deliberately carries no account name.
    banner,
    /// Looked like content but wasn't a plausible account name — dropped so it
    /// is never sprayed.
    dropped,
    /// A real account name (BORROW: sub-slice of the input line).
    user: []const u8,
};

/// Classify one line and, for a data row, extract the sAMAccountName.
/// `console_seen` is set when the line matched the nxc console-log prefix, so the
/// caller can report that a console capture (not a clean export) was fed.
fn classifyLine(line_in: []const u8, console_seen: *bool) Line {
    const line = std.mem.trim(u8, line_in, " \t\r\n");
    if (line.len == 0) return .blank;

    // Global chrome guard: a bare banner/status/credential line ("[*]", "[+] ..",
    // "[-].."), or the "-Username-" table header, that was pasted WITHOUT the
    // `PROTO IP PORT HOST` prefix. sAMAccountNames can contain neither '[' nor
    // the literal header, so this never rejects a real name — but it stops a
    // hand-copied `[+] dom\user:pass` line from ever reaching name extraction.
    if (line[0] == '[') return .banner;
    if (std.mem.startsWith(u8, line, "-Username-")) return .banner;

    // Split into whitespace-delimited fields to test for the nxc console prefix
    // `PROTO  IP  PORT  HOST  <content...>`.
    var it = std.mem.tokenizeAny(u8, line, " \t");
    var fields: [5][]const u8 = undefined;
    var n: usize = 0;
    while (n < 5) : (n += 1) {
        fields[n] = it.next() orelse break;
    }

    // Console line: PROTO IP PORT HOST then content. Port must be all-digits.
    if (n == 5 and isKnownProto(fields[0]) and allDigits(fields[2])) {
        console_seen.* = true;
        const content0 = fields[4];
        // Banner/status/credential/header rows carry no account name.
        if (content0.len > 0 and content0[0] == '[') return .banner;
        if (std.mem.eql(u8, content0, "-Username-")) return .banner;
        // A data row's first content token is the sAMAccountName. Reduce it the
        // same way as the bare path (strip a DOMAIN\ / @realm the table might
        // carry) so both paths normalise identically before validation.
        const reduced_row = username_util.formatUsername(content0) catch return .dropped;
        return if (plausibleSam(reduced_row)) .{ .user = reduced_row } else .dropped;
    }

    // Not a console line. Treat as a clean-export / hand-written entry: it must
    // reduce (UPN / DOWN-LEVEL / padding stripped) to a single plausible name.
    // Anything with embedded whitespace or reserved chars is dropped, not
    // sprayed — that is how a stray un-prefixed table row gets rejected instead
    // of turning into a bogus (or real!) target.
    const reduced = username_util.formatUsername(line) catch return .dropped;
    return if (plausibleSam(reduced)) .{ .user = reduced } else .dropped;
}

/// Parse nxc output (clean export OR tee'd console, smb OR ldap, --users /
/// --active-users / --users-export). OWNERSHIP: call `Result.deinit`.
pub fn parse(allocator: Allocator, content_in: []const u8) !Result {
    // Strip a leading UTF-8 BOM if present (some redirect/tee pipelines add one).
    const content = if (std.mem.startsWith(u8, content_in, "\xEF\xBB\xBF"))
        content_in[3..]
    else
        content_in;

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |u| allocator.free(u);
        out.deinit(allocator);
    }
    // Case-insensitive dedup: lower-cased key -> void. Keys owned here, freed
    // before return (the emitted list owns its own first-seen-spelling copies).
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var kit = seen.keyIterator();
        while (kit.next()) |k| allocator.free(k.*);
        seen.deinit(allocator);
    }

    var res = Result{ .allocator = allocator, .users = &.{} };

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw| {
        var console_seen = false;
        const classified = classifyLine(raw, &console_seen);
        res.console_format = res.console_format or console_seen;

        const cand = switch (classified) {
            .blank => continue,
            .banner => {
                res.banners += 1;
                continue;
            },
            .dropped => {
                res.dropped += 1;
                continue;
            },
            .user => |u| u,
        };

        // Dedup case-insensitively.
        var lbuf: [256]u8 = undefined;
        const key = lowerKey(&lbuf, cand);
        if (seen.contains(key)) {
            res.duplicates += 1;
            continue;
        }
        // Once `owned_key` is in `seen`, the `seen` deinit defer owns it — do NOT
        // also hold an errdefer for it, or a later OOM would free it here AND
        // again in that defer (double-free). Handle the put failure inline
        // instead, and only errdefer the parts not yet handed off.
        const owned_key = try allocator.dupe(u8, key);
        seen.put(allocator, owned_key, {}) catch |e| {
            allocator.free(owned_key);
            return e;
        };

        const owned_user = try allocator.dupe(u8, cand);
        errdefer allocator.free(owned_user);
        try out.append(allocator, owned_user);
        if (isWellKnown(cand)) res.well_known += 1;
    }

    res.users = try out.toOwnedSlice(allocator);
    return res;
}

/// Lower-case `s` into `buf` for use as a dedup key. Falls back to the original
/// slice if it somehow exceeds the buffer (plausibleSam caps names at 256).
fn lowerKey(buf: *[256]u8, s: []const u8) []const u8 {
    if (s.len > buf.len) return s;
    for (s, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..s.len];
}

// ===========================================================================
// Tests — fixtures mirror REAL nxc 1.5.x output captured against a live DC.
// ===========================================================================
const testing = std.testing;

fn expectHasUser(res: *const Result, name: []const u8) !void {
    for (res.users) |u| if (std.mem.eql(u8, u, name)) return;
    std.debug.print("expected user '{s}' not found in parsed roster\n", .{name});
    return error.UserMissing;
}
fn expectNoUser(res: *const Result, name: []const u8) !void {
    for (res.users) |u| if (std.ascii.eqlIgnoreCase(u, name)) {
        std.debug.print("user '{s}' should NOT be in the roster\n", .{name});
        return error.UnexpectedUser;
    };
}

test "clean --users-export: one bare sAMAccountName per line" {
    const in =
        "administrator\nGuest\nkrbtgt\nsvc-scan\nalice.admin\nbob.jones\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 6), r.users.len);
    try expectHasUser(&r, "alice.admin");
    try expectHasUser(&r, "administrator");
    try testing.expect(!r.console_format);
    try testing.expectEqual(@as(usize, 0), r.dropped);
}

test "tee'd smb --users console: extract names, drop banners/header, never the [+] password" {
    const in =
        "SMB                      10.0.0.10      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:None)\n" ++
        "SMB                      10.0.0.10      445    DC01             [+] corp.local\\svc-scan:Passw0rd! \n" ++
        "SMB                      10.0.0.10      445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-\n" ++
        "SMB                      10.0.0.10      445    DC01             administrator                      2024-01-15 09:00:00 0       Built-in account for administering the computer/domain\n" ++
        "SMB                      10.0.0.10      445    DC01             alice.admin                   2024-01-15 09:05:10 0\n" ++
        "SMB                      10.0.0.10      445    DC01             [*] Enumerated 12 local users: CORP\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expect(r.console_format);
    try expectHasUser(&r, "administrator");
    try expectHasUser(&r, "alice.admin");
    // The operator's OWN password must never surface as a username.
    try expectNoUser(&r, "Passw0rd!");
    try expectNoUser(&r, "svc-scan:Passw0rd!");
    // No banner/header/status token leaks in as a username.
    try expectNoUser(&r, "-Username-");
    try expectNoUser(&r, "Windows");
    try testing.expectEqual(@as(usize, 2), r.users.len);
}

test "tee'd ldap --active-users console" {
    const in =
        "LDAP                     10.0.0.10      389    DC01             [*] Total records returned: 12, total 3 user(s) disabled\n" ++
        "LDAP                     10.0.0.10      389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-\n" ++
        "LDAP                     10.0.0.10      389    DC01             svc-scan                      2024-01-15 09:05:10 0\n" ++
        "LDAP                     10.0.0.10      389    DC01             alice.admin                   2024-01-15 09:05:10 0\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expect(r.console_format);
    try testing.expectEqual(@as(usize, 2), r.users.len);
    try expectHasUser(&r, "svc-scan");
    try expectHasUser(&r, "alice.admin");
}

test "full tee'd capture: chrome counts as banners, not dropped (no false alarm)" {
    // Every nxc chrome line (banner, [+] cred, [*] info, -Username- header) must
    // be counted as a banner, never as a 'dropped' line — a false "dropped N,
    // a real account may be missing" alarm would scare the operator for nothing.
    const in =
        "LDAP  10.0.0.10  389  DC01  [*] Windows Server 2022 Build 20348 (name:DC01) (domain:corp.local)\n" ++
        "LDAP  10.0.0.10  389  DC01  [+] corp.local\\svc-scan:Passw0rd!\n" ++
        "LDAP  10.0.0.10  389  DC01  [*] Total records returned: 12, total 3 user(s) disabled\n" ++
        "LDAP  10.0.0.10  389  DC01  -Username-                    -Last PW Set-       -BadPW-  -Description-\n" ++
        "LDAP  10.0.0.10  389  DC01  alice.admin                   2024-01-15 09:05:10 0\n" ++
        "LDAP  10.0.0.10  389  DC01  bob.jones                     2024-01-15 09:05:11 0\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expect(r.console_format);
    try testing.expectEqual(@as(usize, 2), r.users.len);
    try testing.expectEqual(@as(usize, 4), r.banners); // Windows/[+]/Total/header
    try testing.expectEqual(@as(usize, 0), r.dropped); // nothing looked like bad content
}

test "case-insensitive dedup collapses one account to one entry" {
    const in = "Administrator\nadministrator\nADMINISTRATOR\nalice\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 2), r.users.len);
    try testing.expectEqual(@as(usize, 2), r.duplicates);
}

test "UPN and DOWN-LEVEL forms reduce to the bare name and dedup with it" {
    const in = "alice.admin\nLAB\\alice.admin\nalice.admin@corp.local\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.users.len);
    try expectHasUser(&r, "alice.admin");
}

test "garbage / injected lines are dropped, not sprayed" {
    const in =
        "alice.admin\n" ++
        "not a username with spaces\n" ++ // embedded whitespace -> dropped
        "corp.local\\svc:Passw0rd!\n" ++ // ':' reserved -> dropped (would be a pw leak)
        "10.0.0.10:445\n" ++ // ip:port -> dropped
        "   \n" ++ // blank
        "bob.jones\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 2), r.users.len);
    try expectHasUser(&r, "alice.admin");
    try expectHasUser(&r, "bob.jones");
    try testing.expect(r.dropped >= 3);
}

test "well-known non-targets are counted" {
    const in = "krbtgt\nGuest\nalice\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 3), r.users.len);
    try testing.expectEqual(@as(usize, 2), r.well_known);
}

test "bare pasted banner/header lines (no proto prefix) are dropped" {
    const in =
        "[+] corp.local\\svc-scan:Passw0rd!\n" ++
        "-Username-                    -Last PW Set-\n" ++
        "[*] Enumerated 12 local users: CORP\n" ++
        "alice.admin\n";
    var r = try parse(testing.allocator, in);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.users.len);
    try expectHasUser(&r, "alice.admin");
    try expectNoUser(&r, "svc-scan:Passw0rd!");
    try expectNoUser(&r, "svc-scan");
}

test "parse handles allocation failure at every point without leak or double-free" {
    // Exhaustively fails allocation 0,1,2,... and checks each path frees cleanly.
    // This is the regression guard for the owned_key double-free (seen-map owns
    // the key AND an errdefer freed it) and the owned_user leak on the OOM path.
    const in = "alice.admin\nBOB.JONES\nalice.admin\nsvc-scan\n[+] dom\\u:p\nSMB 10.0.0.10 445 DC01 carol\n";
    try std.testing.checkAllAllocationFailures(testing.allocator, struct {
        fn run(alloc: std.mem.Allocator, input: []const u8) !void {
            var r = try parse(alloc, input);
            r.deinit();
        }
    }.run, .{in});
}

test "empty input yields an empty roster, no crash" {
    var r = try parse(testing.allocator, "");
    defer r.deinit();
    try testing.expectEqual(@as(usize, 0), r.users.len);
}

test "isIngestArtifact rejects console/banner lines but passes clean names" {
    // Real spray targets pass through.
    try testing.expect(!isIngestArtifact("alice.admin"));
    try testing.expect(!isIngestArtifact("LAB\\alice.admin"));
    try testing.expect(!isIngestArtifact("alice.admin@corp.local"));
    // nxc console lines (any content, incl. the [+] cred line and data rows).
    try testing.expect(isIngestArtifact("SMB   10.0.0.10   445   DC01   [+] corp.local\\svc-scan:Passw0rd!"));
    try testing.expect(isIngestArtifact("SMB   10.0.0.10   445   DC01   alice.admin   2024-01-15 0 desc"));
    try testing.expect(isIngestArtifact("LDAP  10.0.0.10  389  DC01  -Username-  -Last PW Set-"));
    // Bare-pasted banners.
    try testing.expect(isIngestArtifact("[+] corp.local\\svc-scan:Passw0rd!"));
    try testing.expect(isIngestArtifact("-Username-   -Last PW Set-"));
}

test "plausibleSam rejects reserved chars and requires an alphanumeric" {
    try testing.expect(plausibleSam("alice.admin"));
    try testing.expect(plausibleSam("svc-sql"));
    try testing.expect(plausibleSam("DC01$"));
    // '-Username-' is charset-valid (dashes are legal in a name); the nxc table
    // header is rejected by candidateFromLine's explicit guard, not here.
    try testing.expect(!plausibleSam("a:b"));
    try testing.expect(!plausibleSam("a b"));
    try testing.expect(!plausibleSam(""));
    try testing.expect(!plausibleSam("......"));
}
