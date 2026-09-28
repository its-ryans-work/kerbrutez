//! Dedup index over `REALM:USER:PASSWORD` — "have I ever tried this exact combo?"
//! Keyed on realm (not DC) so the same combo isn't retried against a second DC
//! of the same domain (one shared lockout counter), while the same combo
//! against a different realm is still allowed. Rebuilt by replaying the NDJSON
//! attempt store on startup.

const std = @import("std");
const budget_mod = @import("../engine/budget.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Scope = enum { realm, none };

const sep = "\x1f"; // ASCII unit separator — not expected in realm/user/password

pub const Dedup = struct {
    allocator: Allocator,
    scope: Scope,
    /// Owns its keys.
    seen: std.StringHashMapUnmanaged(void) = .{},

    pub fn init(allocator: Allocator, scope: Scope) Dedup {
        return .{ .allocator = allocator, .scope = scope };
    }

    pub fn deinit(self: *Dedup) void {
        var it = self.seen.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.seen.deinit(self.allocator);
    }

    pub fn count(self: *const Dedup) usize {
        return self.seen.count();
    }

    /// OWNERSHIP: caller frees the returned key.
    ///
    /// The USERNAME is lower-cased (AD is case-insensitive) so `Administrator`
    /// and `administrator` dedup as the one account they actually are. The
    /// PASSWORD is not — passwords are case-sensitive, and treating `Summer2026!`
    /// as already-tried because we tried `summer2026!` would silently skip a
    /// distinct, possibly valid guess.
    fn makeKey(self: *Dedup, realm: []const u8, user: []const u8, password: []const u8) ![]u8 {
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const u = budget_mod.accountKey(&kbuf, user);
        return std.fmt.allocPrint(self.allocator, "{s}" ++ sep ++ "{s}" ++ sep ++ "{s}", .{ realm, u, password });
    }

    /// True if this exact combo has already been attempted. Always false when
    /// scope is `none` (dedup disabled — e.g. re-testing after a reset).
    pub fn contains(self: *Dedup, realm: []const u8, user: []const u8, password: []const u8) bool {
        if (self.scope == .none) return false;
        const k = self.makeKey(realm, user, password) catch return false;
        defer self.allocator.free(k);
        return self.seen.contains(k);
    }

    /// Record a combo as attempted. No-op when scope is `none`.
    pub fn add(self: *Dedup, realm: []const u8, user: []const u8, password: []const u8) !void {
        if (self.scope == .none) return;
        const k = try self.makeKey(realm, user, password);
        errdefer self.allocator.free(k);
        const gop = try self.seen.getOrPut(self.allocator, k);
        if (gop.found_existing) {
            self.allocator.free(k); // key already present; drop the duplicate
        }
    }
};

/// Build a dedup index by replaying the NDJSON attempt store. Missing file =>
/// empty index. Lines that fail to parse are skipped. OWNERSHIP: caller deinit.
pub fn loadFromLog(allocator: Allocator, io: Io, path: []const u8, scope: Scope) !Dedup {
    var dedup = Dedup.init(allocator, scope);
    errdefer dedup.deinit();
    if (scope == .none) return dedup; // nothing to track

    var file = Io.Dir.cwd().openFile(io, path, .{}) catch |e| switch (e) {
        error.FileNotFound => return dedup,
        else => return dedup, // unreadable log => start fresh rather than abort
    };
    defer file.close(io);

    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    // Bounded to avoid OOM on a large state log (see store.max_state_bytes).
    const content = reader.interface.allocRemaining(allocator, .limited(@import("store.zig").max_state_bytes)) catch return dedup;
    defer allocator.free(content);

    // `kind` defaults to "attempt" so legacy records (no kind field) still count.
    // A roster record ("user") has an empty password and must not seed a dedup
    // key, or `spray @state` would treat every ingested user as already tried.
    const Rec = struct { realm: []const u8, user: []const u8, password: []const u8, kind: []const u8 = "attempt", phase: []const u8 = "" };
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const parsed = std.json.parseFromSlice(Rec, allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.kind, "attempt")) continue;
        // Skip RESERVATION records (phase "attempt", empty password): they are the
        // pre-attempt budget marker, not a tried combo. Counting them seeds a
        // spurious empty-password dedup key and inflates the "prior attempts" total.
        // Legacy records (no phase) and outcome records (phase "result") count.
        if (std.mem.eql(u8, parsed.value.phase, "attempt")) continue;
        dedup.add(parsed.value.realm, parsed.value.user, parsed.value.password) catch {};
    }
    return dedup;
}

const testing = std.testing;

test "dedup add/contains and realm scoping" {
    const a = testing.allocator;
    var d = Dedup.init(a, .realm);
    defer d.deinit();

    try testing.expect(!d.contains("R1", "u", "p"));
    try d.add("R1", "u", "p");
    try testing.expect(d.contains("R1", "u", "p"));
    // Same combo, different realm => not deduped.
    try testing.expect(!d.contains("R2", "u", "p"));
    // Adding the same combo twice doesn't leak / double-count.
    try d.add("R1", "u", "p");
    try testing.expectEqual(@as(usize, 1), d.count());
}

test "dedup scope none disables tracking" {
    const a = testing.allocator;
    var d = Dedup.init(a, .none);
    defer d.deinit();
    try d.add("R1", "u", "p");
    try testing.expect(!d.contains("R1", "u", "p"));
    try testing.expectEqual(@as(usize, 0), d.count());
}

test "loadFromLog rebuilds index from NDJSON" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const store = @import("store.zig");

    const path = "test_dedup.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try store.Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "alice", .password = "pw1", .result = .invalid, .kdc_error_code = 24 });
        try s.append(.{ .user = "bob", .password = "pw2", .result = .valid });
    }
    var d = try loadFromLog(a, io, path, .realm);
    defer d.deinit();
    try testing.expect(d.contains("EXAMPLE.COM", "alice", "pw1"));
    try testing.expect(d.contains("EXAMPLE.COM", "bob", "pw2"));
    try testing.expect(!d.contains("EXAMPLE.COM", "alice", "wrong"));
    try testing.expectEqual(@as(usize, 2), d.count());
}
