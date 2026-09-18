//! NDJSON attempt store — the single source of truth for campaign progress.
//! One JSON object per attempt, appended to a file. Replaying the file (see
//! dedup.zig and, later, the windowed budget) reconstructs state across runs.
//!
//! Schema (one line each):
//!   {"realm","dc","user","password","timestamp"(ISO-8601 UTC),"result",
//!    "kdc_error":{"name","code"}}

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const secret_file = @import("../util/secret_file.zig");
const SpinLock = @import("../util/spinlock.zig").SpinLock;
const budget_mod = @import("../engine/budget.zig");

/// Classification of an attempt's outcome (the `result` field).
pub const Result = enum {
    valid,
    invalid,
    user_unknown,
    locked,
    /// Account exists but is unusable for reasons OTHER than a lockout we
    /// caused: disabled, expired, logon-hours/workstation restricted. AD reports
    /// all of these as KDC_ERR_CLIENT_REVOKED, same as a lockout — only the
    /// e-data NTSTATUS tells them apart. Kept distinct from `locked` so these
    /// never consume the --panic-after lockout budget.
    revoked,
    expired, // valid credential, password expired — a win
    skew, // clock skew, but pre-auth succeeded — valid
    network_error,
    decrypt_error,
};

/// One attempt to record. `realm`/`dc`/`timestamp` are filled in by the store.
pub const Attempt = struct {
    user: []const u8,
    /// Empty for username enumeration (no password tried).
    password: []const u8 = "",
    result: Result,
    kdc_error_name: []const u8 = "",
    kdc_error_code: i32 = 0,
};

const KdcErrorJson = struct { name: []const u8, code: i32 };
const RecordJson = struct {
    realm: []const u8,
    dc: []const u8,
    user: []const u8,
    password: []const u8,
    timestamp: []const u8,
    result: []const u8,
    kdc_error: KdcErrorJson,
    /// Which half of an attempt this record is.
    ///
    /// "attempt" is the RESERVATION, published before the KDC is contacted and
    /// while the cross-process lock is held; it is what the lockout budget
    /// counts, exactly one per attempt. "result" is the outcome written
    /// afterwards, which the budget ignores (counting both would halve every
    /// account's budget). Records from older versions carry no phase and are
    /// counted, which is correct — they were written one per attempt.
    phase: []const u8,
    /// Identifies the PROCESS that wrote this record. The lockout budget tails
    /// this log to pick up attempts made by OTHER concurrent kerbrutez runs
    /// (see Budget.refreshFromLog); without a way to recognise its own lines it
    /// would count every attempt twice. Readers that predate this field ignore
    /// it (all parsing uses ignore_unknown_fields).
    run: []const u8,
};

pub const Store = struct {
    allocator: Allocator,
    io: Io,
    /// BORROW: realm/dc must outlive the store (they come from the config).
    realm: []const u8,
    dc: []const u8,
    file: Io.File,
    /// Path this store appends to; used to derive the sidecar lock file.
    /// BORROW: must outlive the store.
    path: []const u8 = "",
    pos: u64,
    lock: SpinLock = .{},
    /// This process's identity in the shared log. BORROW: set by the caller.
    run_id: []const u8 = "",

    /// Open (creating if needed) the NDJSON log for appending. Existing content
    /// is preserved so a campaign resumes. OWNERSHIP: call `deinit`.
    pub fn open(allocator: Allocator, io: Io, path: []const u8, realm: []const u8, dc: []const u8) !Store {
        // Holds EVERY password this campaign has tried, in cleartext.
        const file = try secret_file.create(io, path, .{ .truncate = false });
        // The state log persists across runs, so one created by an older build
        // keeps its old (world-readable) mode — creation flags don't apply to an
        // existing file. Fix it in place.
        secret_file.tighten(io, file);
        const pos: u64 = if (file.stat(io)) |st| st.size else |_| 0;
        return .{ .allocator = allocator, .io = io, .realm = realm, .dc = dc, .file = file, .path = path, .pos = pos };
    }

    pub fn deinit(self: *Store) void {
        self.file.close(self.io);
    }

    /// Append the OUTCOME of an attempt (phase "result"). Not counted by the
    /// lockout budget — the reservation already was.
    pub fn append(self: *Store, attempt: Attempt) !void {
        return self.appendPhase(attempt, "result");
    }

    /// Publish a RESERVATION (phase "attempt") for a slot we are about to spend.
    ///
    /// This is what makes the per-user budget a cross-process guarantee: it is
    /// written while the exclusive lock is held and BEFORE the KDC is contacted,
    /// so any other process that takes the lock next already sees this attempt.
    pub fn appendReservation(self: *Store, user: []const u8, password: []const u8) !void {
        return self.appendPhase(.{ .user = user, .password = password, .result = .invalid }, "attempt");
    }

    /// Open the sidecar lock file with an EXCLUSIVE advisory lock, blocking
    /// until it is ours. Closing the returned handle releases it — and the OS
    /// releases it if the process dies, so a crash cannot wedge other runs.
    /// Returns null if the lock cannot be taken at all; callers then fall back
    /// to the in-process budget rather than refusing to work.
    pub fn lockExclusive(self: *Store, io: Io) ?Io.File {
        var buf: [640]u8 = undefined;
        const lock_path = std.fmt.bufPrint(&buf, "{s}.lock", .{self.path}) catch return null;
        return secret_file.createLocked(io, lock_path) catch null;
    }

    /// Append one attempt as an NDJSON line. Thread-safe.
    /// BORROW: nothing in `attempt` is retained after this returns.
    fn appendPhase(self: *Store, attempt: Attempt, phase: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        var ts_buf: [24]u8 = undefined;
        const ts = isoTimestamp(self.io, &ts_buf);

        const record = RecordJson{
            .realm = self.realm,
            .dc = self.dc,
            .user = attempt.user,
            .password = attempt.password,
            .timestamp = ts,
            .result = @tagName(attempt.result),
            .kdc_error = .{ .name = attempt.kdc_error_name, .code = attempt.kdc_error_code },
            .run = self.run_id,
            .phase = phase,
        };

        const json = try std.json.Stringify.valueAlloc(self.allocator, record, .{});
        defer self.allocator.free(json);

        // Write at the file's CURRENT end, not at an offset cached when we
        // opened it. The state file is shared: another kerbrutez process (a
        // second operator, or a parallel run against the same realm) may have
        // appended since. Trusting our own stale offset overwrites everything
        // they wrote — and lost attempt records make the replayed budget
        // undercount, which is precisely how accounts end up locked.
        // Re-stat is cheap next to the KDC round-trip this record describes.
        const end: u64 = if (self.file.stat(self.io)) |st| @max(st.size, self.pos) else |_| self.pos;

        var buf: [512]u8 = undefined;
        var w = self.file.writer(self.io, &buf);
        w.pos = end;
        try w.interface.writeAll(json);
        try w.interface.writeAll("\n");
        try w.interface.flush();
        self.pos = end + json.len + 1;
    }
};

/// Sentinel for "seen locked, but we could not read WHEN".
///
/// The obvious `orelse 0` is a fail-OPEN: `isBlocked` computes `now - ts`, and
/// with ts=0 that is ~1.8 billion seconds, past any lockout duration — so an
/// unreadable timestamp silently put a locked account back into the spray. The
/// state file persists across runs and is shared between concurrent processes,
/// so a truncated or hand-edited line is not hypothetical. Unknown time means
/// stay blocked; `--retry-locked` is the escape hatch.
pub const unknown_lock_time: i64 = std.math.maxInt(i64);

/// Accounts seen locked/revoked, each with WHEN it was last seen that way.
/// Owns its keys. Free with `deinit`.
pub const LockedSet = struct {
    allocator: Allocator,
    /// canonical (lower-cased) username -> epoch seconds of the last
    /// locked/revoked observation.
    map: std.StringHashMapUnmanaged(i64) = .empty,

    pub fn deinit(self: *LockedSet) void {
        var it = self.map.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.map.deinit(self.allocator);
    }

    pub fn count(self: *const LockedSet) usize {
        return self.map.count();
    }

    /// Should `user` still be skipped at `now`?
    ///
    /// EXPIRY IS NOT OPTIONAL. A lockout is temporary — AD releases it after the
    /// lockout duration — but we only ever learn an account recovered by trying
    /// it. Skipping locked accounts unconditionally is therefore self-sealing:
    /// the account is skipped, so no new record is written, so it stays skipped
    /// FOREVER. On a multi-day engagement that silently erodes coverage until
    /// the spray is testing almost nobody, with no error to notice. Ageing the
    /// skip out puts recovered accounts back in play automatically.
    pub fn isBlocked(self: *const LockedSet, user: []const u8, now: i64, expire_after_secs: i64) bool {
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const ts = self.map.get(budget_mod.accountKey(&kbuf, user)) orelse return false;
        if (ts == unknown_lock_time) return true; // fail closed: see the constant
        if (expire_after_secs <= 0) return true; // expiry disabled
        return (now - ts) < expire_after_secs;
    }
};

/// Replay the NDJSON store and collect every account seen LOCKED or REVOKED
/// (disabled/expired/restricted) in `realm` during an earlier run.
///
/// This is what makes lockouts survive a restart. Without it the locked set is
/// per-process, so a resumed campaign happily sprays accounts it locked five
/// minutes ago — re-confirming the lockout, spending the panic-stop budget on
/// accounts it locked earlier, and reporting them as freshly locked.
///
/// A later successful/invalid attempt for the same user clears them again: that
/// means the account was unlocked (lockout durations expire), so it's back in
/// play. OWNERSHIP: caller calls `deinit`.
pub fn loadLockedFromLog(allocator: Allocator, io: Io, path: []const u8, realm: []const u8) LockedSet {
    var set = LockedSet{ .allocator = allocator };
    var file = Io.Dir.cwd().openFile(io, path, .{}) catch return set; // missing => fresh
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    const content = reader.interface.allocRemaining(allocator, .unlimited) catch return set;
    defer allocator.free(content);

    const Rec = struct { realm: []const u8, user: []const u8, result: []const u8, timestamp: []const u8, phase: []const u8 = "" };
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const parsed = std.json.parseFromSlice(Rec, allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.realm, realm)) continue;
        // A RESERVATION carries no outcome yet, so it must not be read as
        // evidence the account is usable again — otherwise publishing the
        // reservation would clear the very lockout we are trying to respect.
        if (std.mem.eql(u8, parsed.value.phase, "attempt")) continue;
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const user = budget_mod.accountKey(&kbuf, parsed.value.user);
        const blocked = std.mem.eql(u8, parsed.value.result, "locked") or
            std.mem.eql(u8, parsed.value.result, "revoked");
        if (blocked) {
            const ts = budget_mod.parseIso8601(parsed.value.timestamp) orelse unknown_lock_time;
            const gop = set.map.getOrPut(allocator, user) catch continue;
            if (!gop.found_existing) {
                gop.key_ptr.* = allocator.dupe(u8, user) catch {
                    _ = set.map.remove(user);
                    continue;
                };
                gop.value_ptr.* = ts;
            } else if (ts > gop.value_ptr.*) {
                gop.value_ptr.* = ts; // keep the most recent observation
            }
        } else if (set.map.fetchRemove(user)) |kv| {
            // Answered normally since the lockout — it is back in play.
            allocator.free(kv.key);
        }
    }
    return set;
}

/// Format the current UTC time as ISO-8601 "YYYY-MM-DDTHH:MM:SSZ".
fn isoTimestamp(io: Io, out: *[24]u8) []const u8 {
    const now = Io.Timestamp.now(io, .real).toSeconds();
    const days = @divFloor(now, 86400);
    var rem = @mod(now, 86400);
    const hour: u32 = @intCast(@divFloor(rem, 3600));
    rem -= @as(i64, hour) * 3600;
    const minute: u32 = @intCast(@divFloor(rem, 60));
    const second: u32 = @intCast(rem - @as(i64, minute) * 60);
    const ymd = civilFromDays(days);
    return std.fmt.bufPrint(out, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u32, @intCast(ymd.year)), ymd.month, ymd.day, hour, minute, second,
    }) catch out[0..0];
}

const YMD = struct { year: i64, month: u32, day: u32 };

fn civilFromDays(days: i64) YMD {
    const z = days + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    return .{ .year = if (m <= 2) y + 1 else y, .month = @intCast(m), .day = @intCast(d) };
}

const testing = std.testing;

test "store append writes parseable NDJSON and round-trips" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_store.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    {
        var store = try Store.open(a, io, path, "EXAMPLE.COM", "dc01:88");
        defer store.deinit();
        try store.append(.{ .user = "alice", .password = "p\"w\\1", .result = .invalid, .kdc_error_name = "KDC_ERR_PREAUTH_FAILED", .kdc_error_code = 24 });
        try store.append(.{ .user = "bob", .password = "secret", .result = .valid });
    }

    // Read back and verify both lines parse.
    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [256]u8 = undefined;
    var r = f.reader(io, &rbuf);
    const content = try r.interface.allocRemaining(a, .unlimited);
    defer a.free(content);

    var it = std.mem.tokenizeScalar(u8, content, '\n');
    const DedupRec = struct { realm: []const u8, user: []const u8, password: []const u8 };
    const l1 = it.next().?;
    const p1 = try std.json.parseFromSlice(DedupRec, a, l1, .{ .ignore_unknown_fields = true });
    defer p1.deinit();
    try testing.expectEqualStrings("EXAMPLE.COM", p1.value.realm);
    try testing.expectEqualStrings("alice", p1.value.user);
    try testing.expectEqualStrings("p\"w\\1", p1.value.password); // escaping survived
    const l2 = it.next().?;
    const p2 = try std.json.parseFromSlice(DedupRec, a, l2, .{ .ignore_unknown_fields = true });
    defer p2.deinit();
    try testing.expectEqualStrings("bob", p2.value.user);
}

test "loadLockedFromLog remembers locked accounts across runs, and forgets expired ones" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_locked.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "alice", .password = "p1", .result = .invalid });
        try s.append(.{ .user = "alice", .password = "p2", .result = .locked }); // we locked alice
        try s.append(.{ .user = "guest", .password = "p1", .result = .revoked }); // disabled, not ours
        try s.append(.{ .user = "bob", .password = "p1", .result = .locked });
        try s.append(.{ .user = "bob", .password = "p2", .result = .invalid }); // bob's lockout expired
        try s.append(.{ .user = "carol", .password = "p1", .result = .invalid });
    }
    // A different realm's records must not leak in.
    {
        var s2 = try Store.open(a, io, path, "OTHER.COM", "dc:88");
        defer s2.deinit();
        try s2.append(.{ .user = "mallory", .password = "p1", .result = .locked });
    }

    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expect(set.map.contains("alice")); // still locked
    try testing.expect(set.map.contains("guest")); // disabled: don't bother
    try testing.expect(!set.map.contains("bob")); // answered again => unlocked
    try testing.expect(!set.map.contains("carol")); // never locked
    try testing.expect(!set.map.contains("mallory")); // other realm
    try testing.expectEqual(@as(usize, 2), set.count());
}

// REGRESSION TEST for a self-sealing skip list. Skipping locked accounts is
// correct, but we only ever learn an account recovered by TRYING it — so an
// unconditional skip means no new record is ever written for that account and
// it stays skipped forever. Over a multi-day engagement that silently erodes
// coverage to nothing. The skip must age out.
test "locked accounts return to rotation once the lockout duration passes" {
    const a = testing.allocator;
    var set = LockedSet{ .allocator = a };
    defer set.deinit();
    const locked_at: i64 = 1_000_000;
    try set.map.put(a, try a.dupe(u8, "alice"), locked_at);

    const ttl: i64 = 30 * 60;
    try testing.expect(set.isBlocked("alice", locked_at + 60, ttl)); // 1 min later: still out
    try testing.expect(set.isBlocked("alice", locked_at + ttl - 1, ttl)); // just before
    try testing.expect(!set.isBlocked("alice", locked_at + ttl, ttl)); // duration passed: back in play
    try testing.expect(!set.isBlocked("bob", locked_at, ttl)); // never locked

    // Case-insensitive: AD would treat these as the same account.
    try testing.expect(set.isBlocked("Alice", locked_at + 60, ttl));
    try testing.expect(set.isBlocked("ALICE", locked_at + 60, ttl));

    // ttl <= 0 means AD's lockoutDuration is "until an admin unlocks" — the
    // skip must then be permanent, never silently expiring.
    try testing.expect(set.isBlocked("alice", locked_at + 999_999, 0));
}

// REGRESSION TEST for concurrent operators sharing one state file. The store is
// explicitly designed so independent runs see each other's attempts, but each
// process captured the file size ONCE at open and then wrote at its own running
// offset — so a second process's writes land on top of everything the first
// wrote after that moment. Lost attempt records make the replayed budget
// undercount, which is exactly how accounts get locked.
test "a second writer does not clobber records appended since it opened" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_store_concurrent.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Two "processes" hold the same state file at the same time.
    var s1 = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
    defer s1.deinit();
    var s2 = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
    defer s2.deinit();

    try s1.append(.{ .user = "alice", .password = "p1", .result = .invalid });
    try s1.append(.{ .user = "alice", .password = "p2", .result = .invalid });
    // s2 opened when the file was empty; its write must go AFTER s1's records.
    try s2.append(.{ .user = "bob", .password = "p1", .result = .invalid });

    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [512]u8 = undefined;
    var r = f.reader(io, &rbuf);
    const content = try r.interface.allocRemaining(a, .unlimited);
    defer a.free(content);

    var lines: usize = 0;
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |_| lines += 1;
    try testing.expectEqual(@as(usize, 3), lines); // nothing overwritten
    try testing.expect(std.mem.indexOf(u8, content, "\"user\":\"alice\",\"password\":\"p1\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"user\":\"alice\",\"password\":\"p2\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"user\":\"bob\"") != null);
}

// REGRESSION TEST for the "permissive sentinel" class landing on the locked-skip
// list. An unreadable timestamp became 0, and `isBlocked` computes `now - ts` —
// so 0 read as "locked ~1.8 billion seconds ago", i.e. long expired, and the
// account went straight back into the spray.
test "a locked record with an unreadable timestamp stays blocked" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_locked_badts.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        const f = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer f.close(io);
        var buf: [512]u8 = undefined;
        var w = f.writerStreaming(io, &buf);
        // Valid JSON, valid realm/result — only the timestamp is unreadable.
        try w.interface.writeAll(
            \\{"realm":"EXAMPLE.COM","dc":"dc:88","user":"alice","password":"p","timestamp":"not-a-time","result":"locked","kdc_error":{"name":"","code":0}}
            \\
        );
        try w.interface.flush();
    }

    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expectEqual(@as(usize, 1), set.count());
    // Blocked regardless of how much later "now" is, and regardless of the TTL.
    try testing.expect(set.isBlocked("alice", 2_000_000_000, 30 * 60));
    try testing.expect(set.isBlocked("alice", 9_000_000_000, 60));
    try testing.expect(!set.isBlocked("bob", 2_000_000_000, 30 * 60));
}

// A RESERVATION is published before the KDC is contacted, so it carries no
// outcome yet. If the locked-set replay treated it as a normal record, that
// record's non-"locked" result would CLEAR a genuine lockout — publishing the
// reservation would erase the very protection it exists to coordinate.
test "a reservation does not clear a locked account" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_reservation_locked.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer {
        Io.Dir.cwd().deleteFile(io, path) catch {};
        Io.Dir.cwd().deleteFile(io, path ++ ".lock") catch {};
    }
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.appendReservation("alice", "p1");
        try s.append(.{ .user = "alice", .password = "p1", .result = .locked }); // we locked her
        // A later run reserves another slot against the same account.
        try s.appendReservation("alice", "p2");
    }

    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expect(set.isBlocked("alice", 1_000, 30 * 60));

    // A real outcome record showing she answered normally DOES clear her.
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "alice", .password = "p3", .result = .invalid });
    }
    var set2 = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set2.deinit();
    try testing.expect(!set2.isBlocked("alice", 1_000, 30 * 60));
}
