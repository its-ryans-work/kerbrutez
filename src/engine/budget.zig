//! Log-based per-user windowed lockout budget + cadence.
//!
//! The operator usually has NO credentials, so the budget is computed entirely
//! from the tool's own attempts in the NDJSON store — counted PER USER within
//! the realm over the trailing observation window. We never read AD's
//! badPwdCount. To guarantee we never trip the lockout threshold, we cap
//! ATTEMPTS (not just failures) per user per window: `tryReserve` grants at most
//! `attempts_per_window` slots in any trailing window, and otherwise returns how
//! long to wait. Replaying the log re-seeds the per-user windows so a resumed
//! campaign honours the same cadence.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const SpinLock = @import("../util/spinlock.zig").SpinLock;

pub const Policy = struct {
    /// AD lockout threshold (bad attempts before lock). Default assumption: 5.
    threshold: u32 = 5,
    /// Observation window in minutes. Default assumption: 30.
    window_min: u32 = 30,
    /// Attempts we allow per user per window (default threshold - 1 headroom).
    attempts_per_window: u32 = 4,
    /// Extra minutes to wait past the window before the next batch.
    margin_min: u32 = 1,
    /// What the operator actually asked for, before the safety clamp (see
    /// `fromKnobs`). Equal to `attempts_per_window` when nothing was clamped.
    requested_attempts_per_window: u32 = 0,

    pub fn windowSecs(self: Policy) i64 {
        return @as(i64, self.window_min) * 60;
    }
    pub fn marginSecs(self: Policy) i64 {
        return @as(i64, self.margin_min) * 60;
    }

    /// Build a policy from the threshold/window, defaulting attempts-per-window
    /// to threshold-1 unless explicitly overridden.
    ///
    /// SAFETY CLAMP: an explicit `--attempts-per-window` at or above the lockout
    /// threshold is not a preference, it is an instruction to lock every account
    /// in the list — the budget would hand out exactly enough bad passwords to
    /// trip the threshold inside a single window. We clamp to threshold-1 and
    /// let the caller warn. `clamped()` reports whether that happened.
    pub fn fromKnobs(threshold: u32, window_min: u32, attempts_per_window: ?u32, margin_min: u32) Policy {
        const safe_max: u32 = if (threshold > 1) threshold - 1 else 1;
        const requested = attempts_per_window orelse safe_max;
        return .{
            .threshold = threshold,
            .window_min = window_min,
            .attempts_per_window = if (threshold > 0) @min(requested, safe_max) else requested,
            .requested_attempts_per_window = requested,
            .margin_min = margin_min,
        };
    }

    /// True if `fromKnobs` had to reduce an explicitly requested
    /// attempts-per-window to keep it below the lockout threshold.
    pub fn clamped(self: Policy) bool {
        return self.requested_attempts_per_window > self.attempts_per_window;
    }
};

/// Longest username we canonicalise in a stack buffer. AD's sAMAccountName caps
/// at 20 and userPrincipalName well under this; anything longer is used as-is
/// (it cannot be a real account, so exact-matching it is harmless).
pub const account_key_max = 256;

/// Canonical key for an account. ACTIVE DIRECTORY IS CASE-INSENSITIVE, so
/// `Administrator` and `administrator` are ONE account and must share ONE
/// lockout budget. Keying them separately hands each spelling a full budget and
/// spends double the bad passwords against a single AD account — which locks
/// out exactly the accounts the budget exists to protect. Mixed-case user lists
/// are the norm (BloodHound/LDAP exports, hand-merged lists), so this is not a
/// hypothetical. `opsec.CanarySet` already normalises this way.
pub fn accountKey(buf: *[account_key_max]u8, user: []const u8) []const u8 {
    if (user.len > buf.len) return user;
    for (user, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..user.len];
}

/// Minimum gap between filesystem checks in `refreshFromLog`.
const min_refresh_ms: i64 = 1000;
/// Cap on how much new log is folded in per refresh.
const max_refresh_bytes: usize = 8 * 1024 * 1024;

pub const Budget = struct {
    allocator: Allocator,
    policy: Policy,
    /// user -> ascending list of attempt timestamps (epoch seconds). Keys owned.
    attempts: std.StringHashMapUnmanaged(std.ArrayListUnmanaged(i64)) = .{},
    lock: SpinLock = .{},
    /// Shared state log to tail for other processes' attempts (see
    /// `refreshFromLog`). BORROW: owned by the caller.
    log_path: ?[]const u8 = null,
    log_realm: []const u8 = "",
    /// This process's id in that log, so its own records are not double-counted.
    run_id: []const u8 = "",
    /// Bytes of the log already folded into this budget.
    log_offset: u64 = 0,
    last_refresh_ms: i64 = 0,

    pub fn init(allocator: Allocator, policy: Policy) Budget {
        return .{ .allocator = allocator, .policy = policy };
    }

    pub fn deinit(self: *Budget) void {
        var it = self.attempts.iterator();
        while (it.next()) |e| {
            self.allocator.free(e.key_ptr.*);
            e.value_ptr.deinit(self.allocator);
        }
        self.attempts.deinit(self.allocator);
    }

    fn listFor(self: *Budget, user: []const u8) !*std.ArrayListUnmanaged(i64) {
        var kbuf: [account_key_max]u8 = undefined;
        const key = accountKey(&kbuf, user);
        const gop = try self.attempts.getOrPut(self.allocator, key);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = .empty;
        }
        return gop.value_ptr;
    }

    /// The most recent (largest) timestamp in `list`, or `minInt` if empty. The
    /// list is NOT guaranteed ascending — `refreshFromLog` interleaves other
    /// processes' timestamps and NTP can step the clock — so scan for the max
    /// rather than trusting the last element.
    fn maxTs(list: *const std.ArrayListUnmanaged(i64)) i64 {
        var m: i64 = std.math.minInt(i64);
        for (list.items) |t| {
            if (t > m) m = t;
        }
        return m;
    }

    /// Reset the per-user attempt ledger iff AD would have reset badPwdCount.
    ///
    /// THIS IS THE CORE OF THE LOCKOUT MODEL, and it is NOT a sliding window.
    /// AD's badPwdCount is a STREAK counter: it resets to 0 only after a quiet
    /// gap of at least lockoutObservationWindow measured from the MOST RECENT bad
    /// password (badPasswordTime). So bad passwords that keep arriving less than
    /// a window apart accumulate WITHOUT BOUND — a spray spread across hours
    /// (spraycampaign's password-major passes over a large user list, or
    /// --rpm/--delay/jitter) climbs 1,2,3,4,5 and LOCKS even though no trailing
    /// 30-min window ever held more than a couple. The previous trailing-window
    /// COUNT (a classic rate-limiter) modelled the wrong thing and silently
    /// locked accounts. We keep the current STREAK and clear it only once a full
    /// window of silence has elapsed since the most recent attempt — AD's rule.
    ///
    /// A clock stepped backwards makes the gap look smaller (never larger), so it
    /// errs toward keeping the streak: MORE pacing, never less. Safe.
    fn resetIfQuiet(self: *Budget, list: *std.ArrayListUnmanaged(i64), now: i64) void {
        if (list.items.len == 0) return;
        if (now - maxTs(list) >= self.policy.windowSecs()) list.clearRetainingCapacity();
    }

    /// Try to reserve an attempt slot for `user` at time `now` (epoch seconds).
    /// Returns 0 if granted (the slot is recorded), otherwise the number of
    /// seconds to wait before the user's next attempt is permitted.
    pub fn tryReserve(self: *Budget, user: []const u8, now: i64) !i64 {
        self.lock.lock();
        defer self.lock.unlock();
        const list = try self.listFor(user);
        self.resetIfQuiet(list, now);
        if (list.items.len < self.policy.attempts_per_window) {
            try list.append(self.allocator, now);
            return 0;
        }
        // The streak is full (apw = threshold-1) and AD has NOT reset yet. Wait
        // until a FULL window+margin of silence has passed since the MOST RECENT
        // attempt; only then does AD reset and a fresh streak begin. Keying the
        // wait off the most recent attempt (not the oldest) is what makes a
        // spread-out campaign safe — refilling as soon as the oldest aged out
        // would let attempt N+1 land while AD is still counting the streak of N.
        const wait = maxTs(list) + self.policy.windowSecs() + self.policy.marginSecs() - now;
        return if (wait > 0) wait else 1;
    }

    /// Seed `count` bad attempts already on the account's badPwdCount (read from
    /// AD) as in-window attempts at `now`, shrinking the user's first window.
    /// Capped at attempts_per_window (anything more means the user is already at
    /// or past our budget and will simply have to wait).
    pub fn seedBadPwdCount(self: *Budget, user: []const u8, count: u32, now: i64) !void {
        const n = @min(count, self.policy.attempts_per_window);
        var i: u32 = 0;
        while (i < n) : (i += 1) try self.addHistorical(user, now);
    }

    /// Seed a historical attempt (from log replay). Timestamps should arrive in
    /// chronological order (the NDJSON log is append-ordered).
    pub fn addHistorical(self: *Budget, user: []const u8, ts: i64) !void {
        self.lock.lock();
        defer self.lock.unlock();
        const list = try self.listFor(user);
        try list.append(self.allocator, ts);
    }

    /// How many attempts are in `user`'s CURRENT streak (bad passwords since the
    /// last window-length quiet gap) — i.e. what AD's badPwdCount would be. Used
    /// by the lockout predictor.
    pub fn windowCount(self: *Budget, user: []const u8, now: i64) usize {
        self.lock.lock();
        defer self.lock.unlock();
        var kbuf: [account_key_max]u8 = undefined;
        const list = self.attempts.getPtr(accountKey(&kbuf, user)) orelse return 0;
        self.resetIfQuiet(list, now);
        return list.items.len;
    }

    /// The most recent recorded attempt timestamp for `user` (epoch seconds), or
    /// null if none. Timestamps are appended in chronological order, so it's the
    /// last item. Used by the collision check for "last attempt ~N min ago".
    pub fn mostRecent(self: *Budget, user: []const u8) ?i64 {
        self.lock.lock();
        defer self.lock.unlock();
        var kbuf: [account_key_max]u8 = undefined;
        const list = self.attempts.getPtr(accountKey(&kbuf, user)) orelse return null;
        if (list.items.len == 0) return null;
        return list.items[list.items.len - 1];
    }

    /// Pick up attempts made by OTHER concurrent kerbrutez processes.
    ///
    /// THIS IS WHAT STOPS TWO RUNS FROM JOINTLY LOCKING AN ACCOUNT. The budget
    /// used to be seeded from the shared log once, at startup, and never again —
    /// so two operators on the same engagement (or one operator running a spray
    /// and a kerberoast) each believed they held the FULL per-user budget. Each
    /// stayed under the threshold alone; together they sailed past it and locked
    /// the client's accounts. The pre-flight collision check cannot catch this,
    /// because simultaneous starts both read a clean log.
    ///
    /// The log is append-only, so this reads only the bytes appended since last
    /// time. Records written by THIS process are skipped — they were already
    /// counted when the slot was reserved, and counting them twice would halve
    /// our own budget. A trailing partial line (another process mid-append) is
    /// left unconsumed for the next pass.
    ///
    /// Rate-limited: `min_refresh_ms` between filesystem hits, so a fast spray
    /// does not stat/read the log on every single attempt.
    pub fn refreshFromLog(self: *Budget, io: Io, now_ms: i64) void {
        const path = self.log_path orelse return;
        if (now_ms - self.last_refresh_ms < min_refresh_ms) return;
        self.last_refresh_ms = now_ms;

        var file = Io.Dir.cwd().openFile(io, path, .{}) catch return;
        defer file.close(io);
        const size: u64 = if (file.stat(io)) |st| st.size else |_| return;
        if (size <= self.log_offset) return; // nothing new (or truncated: leave it)

        var rbuf: [4096]u8 = undefined;
        var reader = file.reader(io, &rbuf);
        reader.seekTo(self.log_offset) catch return;
        const chunk = reader.interface.allocRemaining(self.allocator, .limited(max_refresh_bytes)) catch return;
        defer self.allocator.free(chunk);

        // Only consume up to the last complete line.
        const last_nl = std.mem.lastIndexOfScalar(u8, chunk, '\n') orelse return;
        const complete = chunk[0 .. last_nl + 1];

        const Rec = struct { realm: []const u8, user: []const u8, timestamp: []const u8, run: []const u8 = "", phase: []const u8 = "", kind: []const u8 = "attempt" };
        var it = std.mem.tokenizeScalar(u8, complete, '\n');
        while (it.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            const parsed = std.json.parseFromSlice(Rec, self.allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
            defer parsed.deinit();
            if (!std.mem.eql(u8, parsed.value.realm, self.log_realm)) continue;
            // Roster ("user") records are not attempts — never charge them to the
            // per-user budget (default "attempt" keeps counting legacy records).
            if (!std.mem.eql(u8, parsed.value.kind, "attempt")) continue;
            // Count RESERVATIONS only. Every attempt writes one reservation and
            // one outcome; counting both would halve each account's budget.
            // Older records carry no phase and are counted (one per attempt).
            if (std.mem.eql(u8, parsed.value.phase, "result")) continue;
            // Our own attempts are already in the budget.
            if (self.run_id.len > 0 and std.mem.eql(u8, parsed.value.run, self.run_id)) continue;
            const ts = parseIso8601(parsed.value.timestamp) orelse continue;
            self.addHistorical(parsed.value.user, ts) catch {};
        }
        self.log_offset += complete.len;
    }

    /// Replay the NDJSON store and seed per-user windows for `realm`.
    pub fn loadFromLog(self: *Budget, io: Io, path: []const u8, realm: []const u8) !void {
        var file = Io.Dir.cwd().openFile(io, path, .{}) catch return; // missing => fresh
        defer file.close(io);
        var rbuf: [4096]u8 = undefined;
        var reader = file.reader(io, &rbuf);
        // Bounded to avoid OOM on a large state log (see store.max_state_bytes).
        const content = reader.interface.allocRemaining(self.allocator, .limited(@import("../state/store.zig").max_state_bytes)) catch return;
        defer self.allocator.free(content);
        // Where the incremental tail should resume from.
        self.log_offset = content.len;

        const Rec = struct { realm: []const u8, user: []const u8, timestamp: []const u8, phase: []const u8 = "", kind: []const u8 = "attempt" };
        var it = std.mem.tokenizeScalar(u8, content, '\n');
        while (it.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            const parsed = std.json.parseFromSlice(Rec, self.allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
            defer parsed.deinit();
            if (!std.mem.eql(u8, parsed.value.realm, realm)) continue;
            if (!std.mem.eql(u8, parsed.value.kind, "attempt")) continue; // skip roster records
            if (std.mem.eql(u8, parsed.value.phase, "result")) continue; // see refreshFromLog
            const ts = parseIso8601(parsed.value.timestamp) orelse continue;
            self.addHistorical(parsed.value.user, ts) catch {};
        }
    }
};

/// Parse "YYYY-MM-DDTHH:MM:SSZ" to UTC epoch seconds, or null on malformed.
pub fn parseIso8601(s: []const u8) ?i64 {
    if (s.len < 20) return null;
    const y = parseN(s[0..4]) orelse return null;
    const mo = parseN(s[5..7]) orelse return null;
    const d = parseN(s[8..10]) orelse return null;
    const h = parseN(s[11..13]) orelse return null;
    const mi = parseN(s[14..16]) orelse return null;
    const se = parseN(s[17..19]) orelse return null;
    if (mo < 1 or mo > 12 or d < 1 or d > 31) return null;
    return daysFromCivil(@intCast(y), mo, d) * 86400 + @as(i64, h) * 3600 + @as(i64, mi) * 60 + se;
}

fn parseN(slice: []const u8) ?u32 {
    var v: u32 = 0;
    for (slice) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

fn daysFromCivil(year: i64, month: u32, day: u32) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const doy = @divFloor(153 * (if (month > 2) m - 3 else m + 9) + 2, 5) + @as(i64, day) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

const testing = std.testing;

test "Policy defaults attempts-per-window to threshold-1" {
    const p = Policy.fromKnobs(5, 30, null, 1);
    try testing.expectEqual(@as(u32, 4), p.attempts_per_window);
    const p2 = Policy.fromKnobs(5, 30, 2, 1);
    try testing.expectEqual(@as(u32, 2), p2.attempts_per_window);
}

test "tryReserve paces a burst and only refills after a full quiet gap (streak model)" {
    const a = testing.allocator;
    // apw=2, window=60s, margin=0 for deterministic timing.
    var b = Budget.init(a, .{ .threshold = 3, .window_min = 1, .attempts_per_window = 2, .margin_min = 0 });
    defer b.deinit();

    try testing.expectEqual(@as(i64, 0), try b.tryReserve("jon", 0)); // 1st
    try testing.expectEqual(@as(i64, 0), try b.tryReserve("jon", 1)); // 2nd (streak=2=apw)
    // 3rd at t=2: at capacity; wait keyed to the MOST RECENT (t=1), not the
    // oldest: 1 + 60 - 2 = 59. (The old sliding-window code returned 58.)
    try testing.expectEqual(@as(i64, 59), try b.tryReserve("jon", 2));
    // A different user is unaffected.
    try testing.expectEqual(@as(i64, 0), try b.tryReserve("arya", 2));
    // At t=60 the OLDEST (t=0) has aged out of a trailing window, but the streak
    // must NOT refill — AD has not reset, because the most recent attempt (t=1)
    // is only 59s ago (< the 60s window). This is the crux of the fix: the old
    // sliding-window code granted here and walked the account toward a lockout.
    try testing.expect((try b.tryReserve("jon", 60)) > 0);
    // Only once a FULL window of silence has elapsed since the MOST RECENT
    // attempt (t=1 + 60 = 61) does AD reset and a fresh streak open.
    try testing.expectEqual(@as(i64, 0), try b.tryReserve("jon", 61));
}

// REGRESSION for the sliding-window vs AD-reset mismatch. AD's badPwdCount is a
// streak that resets only after a full window of quiet from the MOST RECENT bad
// password. A campaign that spreads a user's attempts across the window (every
// R seconds, R > margin) must NOT be allowed to trickle attempt apw+1 out before
// AD resets — otherwise it locks the account at ~threshold despite "correct"
// pacing. Here: threshold 5, window 1800s, apw 4, margin 60, attempts every
// R=100s at t=0,100,200,300. The 5th reserve must be deferred to a point where a
// full window of silence has elapsed since the most recent attempt (t>=300+1800),
// i.e. AD will have reset — never granted early into a still-counting streak.
test "spread-out campaign never lets a streak reach the threshold" {
    const a = testing.allocator;
    var b = Budget.init(a, .{ .threshold = 5, .window_min = 30, .attempts_per_window = 4, .margin_min = 1 });
    defer b.deinit();
    const R: i64 = 100;
    var t: i64 = 0;
    var granted: usize = 0;
    while (t <= 300) : (t += R) {
        if ((try b.tryReserve("victim", t)) == 0) granted += 1;
    }
    try testing.expectEqual(@as(usize, 4), granted); // exactly apw, never a 5th
    // The 5th reserve at t=300 must wait until AD has reset: >= mostRecent(300) +
    // window(1800) + margin(60) - now(300) = 1860.
    const wait = try b.tryReserve("victim", 300);
    try testing.expectEqual(@as(i64, 1860), wait);
    // Attempting again anywhere inside the still-counting streak stays deferred,
    // so AD's counter (max 4) can never reach threshold 5.
    try testing.expect((try b.tryReserve("victim", 300 + 1000)) > 0);
    // After a full window of silence since the last attempt, a fresh streak opens.
    try testing.expectEqual(@as(i64, 0), try b.tryReserve("victim", 300 + 1800 + 60));
}

test "loadFromLog seeds windows from NDJSON timestamps" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const store = @import("../state/store.zig");

    const path = "test_budget.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try store.Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        // A real attempt publishes a RESERVATION (what the budget counts) and
        // then an outcome record (which it must ignore).
        try s.appendReservation("jon", "p1");
        try s.append(.{ .user = "jon", .password = "p1", .result = .invalid, .kdc_error_code = 24 });
        try s.appendReservation("jon", "p2");
        try s.append(.{ .user = "jon", .password = "p2", .result = .invalid, .kdc_error_code = 24 });
    }
    var b = Budget.init(a, .{ .threshold = 5, .window_min = 525600, .attempts_per_window = 4, .margin_min = 1 });
    defer b.deinit();
    try b.loadFromLog(io, path, "EXAMPLE.COM");
    // Use a huge window so the just-written entries still count.
    const now = parseIso8601("2026-06-05T03:17:28Z").?;
    try testing.expectEqual(@as(usize, 2), b.windowCount("jon", now + 10));
    // Different realm not loaded.
    try testing.expectEqual(@as(usize, 0), b.windowCount("nobody", now + 10));
}

test "parseIso8601 round number" {
    // 1970-01-01T00:00:00Z == 0
    try testing.expectEqual(@as(i64, 0), parseIso8601("1970-01-01T00:00:00Z").?);
    // 2000-01-01T00:00:00Z == 946684800
    try testing.expectEqual(@as(i64, 946684800), parseIso8601("2000-01-01T00:00:00Z").?);
}

// REGRESSION TEST. AD is case-insensitive, so `Administrator` and
// `administrator` are ONE account with ONE lockout counter. Keying the budget
// on the raw string gave each spelling its own full budget — a mixed-case user
// list (routine from BloodHound/LDAP exports or hand-merged lists) would then
// spend DOUBLE the bad passwords against a single AD account and lock exactly
// the accounts the budget exists to protect.
test "budget treats username case variants as the same account" {
    const a = testing.allocator;
    var b = Budget.init(a, .{ .threshold = 3, .window_min = 60, .attempts_per_window = 2, .margin_min = 0 });
    defer b.deinit();

    try testing.expectEqual(@as(i64, 0), try b.tryReserve("Administrator", 0)); // 1st
    try testing.expectEqual(@as(i64, 0), try b.tryReserve("administrator", 1)); // 2nd, SAME account
    // Budget is now spent — a third spelling must be made to wait, not granted.
    try testing.expect((try b.tryReserve("ADMINISTRATOR", 2)) > 0);
    try testing.expectEqual(@as(usize, 2), b.windowCount("aDmInIsTrAtOr", 2));
}

test "attempts-per-window is clamped below the lockout threshold" {
    // Asking for 10 attempts against a threshold of 5 is an instruction to lock
    // every account; clamp to threshold-1 and flag it.
    const p = Policy.fromKnobs(5, 30, 10, 1);
    try testing.expectEqual(@as(u32, 4), p.attempts_per_window);
    try testing.expect(p.clamped());
    // Exactly at the threshold is still fatal — one window's budget locks it.
    try testing.expectEqual(@as(u32, 4), Policy.fromKnobs(5, 30, 5, 1).attempts_per_window);
    // A safe request passes through untouched and is not reported as clamped.
    const ok = Policy.fromKnobs(5, 30, 2, 1);
    try testing.expectEqual(@as(u32, 2), ok.attempts_per_window);
    try testing.expect(!ok.clamped());
    // Default (no override) is threshold-1 and never counts as clamped.
    try testing.expect(!Policy.fromKnobs(5, 30, null, 1).clamped());
    // threshold 0 means "no lockout policy": nothing to clamp against.
    try testing.expectEqual(@as(u32, 9), Policy.fromKnobs(0, 30, 9, 1).attempts_per_window);
}

// REGRESSION TEST for the concurrency case that locks a CLIENT'S accounts.
// The budget was seeded from the shared log once, at startup, and never again —
// so two operators on the same engagement (or one running a spray alongside a
// kerberoast) each believed they held the full per-user budget. Each stayed
// under the threshold alone; together they blew past it. The pre-flight
// collision check cannot catch it, because simultaneous starts read a clean log.
test "concurrent runs share one per-user budget instead of each getting a full one" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const store = @import("../state/store.zig");

    const path = "test_budget_concurrent.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Process A: threshold 5, so 4 attempts per window.
    var a_budget = Budget.init(a, .{ .threshold = 5, .window_min = 525_600, .attempts_per_window = 4, .margin_min = 0 });
    defer a_budget.deinit();
    a_budget.log_path = path;
    a_budget.log_realm = "EXAMPLE.COM";
    a_budget.run_id = "AAAA";

    // Process B writes three attempts against the SAME account.
    var b_store = try store.Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
    b_store.run_id = "BBBB";
    defer b_store.deinit();
    const now = parseIso8601("2026-07-28T12:00:00Z").?;
    try b_store.appendReservation("alice", "p1");
    try b_store.appendReservation("alice", "p2");
    try b_store.appendReservation("alice", "p3");

    // A picks them up and now has only ONE slot left, not four.
    a_budget.refreshFromLog(io, 10_000);
    try testing.expectEqual(@as(usize, 3), a_budget.windowCount("alice", now));
    try testing.expectEqual(@as(i64, 0), try a_budget.tryReserve("alice", now)); // 4th overall
    try testing.expect((try a_budget.tryReserve("alice", now)) > 0); // 5th refused

    // A's OWN records must not be double-counted when it re-reads the log.
    var a_store = try store.Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
    a_store.run_id = "AAAA";
    defer a_store.deinit();
    try a_store.appendReservation("alice", "p4");
    a_budget.last_refresh_ms = 0; // allow an immediate refresh
    a_budget.refreshFromLog(io, 20_000);
    try testing.expectEqual(@as(usize, 4), a_budget.windowCount("alice", now)); // still 4, not 5
}
