//! OPSEC governor: noise levels, jitter, request-rate throttling, user-order
//! randomisation, canary/bait protection and a business-hours gate.
//!
//! IMPORTANT INVARIANT: OPSEC controls only *timing and selection noise*. It
//! NEVER relaxes the lockout budget (engine/budget.zig) — a quiet profile slows
//! attempts down, it cannot raise attempts-per-window. Safety always wins.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const SpinLock = @import("../util/spinlock.zig").SpinLock;

/// How loud the operator is willing to be. The default is LOUD (3): kerbrutez
/// assumes an *authorised* engagement. Red-team / evasive work uses 1.
pub const NoiseLevel = enum(u8) {
    stealthy = 1,
    moderate = 2,
    loud = 3,

    pub fn parse(s: []const u8) ?NoiseLevel {
        if (std.mem.eql(u8, s, "1") or std.ascii.eqlIgnoreCase(s, "stealthy")) return .stealthy;
        if (std.mem.eql(u8, s, "2") or std.ascii.eqlIgnoreCase(s, "moderate")) return .moderate;
        if (std.mem.eql(u8, s, "3") or std.ascii.eqlIgnoreCase(s, "loud")) return .loud;
        return null;
    }
};

/// Pacing/selection defaults implied by a noise level. Explicit CLI flags
/// override any of these.
pub const Profile = struct {
    /// Random extra delay per attempt, milliseconds (0..jitter_ms).
    jitter_ms: u64,
    /// Global cap on requests/minute (0 = unlimited).
    rpm: u32,
    /// Shuffle the order of users/passwords.
    randomize: bool,
    /// Only operate during business hours.
    business_hours: bool,

    pub fn fromNoise(level: NoiseLevel) Profile {
        return switch (level) {
            // Loud: as fast as the budget allows; predictable order.
            .loud => .{ .jitter_ms = 0, .rpm = 0, .randomize = false, .business_hours = false },
            // Moderate: light jitter, gentle rate cap, shuffled order.
            .moderate => .{ .jitter_ms = 750, .rpm = 60, .randomize = true, .business_hours = false },
            // Stealthy: heavy jitter, slow, shuffled, business-hours only.
            .stealthy => .{ .jitter_ms = 4000, .rpm = 10, .randomize = true, .business_hours = true },
        };
    }
};

/// Per-attempt pacing: a global request-rate gate plus per-attempt jitter.
/// Thread-safe (all workers share one Governor).
pub const Governor = struct {
    jitter_ms: u64 = 0,
    /// Minimum spacing between successive attempts (derived from rpm). 0 = none.
    min_interval_ms: u64 = 0,
    lock: SpinLock = .{},
    /// Earliest monotonic-ms time the next attempt may start (rpm reservation).
    next_allowed_ms: i64 = 0,
    prng: std.Random.DefaultPrng,

    pub fn init(seed: u64, jitter_ms: u64, rpm: u32) Governor {
        return .{
            .jitter_ms = jitter_ms,
            .min_interval_ms = if (rpm > 0) @max(1, 60_000 / @as(u64, rpm)) else 0,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    /// True if this governor would impose no delay (can be skipped entirely).
    pub fn isNoop(self: *const Governor) bool {
        return self.jitter_ms == 0 and self.min_interval_ms == 0;
    }

    /// Reserve the next attempt slot at monotonic time `now_ms`; returns the
    /// number of milliseconds the caller should sleep before proceeding. Pure
    /// given the seed (testable): the rpm reservation is deterministic, jitter
    /// draws from the PRNG.
    pub fn reserve(self: *Governor, now_ms: i64) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        var wait: i64 = 0;
        if (self.min_interval_ms > 0) {
            const slot = @max(now_ms, self.next_allowed_ms);
            self.next_allowed_ms = slot + @as(i64, @intCast(self.min_interval_ms));
            wait = slot - now_ms;
        }
        var jit: u64 = 0;
        if (self.jitter_ms > 0) jit = self.prng.random().uintLessThan(u64, self.jitter_ms + 1);
        return @as(u64, @intCast(@max(wait, 0))) + jit;
    }
};

/// A set of usernames to NEVER touch (honeypot/canary accounts). Owns its keys.
pub const CanarySet = struct {
    allocator: Allocator,
    set: std.StringHashMapUnmanaged(void) = .{},

    pub fn deinit(self: *CanarySet) void {
        var it = self.set.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.set.deinit(self.allocator);
    }

    /// Load one username per line (lower-cased, '#' comments and blanks skipped).
    pub fn loadFromFile(allocator: Allocator, io: Io, path: []const u8) !CanarySet {
        var self = CanarySet{ .allocator = allocator };
        errdefer self.deinit();
        var file = try Io.Dir.cwd().openFile(io, path, .{});
        defer file.close(io);
        var buf: [4096]u8 = undefined;
        var reader = file.reader(io, &buf);
        const content = try reader.interface.allocRemaining(allocator, .limited(8 * 1024 * 1024));
        defer allocator.free(content);
        var it = std.mem.tokenizeScalar(u8, content, '\n');
        while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            try self.add(line);
        }
        return self;
    }

    /// Add a protected account. The entry is reduced to the same bare, lower-cased
    /// sAMAccountName that target usernames are reduced to, so the forms people
    /// actually paste into a canary file all match.
    pub fn add(self: *CanarySet, user: []const u8) !void {
        var tmp: [256]u8 = undefined;
        const canon = canonicalCanary(&tmp, user) orelse user;
        const key = try lowerDupe(self.allocator, canon);
        errdefer self.allocator.free(key);
        const gop = try self.set.getOrPut(self.allocator, key);
        if (gop.found_existing) self.allocator.free(key); // already present
    }

    /// Is `user` a protected account? Compared on the same canonical form the
    /// canary file entries were stored in (see `add`).
    ///
    /// FAILS CLOSED. A name too long to canonicalise is reported as a canary
    /// rather than waved through: this guard exists to guarantee an account is
    /// never touched, so the safe answer when we cannot tell is "don't touch
    /// it". The old code returned false there, i.e. sprayed it.
    pub fn contains(self: *const CanarySet, user: []const u8) bool {
        var tmp: [256]u8 = undefined;
        const key = canonicalCanary(&tmp, user) orelse return true;
        return self.set.contains(key);
    }

    pub fn count(self: *const CanarySet) usize {
        return self.set.count();
    }
};

/// Reduce an account name to the bare lower-cased sAMAccountName used as the
/// canary key, or null if it does not fit the scratch buffer.
///
/// Canary lists are pasted from AD exports and tickets, so entries turn up as
/// `honeypot`, `honeypot@corp.local` and `CORP\\honeypot`. Target usernames are
/// reduced to the bare form before they are sprayed (util/username.formatUsername),
/// so storing the raw entry meant a canary written in either of the other two
/// forms NEVER matched — and the one account the operator explicitly said to
/// never touch got sprayed. Both sides must be canonicalised the same way.
fn canonicalCanary(buf: *[256]u8, user: []const u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, user, " \t\r");
    // DOMAIN\user -> user
    const after_domain = if (std.mem.lastIndexOfScalar(u8, trimmed, '\\')) |i| trimmed[i + 1 ..] else trimmed;
    // user@realm -> user
    const bare = if (std.mem.indexOfScalar(u8, after_domain, '@')) |at| after_domain[0..at] else after_domain;
    if (bare.len == 0 or bare.len > buf.len) return null;
    for (bare, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..bare.len];
}

fn lowerDupe(allocator: Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| out[i] = std.ascii.toLower(c);
    return out;
}

/// Heuristic: does this username look like a deliberately-planted honeypot/bait
/// account? Tripping a canary is a fast way to get caught. We only WARN.
pub fn looksLikeBait(user: []const u8) bool {
    const needles = [_][]const u8{ "honey", "honeypot", "canary", "decoy", "bait", "trap", "donotuse", "do_not_use", "dont_use", "_bait", "fakeadmin", "test_admin", "admin_test" };
    var lower: [256]u8 = undefined;
    if (user.len > lower.len) return false;
    for (user, 0..) |c, i| lower[i] = std.ascii.toLower(c);
    const l = lower[0..user.len];
    for (needles) |n| {
        if (std.mem.indexOf(u8, l, n) != null) return true;
    }
    return false;
}

/// True if `epoch_secs`, shifted by `tz_offset_hours`, falls within
/// [start_hour, end_hour) on Mon–Fri. A simple, deterministic gate (no system
/// TZ database needed); the operator supplies the target's UTC offset.
pub fn isWithinBusinessHours(epoch_secs: i64, tz_offset_hours: i32, start_hour: u8, end_hour: u8) bool {
    const local = epoch_secs + @as(i64, tz_offset_hours) * 3600;
    const days = @divFloor(local, 86400);
    // 1970-01-01 was a Thursday (=4 with 0=Sunday).
    const dow = @mod(days + 4, 7); // 0=Sun .. 6=Sat
    if (dow == 0 or dow == 6) return false; // weekend
    const secs_of_day = @mod(local, 86400);
    const hour: i64 = @divFloor(secs_of_day, 3600);
    return hour >= start_hour and hour < end_hour;
}

const testing = std.testing;

test "NoiseLevel.parse accepts digits and names" {
    try testing.expectEqual(NoiseLevel.stealthy, NoiseLevel.parse("1").?);
    try testing.expectEqual(NoiseLevel.loud, NoiseLevel.parse("loud").?);
    try testing.expectEqual(@as(?NoiseLevel, null), NoiseLevel.parse("x"));
}

test "Profile.fromNoise: loud is wide open, stealthy is slow" {
    const loud = Profile.fromNoise(.loud);
    try testing.expect(loud.jitter_ms == 0 and loud.rpm == 0 and !loud.randomize);
    const stealth = Profile.fromNoise(.stealthy);
    try testing.expect(stealth.jitter_ms > 0 and stealth.rpm > 0 and stealth.randomize and stealth.business_hours);
}

test "Governor.reserve spaces attempts by 60000/rpm" {
    var g = Governor.init(12345, 0, 60); // 60 rpm => 1000ms apart, no jitter
    try testing.expectEqual(@as(u64, 0), g.reserve(0)); // first is immediate
    // second attempt arriving immediately must wait ~1000ms.
    try testing.expectEqual(@as(u64, 1000), g.reserve(0));
    // a third arriving at t=1500 waits until 2000 => 500ms.
    try testing.expectEqual(@as(u64, 500), g.reserve(1500));
    // arriving after the slot has passed => no wait.
    try testing.expectEqual(@as(u64, 0), g.reserve(10_000));
}

test "Governor noop detection + jitter bound" {
    var g0 = Governor.init(1, 0, 0);
    try testing.expect(g0.isNoop());
    var gj = Governor.init(1, 100, 0);
    try testing.expect(!gj.isNoop());
    var i: usize = 0;
    while (i < 50) : (i += 1) try testing.expect(gj.reserve(0) <= 100);
}

test "looksLikeBait flags honeypot-ish names, not normal ones" {
    try testing.expect(looksLikeBait("honeypot_svc"));
    try testing.expect(looksLikeBait("CANARY01"));
    try testing.expect(looksLikeBait("decoy.admin"));
    try testing.expect(!looksLikeBait("john.doe"));
    try testing.expect(!looksLikeBait("administrator"));
}

test "CanarySet skips listed users (case-insensitive)" {
    const a = testing.allocator;
    var cs = CanarySet{ .allocator = a };
    defer cs.deinit();
    try cs.add("HoneyAdmin");
    try cs.add("trap1");
    try cs.add("trap1"); // dup ignored
    try testing.expectEqual(@as(usize, 2), cs.count());
    try testing.expect(cs.contains("honeyadmin"));
    try testing.expect(cs.contains("HONEYADMIN"));
    try testing.expect(!cs.contains("john.doe"));
}

test "business hours: weekday in-window vs weekend/after-hours" {
    // 2024-01-03 (Wednesday) 14:00 UTC => epoch 1704290400.
    const wed_1400: i64 = 1704290400;
    try testing.expect(isWithinBusinessHours(wed_1400, 0, 8, 18));
    try testing.expect(!isWithinBusinessHours(wed_1400, 0, 8, 13)); // window ends 13:00
    // Same instant at tz -8 (06:00 local) => before 08:00.
    try testing.expect(!isWithinBusinessHours(wed_1400, -8, 8, 18));
    // 2024-01-06 (Saturday) 14:00 UTC => epoch 1704549600.
    const sat_1400: i64 = 1704549600;
    try testing.expect(!isWithinBusinessHours(sat_1400, 0, 8, 18));
}

// REGRESSION TEST for a fail-open in the one control that promises an account is
// never touched. Canary entries were stored verbatim (only lower-cased) while
// target usernames are reduced to the bare sAMAccountName before spraying — so a
// canary written as `honeypot@corp.local` or `CORP\honeypot`, which is exactly
// how they come out of AD exports, never matched and the honeypot got sprayed.
test "canary matches whatever form the account was written in" {
    const a = testing.allocator;
    var cs = CanarySet{ .allocator = a };
    defer cs.deinit();
    try cs.add("honeypot@corp.local"); // UPN form in the canary file
    try cs.add("CORP\\trap");          // down-level form
    try cs.add("  Decoy  ");           // padded + mixed case

    // Every spelling of a protected account must be caught.
    for ([_][]const u8{ "honeypot", "HONEYPOT", "honeypot@corp.local", "CORP\\honeypot" }) |u| {
        try testing.expect(cs.contains(u));
    }
    try testing.expect(cs.contains("trap"));
    try testing.expect(cs.contains("TRAP@other.realm"));
    try testing.expect(cs.contains("decoy"));

    // Unprotected accounts are still sprayable.
    try testing.expect(!cs.contains("alice"));
    try testing.expect(!cs.contains("honeypot2"));

    // FAIL CLOSED: a name we cannot canonicalise is treated as protected rather
    // than waved through.
    const huge = "x" ** 300;
    try testing.expect(cs.contains(huge));
}

test "governor delivers the advertised request rate" {
    // rpm 10 => one attempt every 6s; rpm 60 => every 1s.
    var g = Governor.init(1, 0, 10);
    try testing.expectEqual(@as(u64, 6_000), g.min_interval_ms);
    // Successive reservations from a standing start are spaced by the interval.
    try testing.expectEqual(@as(u64, 0), g.reserve(0));
    try testing.expectEqual(@as(u64, 6_000), g.reserve(0));
    try testing.expectEqual(@as(u64, 12_000), g.reserve(0));
    // A caller arriving after the slot has already passed waits not at all.
    var g2 = Governor.init(1, 0, 60);
    try testing.expectEqual(@as(u64, 1_000), g2.min_interval_ms);
    _ = g2.reserve(0);
    try testing.expectEqual(@as(u64, 0), g2.reserve(10_000));
    // rpm 0 disables the gate entirely.
    try testing.expectEqual(@as(u64, 0), Governor.init(1, 0, 0).min_interval_ms);
}
