//! Lockout-policy model. Either assumed (the M2 default), supplied via flags, or
//! fetched from AD over LDAP (`--policy-fetch`) — the default domain policy plus
//! any fine-grained password-settings objects (PSOs), taking the most
//! restrictive so the derived cadence never trips a real lockout.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ldap = @import("ldap");
const budget = @import("../engine/budget.zig");

pub const LockoutPolicy = struct {
    /// 0 means "no account lockout".
    /// Effective threshold used everywhere. 0 genuinely means "no lockout".
    threshold: u32,
    /// What the directory actually said: null when the attribute was absent or
    /// unparseable, so callers can tell that apart from an explicit 0 (which
    /// disables every lockout protection). See `parseThreshold`.
    threshold_raw: ?u32 = null,
    observation_window_min: u32,
    duration_min: u32,
    /// Where this came from (e.g. "domain default", "PSO <name>"). BORROW.
    source: []const u8 = "domain default",

    /// Convert to a budget Policy. `apw` null => threshold-1 headroom.
    pub fn toBudget(self: LockoutPolicy, attempts_per_window: ?u32, margin_min: u32) budget.Policy {
        const window = if (self.observation_window_min == 0) 30 else self.observation_window_min;
        return budget.Policy.fromKnobs(self.threshold, window, attempts_per_window, margin_min);
    }
};

/// Parse a lockout threshold attribute.
///
/// Returns null when the attribute is ABSENT OR UNPARSEABLE, which must not be
/// confused with an explicit 0. AD uses 0 to mean "no lockout policy", and this
/// tool disables ALL pacing, lockout prediction and the collision check when the
/// threshold is 0 — so `catch 0` turned an unreadable value into a silent,
/// total loss of lockout protection. The caller keeps its assumed threshold in
/// that case and says so.
fn parseThreshold(v: ?[]const u8) ?u32 {
    const s = v orelse return null;
    const t = std.mem.trim(u8, s, " \t\r\n");
    if (t.len == 0) return null;
    return std.fmt.parseInt(u32, t, 10) catch null;
}

/// Parse an AD Interval (LargeInteger, negative 100-nanosecond units) to whole
/// minutes. Handles the sign and clamps absurd ("never") values.
pub fn parseIntervalMinutes(s: []const u8) u32 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    const body = if (trimmed.len > 0 and trimmed[0] == '-') trimmed[1..] else trimmed;
    const mag = std.fmt.parseInt(u64, body, 10) catch return 0;
    const minutes = mag / (60 * 10_000_000); // 100ns units per minute
    return if (minutes > std.math.maxInt(u32)) std.math.maxInt(u32) else @intCast(minutes);
}

/// Read the default domain lockout policy from the NC head object.
pub fn fetchDomainPolicy(client: *ldap.Client, allocator: Allocator, base_dn: []const u8) !LockoutPolicy {
    const filter = try ldap.filterPresent(allocator, "objectClass"); // (objectClass=*)
    defer allocator.free(filter);
    const attrs = [_][]const u8{ "lockoutThreshold", "lockoutObservationWindow", "lockoutDuration" };
    var res = try client.search(base_dn, .base, filter, &attrs);
    defer res.deinit();
    if (res.entries.len == 0) return error.PolicyNotFound;
    const e = res.entries[0];
    return .{
        .threshold = parseThreshold(e.first("lockoutThreshold")) orelse 0,
        .threshold_raw = parseThreshold(e.first("lockoutThreshold")),
        .observation_window_min = if (e.first("lockoutObservationWindow")) |s| parseIntervalMinutes(s) else 0,
        .duration_min = if (e.first("lockoutDuration")) |s| parseIntervalMinutes(s) else 0,
        .source = "domain default",
    };
}

/// Read any fine-grained password-settings objects (PSOs). OWNERSHIP: caller
/// frees the slice and each `source` string.
pub fn fetchPSOs(client: *ldap.Client, allocator: Allocator, base_dn: []const u8) ![]LockoutPolicy {
    const pso_base = try std.fmt.allocPrint(allocator, "CN=Password Settings Container,CN=System,{s}", .{base_dn});
    defer allocator.free(pso_base);
    const filter = try ldap.filterEquality(allocator, "objectClass", "msDS-PasswordSettings");
    defer allocator.free(filter);
    const attrs = [_][]const u8{ "name", "msDS-LockoutThreshold", "msDS-LockoutObservationWindow", "msDS-LockoutDuration" };

    var res = client.search(pso_base, .whole_subtree, filter, &attrs) catch return &.{};
    defer res.deinit();

    var out: std.ArrayList(LockoutPolicy) = .empty;
    errdefer {
        for (out.items) |p| allocator.free(p.source);
        out.deinit(allocator);
    }
    for (res.entries) |e| {
        const name = e.first("name") orelse "PSO";
        try out.append(allocator, .{
            .threshold = parseThreshold(e.first("msDS-LockoutThreshold")) orelse 0,
            .threshold_raw = parseThreshold(e.first("msDS-LockoutThreshold")),
            .observation_window_min = if (e.first("msDS-LockoutObservationWindow")) |s| parseIntervalMinutes(s) else 0,
            .duration_min = if (e.first("msDS-LockoutDuration")) |s| parseIntervalMinutes(s) else 0,
            .source = try std.fmt.allocPrint(allocator, "PSO {s}", .{name}),
        });
    }
    return out.toOwnedSlice(allocator);
}

/// Pick the most restrictive policy: the lowest non-zero threshold (tie broken
/// by the shortest observation window). If every policy has threshold 0 (no
/// lockout), returns a threshold-0 policy.
pub fn mostRestrictive(policies: []const LockoutPolicy) LockoutPolicy {
    var best: ?LockoutPolicy = null;
    for (policies) |p| {
        if (p.threshold == 0) continue;
        if (best == null) {
            best = p;
        } else {
            const b = best.?;
            if (p.threshold < b.threshold or (p.threshold == b.threshold and p.observation_window_min < b.observation_window_min)) {
                best = p;
            }
        }
    }
    if (best) |b| return b;
    // No lockout anywhere — return threshold 0 with the first policy's window.
    return if (policies.len > 0) policies[0] else .{ .threshold = 0, .observation_window_min = 30, .duration_min = 0 };
}

const testing = std.testing;

test "parseIntervalMinutes: -18000000000 == 30 minutes" {
    try testing.expectEqual(@as(u32, 30), parseIntervalMinutes("-18000000000"));
    try testing.expectEqual(@as(u32, 30), parseIntervalMinutes("18000000000"));
    try testing.expectEqual(@as(u32, 0), parseIntervalMinutes("0"));
    try testing.expectEqual(@as(u32, 15), parseIntervalMinutes("-9000000000"));
}

test "mostRestrictive picks lowest non-zero threshold" {
    const policies = [_]LockoutPolicy{
        .{ .threshold = 0, .observation_window_min = 30, .duration_min = 30, .source = "domain default" },
        .{ .threshold = 5, .observation_window_min = 30, .duration_min = 30, .source = "PSO a" },
        .{ .threshold = 3, .observation_window_min = 60, .duration_min = 60, .source = "PSO b" },
    };
    const r = mostRestrictive(&policies);
    try testing.expectEqual(@as(u32, 3), r.threshold);
    try testing.expectEqualStrings("PSO b", r.source);

    const none = [_]LockoutPolicy{.{ .threshold = 0, .observation_window_min = 30, .duration_min = 0 }};
    try testing.expectEqual(@as(u32, 0), mostRestrictive(&none).threshold);
}

test "toBudget derives cadence" {
    const lp = LockoutPolicy{ .threshold = 5, .observation_window_min = 30, .duration_min = 30 };
    const p = lp.toBudget(null, 1);
    try testing.expectEqual(@as(u32, 5), p.threshold);
    try testing.expectEqual(@as(u32, 30), p.window_min);
    try testing.expectEqual(@as(u32, 4), p.attempts_per_window);
}

// REGRESSION TEST. AD uses lockoutThreshold=0 to mean "no lockout policy", and
// kerbrutez disables pacing, lockout prediction AND the collision check when the
// threshold is 0. Parsing an unreadable value as 0 therefore turned a parse
// hiccup into a silent, total loss of lockout protection — the most permissive
// possible reading of input we failed to understand.
test "an unreadable lockoutThreshold is not mistaken for 'no lockout policy'" {
    // Absent, blank and malformed are all "we don't know" (null)...
    try testing.expectEqual(@as(?u32, null), parseThreshold(null));
    try testing.expectEqual(@as(?u32, null), parseThreshold(""));
    try testing.expectEqual(@as(?u32, null), parseThreshold("   "));
    try testing.expectEqual(@as(?u32, null), parseThreshold("not-a-number"));
    try testing.expectEqual(@as(?u32, null), parseThreshold("-1"));
    try testing.expectEqual(@as(?u32, null), parseThreshold("99999999999999999999"));

    // ...while a real 0 stays a real 0, and normal values parse (with padding,
    // which LDAP values sometimes carry).
    try testing.expectEqual(@as(?u32, 0), parseThreshold("0"));
    try testing.expectEqual(@as(?u32, 5), parseThreshold("5"));
    try testing.expectEqual(@as(?u32, 5), parseThreshold(" 5\r\n"));
}
