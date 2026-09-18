//! Live campaign status block (M-extra).
//!
//! A fixed-height block redrawn in place at the bottom of the terminal while a
//! spray/brute campaign runs. The Logger clears and redraws it around every log
//! line (so findings scroll above it), and a 1 s ticker thread redraws it so the
//! elapsed/countdown timers tick. Only used on a TTY in campaign mode.

const std = @import("std");
const Io = std.Io;
const Writer = std.Io.Writer;

const green = "\x1b[32m";
const yellow = "\x1b[33m";
const red = "\x1b[31m";
const dim = "\x1b[2m";
const reset = "\x1b[0m";

pub const Status = struct {
    /// What the campaign is doing, e.g. "password-spray campaign".
    label: []const u8,
    total_passwords: usize,
    total_users: usize,
    /// Monotonic (`.awake`) milliseconds at campaign start.
    start_ms: i64,
    /// Live counters owned by the worker pool.
    attempts: *std.atomic.Value(u32),
    successes: *std.atomic.Value(u32),
    locked: *std.atomic.Value(u32),
    /// Monotonic ms of the most recent attempt / the next scheduled attempt
    /// (0 = none). Updated by the workers.
    last_attempt_ms: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    next_attempt_ms: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),
    /// Whether a block is currently on screen (guarded by the Logger lock).
    drawn: bool = false,

    /// Number of terminal lines the block occupies (must match `render`).
    pub const height: usize = 5;

    pub fn noteAttempt(self: *Status, now_ms: i64) void {
        self.last_attempt_ms.store(now_ms, .monotonic);
    }
    pub fn noteNext(self: *Status, at_ms: i64) void {
        self.next_attempt_ms.store(at_ms, .monotonic);
    }
    pub fn clearNext(self: *Status) void {
        self.next_attempt_ms.store(0, .monotonic);
    }

    /// Render the block (exactly `height` newline-terminated lines).
    pub fn render(self: *Status, w: *Writer, now_ms: i64) Writer.Error!void {
        const z = self.attempts.load(.monotonic);
        const g = self.successes.load(.monotonic);
        const h = self.locked.load(.monotonic);

        var b1: [16]u8 = undefined;
        var b2: [16]u8 = undefined;
        var b3: [16]u8 = undefined;
        const last = self.last_attempt_ms.load(.monotonic);
        const next = self.next_attempt_ms.load(.monotonic);
        const since = if (last == 0) "--:--" else fmtDur(&b1, @divFloor(now_ms - last, 1000));
        const until = if (next == 0 or next <= now_ms) "now" else fmtDur(&b2, @divFloor(next - now_ms, 1000));
        const total = fmtDur(&b3, @divFloor(now_ms - self.start_ms, 1000));

        try w.print("  {d} password(s) sprayed across {d} users for {d} total guesses.\n", .{ self.total_passwords, self.total_users, z });
        try w.print("  {s} since last  |  {s} until next  |  {s} total on {s}\n", .{ since, until, total, self.label });
        try w.writeByte('\n');
        try w.print("  {s}{d} valid password(s) discovered{s}\n", .{ green, g, reset });
        const hc: []const u8 = if (h > 3) red else if (h > 0) yellow else dim;
        try w.print("  {s}{d} account(s) locked out{s}\n", .{ hc, h, reset });
    }
};

/// Format whole seconds as MM:SS (or H:MM:SS past an hour). Computed unsigned so
/// the zero-pad doesn't render a sign.
fn fmtDur(buf: []u8, secs_in: i64) []const u8 {
    const secs: u64 = if (secs_in < 0) 0 else @intCast(secs_in);
    const h = secs / 3600;
    const m = (secs % 3600) / 60;
    const s = secs % 60;
    if (h > 0) return std.fmt.bufPrint(buf, "{d}:{d:0>2}:{d:0>2}", .{ h, m, s }) catch "?";
    return std.fmt.bufPrint(buf, "{d:0>2}:{d:0>2}", .{ m, s }) catch "?";
}

const testing = std.testing;

test "render emits exactly `height` lines and the live counts" {
    var attempts = std.atomic.Value(u32).init(42);
    var successes = std.atomic.Value(u32).init(2);
    var locked = std.atomic.Value(u32).init(5);
    var st = Status{
        .label = "password-spray campaign",
        .total_passwords = 1,
        .total_users = 100,
        .start_ms = 0,
        .attempts = &attempts,
        .successes = &successes,
        .locked = &locked,
    };
    st.noteAttempt(60_000); // 1 min ago relative to now=120s

    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try st.render(&w, 120_000);
    const out = w.buffered();

    var lines: usize = 0;
    for (out) |c| {
        if (c == '\n') lines += 1;
    }
    try testing.expectEqual(Status.height, lines);
    try testing.expect(std.mem.indexOf(u8, out, "100 users for 42 total guesses") != null);
    try testing.expect(std.mem.indexOf(u8, out, "2 valid password(s)") != null);
    try testing.expect(std.mem.indexOf(u8, out, "5 account(s) locked out") != null);
    try testing.expect(std.mem.indexOf(u8, out, "01:00 since last") != null); // 120s - 60s
}

test "fmtDur formats mm:ss and h:mm:ss" {
    var b: [16]u8 = undefined;
    try testing.expectEqualStrings("00:05", fmtDur(&b, 5));
    try testing.expectEqualStrings("02:03", fmtDur(&b, 123));
    try testing.expectEqualStrings("1:01:05", fmtDur(&b, 3665));
}
