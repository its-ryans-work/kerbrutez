//! Leveled, timestamped, colorised logger — a thread-safe stand-in for the
//! go-logging setup kerbrute uses. Writes coloured lines to stdout and, when
//! configured, plain lines to a log file. Format mirrors kerbrute:
//!   `<color>YYYY/MM/DD HH:MM:SS >  <message><reset>`

const std = @import("std");
const Io = std.Io;
const secret_file = @import("../util/secret_file.zig");
const SpinLock = @import("spinlock.zig").SpinLock;
const Status = @import("status.zig").Status;

/// A byte that must never reach a terminal verbatim: a C0 control (except the
/// `\n`/`\t` our own format strings use) or DEL. Attacker/AD-controlled data
/// (sAMAccountName, SPN, BloodHound export, nxc capture) flows into both the
/// console log AND the plain-text report files, so BOTH sinks scrub with this
/// one predicate — a terminal escape sequence in a name could otherwise forge or
/// hide findings when the operator cats the console output or a deliverable.
pub fn isUnsafeControl(c: u8) bool {
    return (c < 0x20 and c != '\n' and c != '\t') or c == 0x7F;
}

/// Write `s` to `w` with unsafe control bytes replaced by '?'. Shared by the
/// report writers so they can't drift from the logger's neutralization.
pub fn scrubControlsInto(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| try w.writeByte(if (isUnsafeControl(c)) '?' else c);
}

/// Strict variant for report DATA fields (username / SPN / hash / note): also
/// neutralizes '\n' and '\t'. Those never legitimately appear in such a field,
/// and — unlike the console logger, which prefixes only the first line so an
/// injected newline shows up conspicuously unprefixed — the report file writers
/// have no per-line prefix, so a raw '\n' in a field would forge a whole record.
pub fn scrubFieldInto(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |c| try w.writeByte(if (c < 0x20 or c == 0x7F) '?' else c);
}

pub const Level = enum(u8) {
    debug = 0,
    info = 1,
    notice = 2,
    warning = 3,
    err = 4,

    fn color(self: Level) []const u8 {
        return switch (self) {
            .debug => "\x1b[36m", // cyan
            .info => "", // default
            .notice => "\x1b[32m", // green
            .warning => "\x1b[33m", // yellow
            .err => "\x1b[31m", // red
        };
    }
};

const reset = "\x1b[0m";

pub const Logger = struct {
    io: Io,
    lock_: SpinLock = .{},
    min_level: Level,
    stdout: Io.File,
    /// Whether stdout is a terminal. Colour is emitted only when it is, so a
    /// redirected run produces a clean, greppable log (tests replace `stdout`
    /// with a file and leave this false).
    stdout_is_tty: bool = false,
    file: ?Io.File,
    /// Optional live status block (campaign mode on a TTY). BORROW.
    status: ?*Status = null,

    /// Create a logger. `log_file` (if non-null) is created/truncated and all
    /// shown lines are also written there without colour.
    /// OWNERSHIP: call `deinit` to close the log file.
    pub fn init(io: Io, verbose: bool, log_file_path: ?[]const u8) !Logger {
        var file: ?Io.File = null;
        if (log_file_path) |path| {
            // Contains "VALID LOGIN: user:password" lines.
            file = try secret_file.create(io, path, .{ .truncate = true });
        }
        return .{
            .io = io,
            .min_level = if (verbose) .debug else .info,
            .stdout = Io.File.stdout(),
            .stdout_is_tty = Io.File.stdout().isTty(io) catch false,
            .file = file,
        };
    }

    pub fn deinit(self: *Logger) void {
        if (self.file) |f| f.close(self.io);
        self.file = null;
    }

    pub fn debug(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.debug, fmt, args);
    }
    pub fn info(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.info, fmt, args);
    }
    pub fn notice(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.notice, fmt, args);
    }
    pub fn warning(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.warning, fmt, args);
    }
    pub fn err(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.log(.err, fmt, args);
    }

    /// TYPE CONSTRAINT: `args` must be a tuple matching `fmt`'s placeholders.
    fn log(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) return;

        // DEGRADE, DON'T VANISH. `bufPrint ... catch msg_buf[0..0]` turned any
        // over-long line into an EMPTY one. The longest lines here are captured
        // `$krb5tgs$`/`$krb5asrep$` hashes, whose size scales with the ticket's
        // PAC — i.e. with the target's group memberships — so the highest-value
        // accounts are exactly the ones whose hash would have logged blank.
        // A fixed writer keeps whatever fits and we flag the truncation, so the
        // operator sees the finding and knows to read the -o/hash file for the
        // full value.
        var msg_buf: [8192]u8 = undefined;
        const reserve = 24; // room for the truncation marker
        var mw: std.Io.Writer = .fixed(msg_buf[0 .. msg_buf.len - reserve]);
        var truncated = false;
        mw.print(fmt, args) catch {
            truncated = true;
        };
        var used = mw.buffered().len;
        if (truncated) {
            const marker = " …[TRUNCATED]";
            @memcpy(msg_buf[used .. used + marker.len], marker);
            used += marker.len;
        }
        // NEUTRALISE TERMINAL CONTROL SEQUENCES coming from DATA.
        //
        // Everything interpolated here is attacker-influenceable: usernames from
        // a downloaded wordlist, sAMAccountName/description straight from the
        // target's DC, names inside a third-party BloodHound export. This logger
        // adds its own colour AROUND the message (see writeLine), so any escape
        // byte INSIDE it came from that data — never from us.
        //
        // Left raw, a crafted account name forges findings: `ESC[2K` + CR wipes
        // our timestamp prefix, the name then prints its own green
        // "[+] VALID LOGIN: administrator@corp:Summer2026!", and `ESC[1A` hides
        // the remainder. For a tool whose console output IS the deliverable,
        // that means reporting a credential to a client that never existed.
        //
        // \n and \t are kept because our own format strings use them (the hash
        // lines and the VALID LOGIN column). A newline injected by data is still
        // visible as an anomaly, because writeLine prefixes only the FIRST line
        // with the timestamp — a forged line arrives conspicuously unprefixed.
        const msg = msg_buf[0..used];
        for (msg) |*c| {
            if (isUnsafeControl(c.*)) c.* = '?';
        }

        var ts_buf: [20]u8 = undefined;
        const ts = formatTimestamp(self.io, &ts_buf);

        self.lock_.lock();
        defer self.lock_.unlock();

        // Lift any live status block so this line scrolls above it.
        if (self.status) |st| {
            if (st.drawn) self.clearBlock(st);
        }
        // Colour ONLY when stdout is a terminal. Redirected output (`> run.log`,
        // `| grep`, a CI job) was getting raw ANSI escapes baked into the file,
        // which is both unparseable and a poor deliverable — note the -o log has
        // always been written plain, so the two disagreed.
        const use_colour = self.stdout_is_tty;
        writeLine(self.io, self.stdout, if (use_colour) level.color() else "", ts, msg, if (use_colour) reset else "");
        // Plain to the log file (never the status block).
        if (self.file) |f| writeLine(self.io, f, "", ts, msg, "");
        // Redraw the status block at the new bottom.
        if (self.status) |st| self.drawBlock(st);
    }

    /// Attach (or detach) the live status block. Clears any previous one.
    pub fn setStatus(self: *Logger, s: ?*Status) void {
        self.lock_.lock();
        defer self.lock_.unlock();
        if (self.status) |old| {
            if (old.drawn) self.clearBlock(old);
        }
        self.status = s;
    }

    /// Redraw the status block (called ~1/s by the ticker thread).
    pub fn refreshStatus(self: *Logger) void {
        self.lock_.lock();
        defer self.lock_.unlock();
        if (self.status) |st| {
            if (st.drawn) self.clearBlock(st);
            self.drawBlock(st);
        }
    }

    /// Remove the live status block for good (call once at the end of the run).
    pub fn finishStatus(self: *Logger) void {
        self.lock_.lock();
        defer self.lock_.unlock();
        if (self.status) |st| {
            if (st.drawn) self.clearBlock(st);
        }
        self.status = null;
    }

    // Cursor up `height` lines + clear to end of screen (caller holds the lock).
    fn clearBlock(self: *Logger, st: *Status) void {
        var buf: [32]u8 = undefined;
        var w = self.stdout.writerStreaming(self.io, &buf);
        w.interface.print("\x1b[{d}A\x1b[0J", .{Status.height}) catch return;
        w.interface.flush() catch {};
        st.drawn = false;
    }

    // Render the block at the current cursor (caller holds the lock).
    fn drawBlock(self: *Logger, st: *Status) void {
        var buf: [1024]u8 = undefined;
        var w = self.stdout.writerStreaming(self.io, &buf);
        const now_ms = Io.Timestamp.now(self.io, .awake).toMilliseconds();
        st.render(&w.interface, now_ms) catch {};
        w.interface.flush() catch {};
        st.drawn = true;
    }
};

fn writeLine(io: Io, file: Io.File, color: []const u8, ts: []const u8, msg: []const u8, reset_str: []const u8) void {
    // Streaming (not positional) so each line appends; a positional writer
    // would restart at offset 0 every call and overwrite when stdout/-o is a
    // regular file.
    var buf: [8320]u8 = undefined;
    var w = file.writerStreaming(io, &buf);
    w.interface.print("{s}{s} >  {s}{s}\n", .{ color, ts, msg, reset_str }) catch return;
    w.interface.flush() catch {};
}

/// Format the current UTC time as "YYYY/MM/DD HH:MM:SS".
fn formatTimestamp(io: Io, out: *[20]u8) []const u8 {
    const now = Io.Timestamp.now(io, .real).toSeconds();
    const days = @divFloor(now, 86400);
    var rem = @mod(now, 86400);
    const hour: u32 = @intCast(@divFloor(rem, 3600));
    rem -= @as(i64, hour) * 3600;
    const minute: u32 = @intCast(@divFloor(rem, 60));
    const second: u32 = @intCast(rem - @as(i64, minute) * 60);
    const ymd = civilFromDays(days);
    return std.fmt.bufPrint(out, "{d:0>4}/{d:0>2}/{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
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

test "timestamp format shape" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    var buf: [20]u8 = undefined;
    const ts = formatTimestamp(threaded.io(), &buf);
    try testing.expectEqual(@as(usize, 19), ts.len);
    try testing.expectEqual(@as(u8, '/'), ts[4]);
    try testing.expectEqual(@as(u8, '/'), ts[7]);
    try testing.expectEqual(@as(u8, ' '), ts[10]);
    try testing.expectEqual(@as(u8, ':'), ts[13]);
}

// REGRESSION TEST. An over-long line used to be replaced by NOTHING
// (`bufPrint ... catch msg_buf[0..0]`). The longest lines this logger carries
// are captured kerberoast/AS-REP hashes, whose length scales with the ticket's
// PAC and therefore with the target's group memberships — so a Domain Admin's
// hash was the most likely of all to be logged as a blank line.
test "an over-long log line is truncated with a marker, never blanked" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var logger = try Logger.init(io, false, null);
    defer logger.deinit();
    const path = "zz_log_truncate.log";
    const sink = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, path) catch {};
    }

    // Stand in for a very large $krb5tgs$ hash line.
    const huge = "A" ** 12000;
    logger.notice("[+] roast hash: {s}", .{huge});

    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [1024]u8 = undefined;
    var r = f.reader(io, &rbuf);
    const content = try r.interface.allocRemaining(a, .unlimited);
    defer a.free(content);

    // The finding survives: the prefix is present and the loss is announced.
    try testing.expect(std.mem.indexOf(u8, content, "[+] roast hash: AAA") != null);
    try testing.expect(std.mem.indexOf(u8, content, "TRUNCATED") != null);
}

// SECURITY REGRESSION TEST. Everything this logger interpolates is
// attacker-influenceable — usernames from a downloaded wordlist,
// sAMAccountName/description straight from the target's DC, names inside a
// third-party BloodHound export. Printed raw, a crafted name forged findings:
// ESC[2K + CR erased our timestamp prefix and the name printed its own green
// "[+] VALID LOGIN: administrator@corp:Summer2026!", with ESC[1A to hide the
// rest. For a tool whose console output is the deliverable, that means
// reporting a credential to a client that never existed.
test "terminal control sequences in data cannot forge or hide output" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var logger = try Logger.init(io, false, null);
    defer logger.deinit();
    const path = "zz_log_ansi.log";
    const sink = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, path) catch {};
    }

    // The exact shape a hostile directory entry would use.
    const evil = "\x1b[2K\r\x1b[32m[+] VALID LOGIN:\t administrator@corp:Summer2026!\x1b[0m\x1b[1A";
    logger.notice("[+] {s}@corp.example.com", .{evil});

    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [1024]u8 = undefined;
    var r = f.reader(io, &rbuf);
    const content = try r.interface.allocRemaining(a, .unlimited);
    defer a.free(content);

    // No ESC and no CR may survive from the DATA. (The logger's own colour codes
    // are written separately by writeLine, so we check the payload region only:
    // everything after our "[+] " marker and before the trailing reset.)
    const start = std.mem.indexOf(u8, content, "[+] ").? + 4;
    const end = std.mem.lastIndexOfScalar(u8, content, 0x1B) orelse content.len;
    const payload = content[start..end];
    try testing.expect(std.mem.indexOfScalar(u8, payload, 0x1B) == null); // no ESC
    try testing.expect(std.mem.indexOfScalar(u8, payload, '\r') == null); // no CR

    // The text is still shown (neutralised, not silently dropped) so the
    // operator can see the name is hostile.
    try testing.expect(std.mem.indexOf(u8, content, "?[2K") != null);
    // And our own timestamp prefix survived, which is what made the forgery work.
    try testing.expect(std.mem.indexOf(u8, content, " >  [+] ") != null);
}

// Colour belongs on a terminal, not in a file. A redirected run (`> run.log`,
// `| grep`, CI) was getting raw ANSI escapes baked into the output, which is
// unparseable and a poor deliverable — and the -o log has always been plain, so
// the two disagreed about the same run.
test "colour is emitted only when stdout is a terminal" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "zz_log_colour.log";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const read = struct {
        fn all(alloc: std.mem.Allocator, i: Io, p: []const u8) []u8 {
            var f = Io.Dir.cwd().openFile(i, p, .{}) catch unreachable;
            defer f.close(i);
            var buf: [1024]u8 = undefined;
            var r = f.reader(i, &buf);
            return r.interface.allocRemaining(alloc, .unlimited) catch unreachable;
        }
    };

    // Not a terminal (the normal case for a redirected run): no escapes at all.
    {
        var logger = try Logger.init(io, false, null);
        defer logger.deinit();
        const sink = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        logger.stdout = sink;
        logger.stdout_is_tty = false;
        logger.notice("[+] VALID LOGIN: alice", .{});
        sink.close(io);

        const c = read.all(a, io, path);
        defer a.free(c);
        try testing.expect(std.mem.indexOfScalar(u8, c, 0x1B) == null);
        try testing.expect(std.mem.indexOf(u8, c, "VALID LOGIN: alice") != null);
    }

    // A terminal still gets its colour.
    {
        var logger = try Logger.init(io, false, null);
        defer logger.deinit();
        const sink = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        logger.stdout = sink;
        logger.stdout_is_tty = true;
        logger.notice("[+] VALID LOGIN: alice", .{});
        sink.close(io);

        const c = read.all(a, io, path);
        defer a.free(c);
        try testing.expect(std.mem.indexOfScalar(u8, c, 0x1B) != null);
    }
}
