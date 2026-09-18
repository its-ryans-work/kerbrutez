//! Cryptographically secure random bytes. Zig 0.16 removed
//! `std.crypto.random`/`std.posix.getrandom` and file access now goes through
//! the `Io` interface. We use /dev/urandom on POSIX (read via `Io`) and
//! RtlGenRandom on Windows.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

pub const Error = error{RandomSourceUnavailable};

const is_windows = builtin.os.tag == .windows;

// RtlGenRandom, exported from advapi32 as SystemFunction036 — the simplest
// always-available Windows CSPRNG (no BCrypt provider handle needed).
extern "advapi32" fn SystemFunction036(buffer: ?[*]u8, length: u32) callconv(.winapi) u8;

/// Fill `buf` with secure random bytes from the OS.
/// BORROW: `io` is not retained (and unused on Windows).
pub fn bytes(io: Io, buf: []u8) Error!void {
    if (is_windows) {
        if (buf.len == 0) return;
        if (SystemFunction036(buf.ptr, @intCast(buf.len)) == 0) return Error.RandomSourceUnavailable;
        return;
    }
    var file = Io.Dir.openFileAbsolute(io, "/dev/urandom", .{}) catch return Error.RandomSourceUnavailable;
    defer file.close(io);
    var rbuf: [64]u8 = undefined;
    var r = file.reader(io, &rbuf);
    r.interface.readSliceAll(buf) catch return Error.RandomSourceUnavailable;
}

/// Return a random non-negative i32 (used for Kerberos nonces).
pub fn nonce(io: Io) Error!i32 {
    var b: [4]u8 = undefined;
    try bytes(io, &b);
    const v = std.mem.readInt(u32, &b, .big) & 0x7FFF_FFFF;
    return @intCast(v);
}
