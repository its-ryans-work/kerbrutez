//! A minimal atomic spinlock. Zig 0.16 moved Mutex/Condition under `std.Io`
//! (they require an `Io`), but our logger/hash-file writes are short critical
//! sections shared across raw OS threads, so a spinlock built from
//! `std.atomic` is simpler and dependency-free here.

const std = @import("std");

pub const SpinLock = struct {
    locked: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn lock(self: *SpinLock) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    pub fn unlock(self: *SpinLock) void {
        self.locked.store(false, .release);
    }
};

const testing = std.testing;

test "spinlock basic acquire/release" {
    var l = SpinLock{};
    l.lock();
    try testing.expect(l.locked.load(.monotonic));
    l.unlock();
    try testing.expect(!l.locked.load(.monotonic));
}
