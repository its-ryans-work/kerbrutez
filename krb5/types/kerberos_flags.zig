//! RFC 4120 §5.2.8 KerberosFlags (used for KDCOptions). Always a 32-bit field.

const std = @import("std");

pub const KrbFlags = struct {
    bytes: [4]u8 = .{ 0, 0, 0, 0 },

    pub const bit_length: usize = 32;

    /// Set flag at bit position `i` (counted from the MSB of byte 0).
    pub fn setFlag(self: *KrbFlags, i: usize) void {
        const b = i / 8;
        const p: u3 = @intCast(7 - (i - 8 * b));
        self.bytes[b] |= (@as(u8, 1) << p);
    }

    pub fn isSet(self: KrbFlags, i: usize) bool {
        const b = i / 8;
        const p: u3 = @intCast(7 - (i - 8 * b));
        return (self.bytes[b] & (@as(u8, 1) << p)) != 0;
    }
};

const testing = std.testing;

test "KrbFlags renewable_ok bit 27 -> 0x00000010" {
    var f = KrbFlags{};
    f.setFlag(27); // renewable_ok
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x10 }, &f.bytes);
    try testing.expect(f.isSet(27));
    try testing.expect(!f.isSet(1));
}

test "KrbFlags forwardable bit 1 -> 0x40000000" {
    var f = KrbFlags{};
    f.setFlag(1);
    try testing.expectEqualSlices(u8, &.{ 0x40, 0x00, 0x00, 0x00 }, &f.bytes);
}
