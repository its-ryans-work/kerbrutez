//! RFC 4120 §5.2.9 EncryptedData / EncryptionKey.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");

/// EncryptedData ::= SEQUENCE {
///   [0] etype INTEGER, [1] kvno INTEGER OPTIONAL, [2] cipher OCTET STRING }
pub const EncryptedData = struct {
    etype: i32,
    /// kvno of 0 is treated as "absent" and omitted on marshal (matches Go's
    /// optional-field behaviour).
    kvno: i32 = 0,
    /// BORROW or OWNED depending on construction; `unmarshal` borrows from the
    /// source buffer.
    cipher: []const u8,

    /// OWNERSHIP: caller frees.
    pub fn marshal(self: EncryptedData, allocator: Allocator) ![]u8 {
        const et = try der.encodeInt(allocator, self.etype);
        defer allocator.free(et);
        const field0 = try der.explicit(allocator, 0, et);
        defer allocator.free(field0);

        const c = try der.encodeOctetString(allocator, self.cipher);
        defer allocator.free(c);
        const field2 = try der.explicit(allocator, 2, c);
        defer allocator.free(field2);

        if (self.kvno != 0) {
            const kv = try der.encodeInt(allocator, self.kvno);
            defer allocator.free(kv);
            const field1 = try der.explicit(allocator, 1, kv);
            defer allocator.free(field1);
            return der.sequence(allocator, &.{ field0, field1, field2 });
        }
        return der.sequence(allocator, &.{ field0, field2 });
    }

    /// Parse from a SEQUENCE element. BORROW: `cipher` points into the source.
    pub fn unmarshal(seq: der.Element) !EncryptedData {
        var ed = EncryptedData{ .etype = 0, .kvno = 0, .cipher = &.{} };
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                0 => ed.etype = try (try field.inner()).integer32(),
                1 => ed.kvno = try (try field.inner()).integer32(),
                2 => ed.cipher = (try field.inner()).bytes(),
                else => {}, // ignore unknown context tags
            }
        }
        return ed;
    }
};

/// EncryptionKey ::= SEQUENCE { [0] keytype INTEGER, [1] keyvalue OCTET STRING }
pub const EncryptionKey = struct {
    key_type: i32,
    key_value: []const u8,

    /// Parse from a SEQUENCE element. BORROW: `key_value` points into source.
    pub fn unmarshal(seq: der.Element) !EncryptionKey {
        var k = EncryptionKey{ .key_type = 0, .key_value = &.{} };
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                0 => k.key_type = try (try field.inner()).integer32(),
                1 => k.key_value = (try field.inner()).bytes(),
                else => {},
            }
        }
        return k;
    }
};

const testing = std.testing;

test "EncryptedData marshal matches gokrb5 (kvno omitted when 0)" {
    const a = testing.allocator;
    const ed = EncryptedData{ .etype = 18, .kvno = 0, .cipher = &.{ 0xAA, 0xBB } };
    const b = try ed.marshal(a);
    defer a.free(b);
    // Verified against gokrb5: 300ba003020112a2040402aabb
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("300ba003020112a2040402aabb", try std.fmt.bufPrint(&buf, "{x}", .{b}));

    const ed2 = EncryptedData{ .etype = 18, .kvno = 5, .cipher = &.{ 0xAA, 0xBB } };
    const b2 = try ed2.marshal(a);
    defer a.free(b2);
    try testing.expectEqualStrings("3010a003020112a103020105a2040402aabb", try std.fmt.bufPrint(&buf, "{x}", .{b2}));
}

test "EncryptedData round trip" {
    const a = testing.allocator;
    const ed = EncryptedData{ .etype = 23, .kvno = 3, .cipher = &.{ 1, 2, 3, 4, 5 } };
    const b = try ed.marshal(a);
    defer a.free(b);
    const r = try der.read(b);
    const parsed = try EncryptedData.unmarshal(r.elem);
    try testing.expectEqual(@as(i32, 23), parsed.etype);
    try testing.expectEqual(@as(i32, 3), parsed.kvno);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5 }, parsed.cipher);
}
