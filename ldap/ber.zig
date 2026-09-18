//! Minimal BER (ASN.1) codec for the subset LDAP (RFC 4511) needs.
//!
//! LDAP uses definite-length BER, which for the types we emit is identical to
//! DER. This is a self-contained codec so the `ldap` module has no dependency
//! on the Kerberos library. Encoders build TLVs bottom-up as owned slices
//! (OWNERSHIP: caller frees; callers typically use an arena).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{ Truncated, InvalidLength, HighTagNumberForm, InvalidInteger };

pub const tag = struct {
    pub const boolean: u8 = 0x01;
    pub const integer: u8 = 0x02;
    pub const octet_string: u8 = 0x04;
    pub const enumerated: u8 = 0x0A;
    pub const sequence: u8 = 0x30; // constructed
    pub const set: u8 = 0x31; // constructed
};

/// Encode a definite length (short form <=127, else long form).
pub fn encodeLength(allocator: Allocator, l: usize) ![]u8 {
    if (l <= 127) {
        const b = try allocator.alloc(u8, 1);
        b[0] = @intCast(l);
        return b;
    }
    var n: usize = 0;
    var v = l;
    while (v > 0) : (v >>= 8) n += 1;
    const b = try allocator.alloc(u8, n + 1);
    b[0] = 0x80 | @as(u8, @intCast(n));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const shift: u6 = @intCast((n - 1 - i) * 8);
        b[1 + i] = @truncate(l >> shift);
    }
    return b;
}

/// Emit a full TLV. OWNERSHIP: caller frees.
pub fn tlv(allocator: Allocator, tag_byte: u8, content: []const u8) ![]u8 {
    const len = try encodeLength(allocator, content.len);
    defer allocator.free(len);
    const out = try allocator.alloc(u8, 1 + len.len + content.len);
    out[0] = tag_byte;
    @memcpy(out[1 .. 1 + len.len], len);
    @memcpy(out[1 + len.len ..], content);
    return out;
}

fn intLength(value: i64) usize {
    var length: usize = 1;
    var v = value;
    while (v > 127 or v < -128) : (v >>= 8) length += 1;
    return length;
}

fn intContent(allocator: Allocator, value: i64) ![]u8 {
    const length = intLength(value);
    const content = try allocator.alloc(u8, length);
    var i: usize = 0;
    while (i < length) : (i += 1) {
        const shift: u6 = @intCast((length - 1 - i) * 8);
        content[i] = @truncate(@as(u64, @bitCast(value)) >> shift);
    }
    return content;
}

pub fn integer(allocator: Allocator, value: i64) ![]u8 {
    const c = try intContent(allocator, value);
    defer allocator.free(c);
    return tlv(allocator, tag.integer, c);
}

pub fn enumerated(allocator: Allocator, value: i64) ![]u8 {
    const c = try intContent(allocator, value);
    defer allocator.free(c);
    return tlv(allocator, tag.enumerated, c);
}

pub fn boolean(allocator: Allocator, b: bool) ![]u8 {
    return tlv(allocator, tag.boolean, &[_]u8{if (b) 0xFF else 0x00});
}

pub fn octetString(allocator: Allocator, s: []const u8) ![]u8 {
    return tlv(allocator, tag.octet_string, s);
}

pub fn sequence(allocator: Allocator, elements: []const []const u8) ![]u8 {
    return constructed(allocator, tag.sequence, elements);
}

pub fn set(allocator: Allocator, elements: []const []const u8) ![]u8 {
    return constructed(allocator, tag.set, elements);
}

/// Concatenate pre-encoded TLVs and wrap them in `tag_byte`.
pub fn constructed(allocator: Allocator, tag_byte: u8, elements: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (elements) |e| total += e.len;
    const content = try allocator.alloc(u8, total);
    defer allocator.free(content);
    var off: usize = 0;
    for (elements) |e| {
        @memcpy(content[off .. off + e.len], e);
        off += e.len;
    }
    return tlv(allocator, tag_byte, content);
}

/// Context-class constructed tag [n] (0xA0 | n).
pub fn context(allocator: Allocator, tag_number: u8, elements: []const []const u8) ![]u8 {
    return constructed(allocator, 0xA0 | tag_number, elements);
}

/// Context-class primitive tag [n] (0x80 | n) wrapping raw bytes.
pub fn contextPrimitive(allocator: Allocator, tag_number: u8, content: []const u8) ![]u8 {
    return tlv(allocator, 0x80 | tag_number, content);
}

/// Application-class constructed tag [APPLICATION n] (0x60 | n).
pub fn application(allocator: Allocator, tag_number: u8, elements: []const []const u8) ![]u8 {
    return constructed(allocator, 0x60 | tag_number, elements);
}

// ---- Decoding ----

pub const Class = enum(u2) { universal = 0, application = 1, context = 2, private = 3 };

pub const Element = struct {
    class: Class,
    constructed: bool,
    tag_number: u8,
    content: []const u8,
    raw: []const u8,

    pub fn integer(self: Element) Error!i64 {
        if (self.content.len == 0 or self.content.len > 8) return Error.InvalidInteger;
        var result: i64 = 0;
        if (self.content[0] & 0x80 != 0) result = -1;
        for (self.content) |b| result = (result << 8) | b;
        return result;
    }
    pub fn bytes(self: Element) []const u8 {
        return self.content;
    }
    pub fn iterator(self: Element) Iterator {
        return .{ .rest = self.content };
    }
};

pub const Iterator = struct {
    rest: []const u8,
    pub fn next(self: *Iterator) Error!?Element {
        if (self.rest.len == 0) return null;
        const r = try read(self.rest);
        self.rest = r.rest;
        return r.elem;
    }
};

/// Read one TLV from the front of `buf`. BORROW: result references `buf`.
pub fn read(buf: []const u8) Error!struct { elem: Element, rest: []const u8 } {
    if (buf.len < 2) return Error.Truncated;
    const id = buf[0];
    const tag_number = id & 0x1F;
    if (tag_number == 0x1F) return Error.HighTagNumberForm;
    var idx: usize = 1;
    const first = buf[idx];
    idx += 1;
    var length: usize = 0;
    if (first < 0x80) {
        length = first;
    } else {
        const count = first & 0x7F;
        if (count == 0 or count > 8) return Error.InvalidLength;
        if (buf.len < idx + count) return Error.Truncated;
        var i: usize = 0;
        while (i < count) : (i += 1) length = (length << 8) | buf[idx + i];
        idx += count;
    }
    // Compare by SUBTRACTION, never `idx + length`: `length` is up to eight
    // attacker-supplied bytes (any u64), so adding first overflows — a panic in
    // a safety-checked build and, in ReleaseFast where the checks are gone, a
    // silent wrap that lets the check pass and then slices with an end below its
    // start. `idx <= buf.len` is already established above, so this cannot
    // underflow.
    if (length > buf.len - idx) return Error.Truncated;
    return .{
        .elem = .{
            .class = @enumFromInt(@as(u2, @intCast(id >> 6))),
            .constructed = (id & 0x20) != 0,
            .tag_number = tag_number,
            .content = buf[idx .. idx + length],
            .raw = buf[0 .. idx + length],
        },
        .rest = buf[idx + length ..],
    };
}

/// How many bytes the TLV at the front of `buf` occupies (tag+len+content), or
/// null if the header/content isn't fully present yet (used for TCP framing).
pub fn messageLength(buf: []const u8) ?usize {
    if (buf.len < 2) return null;
    const first = buf[1];
    if (first < 0x80) return 2 + first;
    const count: usize = first & 0x7F;
    if (count == 0 or count > 8) return null;
    if (buf.len < 2 + count) return null;
    var length: usize = 0;
    var i: usize = 0;
    while (i < count) : (i += 1) length = (length << 8) | buf[2 + i];
    // Same overflow hazard as `read`: a crafted length would wrap `2 + count +
    // length` to a small value and mis-frame the stream. Treat it as "no
    // complete message" instead.
    if (length > std.math.maxInt(usize) - 2 - count) return null;
    return 2 + count + length;
}

const testing = std.testing;

test "encode integer/enumerated/sequence round trip" {
    const a = testing.allocator;
    const i = try integer(a, 3);
    defer a.free(i);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x01, 0x03 }, i);

    const e = try enumerated(a, 0);
    defer a.free(e);
    try testing.expectEqualSlices(u8, &.{ 0x0A, 0x01, 0x00 }, e);

    const os = try octetString(a, "ab");
    defer a.free(os);
    const seq = try sequence(a, &.{ i, os });
    defer a.free(seq);
    const r = try read(seq);
    var it = r.elem.iterator();
    try testing.expectEqual(@as(i64, 3), try (try it.next()).?.integer());
    try testing.expectEqualStrings("ab", (try it.next()).?.bytes());
}

test "application/context tags" {
    const a = testing.allocator;
    const inner = try integer(a, 3);
    defer a.free(inner);
    const app0 = try application(a, 0, &.{inner}); // BindRequest tag
    defer a.free(app0);
    try testing.expectEqual(@as(u8, 0x60), app0[0]);
    const r = try read(app0);
    try testing.expectEqual(Class.application, r.elem.class);
    try testing.expectEqual(@as(u8, 0), r.elem.tag_number);

    const cp = try contextPrimitive(a, 0, "pw"); // simple auth [0]
    defer a.free(cp);
    try testing.expectEqual(@as(u8, 0x80), cp[0]);
}

test "messageLength framing" {
    const a = testing.allocator;
    const inner = try integer(a, 1);
    defer a.free(inner);
    const seq = try sequence(a, &.{inner});
    defer a.free(seq);
    try testing.expectEqual(seq.len, messageLength(seq).?);
    // Partial buffer => null.
    try testing.expectEqual(@as(?usize, null), messageLength(seq[0..1]));
}

// SECURITY REGRESSION TEST — same class as krb5/asn1/der.zig. LDAP responses
// come from whatever host --dc / --ldap-server names, which on an engagement is
// not a host the operator controls.
test "read and messageLength reject oversized lengths instead of overflowing" {
    const evil = [_]u8{ 0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try testing.expectError(Error.Truncated, read(&evil));
    // Framing must report "no complete message", not a wrapped small length.
    try testing.expectEqual(@as(?usize, null), messageLength(&evil));

    const short = [_]u8{ 0x30, 0x82, 0xFF, 0xFF, 0x01 };
    try testing.expectError(Error.Truncated, read(&short));

    // Well-formed input is unaffected.
    const ok = [_]u8{ 0x30, 0x02, 0xAA, 0xBB };
    const r = try read(&ok);
    try testing.expectEqual(@as(usize, 2), r.elem.content.len);
    try testing.expectEqual(@as(?usize, 4), messageLength(&ok));
}
