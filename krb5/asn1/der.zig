//! Minimal ASN.1 DER encoder/decoder for the subset Kerberos needs.
//!
//! Byte output is designed to match Go's `encoding/asn1` (with the
//! GeneralString support gokrb5 relies on via its gofork), so that messages
//! marshalled here are byte-for-byte identical to gokrb5's.
//!
//! Encoding model: TLVs are built bottom-up as owned `[]u8` slices. Callers
//! generally pass an arena allocator (see messages layer) so the many small
//! intermediate allocations are freed in one shot.
//!
//! OWNERSHIP: every `encode*`/`sequence`/`explicit`/`application` function
//! returns a freshly allocated slice owned by the caller.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Universal tag numbers we use.
pub const tag = struct {
    pub const integer: u8 = 0x02;
    pub const bit_string: u8 = 0x03;
    pub const octet_string: u8 = 0x04;
    pub const generalized_time: u8 = 0x18;
    pub const general_string: u8 = 0x1B;
    pub const sequence: u8 = 0x30; // constructed
};

pub const Error = error{
    Truncated,
    InvalidLength,
    HighTagNumberForm,
    TagMismatch,
    InvalidInteger,
    InvalidTime,
    InvalidBitString,
};

// ===========================================================================
// Length encoding
// ===========================================================================

/// Encode a DER definite length. Short form for <=127, long form otherwise.
/// OWNERSHIP: caller frees.
pub fn encodeLength(allocator: Allocator, l: usize) ![]u8 {
    if (l <= 127) {
        const b = try allocator.alloc(u8, 1);
        b[0] = @intCast(l);
        return b;
    }
    // Long form: minimal big-endian byte count.
    var n: usize = 0;
    var v = l;
    while (v > 0) : (v >>= 8) {
        n += 1;
    }
    const b = try allocator.alloc(u8, n + 1);
    b[0] = 0x80 | @as(u8, @intCast(n));
    var i: usize = 0;
    while (i < n) : (i += 1) {
        // Most significant byte first.
        const shift: u6 = @intCast((n - 1 - i) * 8);
        b[1 + i] = @truncate(l >> shift);
    }
    return b;
}

/// Emit a full TLV: a tag byte, the DER length of `content`, then `content`.
/// OWNERSHIP: caller frees.
pub fn tlv(allocator: Allocator, tag_byte: u8, content: []const u8) ![]u8 {
    const len_bytes = try encodeLength(allocator, content.len);
    defer allocator.free(len_bytes);
    const out = try allocator.alloc(u8, 1 + len_bytes.len + content.len);
    out[0] = tag_byte;
    @memcpy(out[1 .. 1 + len_bytes.len], len_bytes);
    @memcpy(out[1 + len_bytes.len ..], content);
    return out;
}

// ===========================================================================
// Primitive encoders
// ===========================================================================

/// Number of bytes used by Go's minimal two's-complement INTEGER encoding.
fn intLength(value: i64) usize {
    var length: usize = 1;
    var v = value;
    while (v > 127 or v < -128) : (v >>= 8) {
        length += 1;
    }
    return length;
}

/// Encode an INTEGER (signed, minimal big-endian two's complement).
/// OWNERSHIP: caller frees.
pub fn encodeInt(allocator: Allocator, value: i64) ![]u8 {
    const length = intLength(value);
    const content = try allocator.alloc(u8, length);
    var i: usize = 0;
    while (i < length) : (i += 1) {
        const shift: u6 = @intCast((length - 1 - i) * 8);
        content[i] = @truncate(@as(u64, @bitCast(value)) >> shift);
    }
    defer allocator.free(content);
    return tlv(allocator, tag.integer, content);
}

/// Encode an OCTET STRING. OWNERSHIP: caller frees.
pub fn encodeOctetString(allocator: Allocator, bytes: []const u8) ![]u8 {
    return tlv(allocator, tag.octet_string, bytes);
}

/// Encode a GeneralString (raw bytes, tag 27). OWNERSHIP: caller frees.
pub fn encodeGeneralString(allocator: Allocator, s: []const u8) ![]u8 {
    return tlv(allocator, tag.general_string, s);
}

/// Encode a BIT STRING. `bit_length` is the number of significant bits; the
/// leading "unused bits" octet is derived from it. OWNERSHIP: caller frees.
pub fn encodeBitString(allocator: Allocator, bytes: []const u8, bit_length: usize) ![]u8 {
    const total_bits = bytes.len * 8;
    const unused: u8 = if (total_bits >= bit_length) @intCast(total_bits - bit_length) else 0;
    const content = try allocator.alloc(u8, bytes.len + 1);
    defer allocator.free(content);
    content[0] = unused;
    @memcpy(content[1..], bytes);
    return tlv(allocator, tag.bit_string, content);
}

/// Encode a GeneralizedTime from a UTC epoch-seconds value, producing
/// "YYYYMMDDHHMMSSZ" exactly as Go encodes whole-second UTC times.
/// OWNERSHIP: caller frees.
pub fn encodeGeneralizedTime(allocator: Allocator, epoch_secs: i64) ![]u8 {
    var b: [15]u8 = undefined;
    formatGeneralizedTime(&b, epoch_secs);
    return tlv(allocator, tag.generalized_time, &b);
}

/// Write "YYYYMMDDHHMMSSZ" (15 bytes) for a UTC epoch-seconds value.
pub fn formatGeneralizedTime(out: *[15]u8, epoch_secs: i64) void {
    const days = @divFloor(epoch_secs, 86400);
    var rem = @mod(epoch_secs, 86400);
    const hour: u32 = @intCast(@divFloor(rem, 3600));
    rem -= @as(i64, hour) * 3600;
    const minute: u32 = @intCast(@divFloor(rem, 60));
    const second: u32 = @intCast(rem - @as(i64, minute) * 60);
    const ymd = civilFromDays(days);

    writeDigits(out[0..4], @intCast(ymd.year), 4);
    writeDigits(out[4..6], ymd.month, 2);
    writeDigits(out[6..8], ymd.day, 2);
    writeDigits(out[8..10], hour, 2);
    writeDigits(out[10..12], minute, 2);
    writeDigits(out[12..14], second, 2);
    out[14] = 'Z';
}

fn writeDigits(dst: []u8, value: u32, width: usize) void {
    var v = value;
    var i: usize = width;
    while (i > 0) {
        i -= 1;
        dst[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
}

const YMD = struct { year: i64, month: u32, day: u32 };

/// Howard Hinnant's days->civil conversion. `days` is days since 1970-01-01.
fn civilFromDays(days: i64) YMD {
    const z = days + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe = z - era * 146097; // [0, 146096]
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100)); // [0, 365]
    const mp = @divFloor(5 * doy + 2, 153); // [0, 11]
    const d = doy - @divFloor(153 * mp + 2, 5) + 1; // [1, 31]
    const m = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
    return .{ .year = if (m <= 2) y + 1 else y, .month = @intCast(m), .day = @intCast(d) };
}

/// Howard Hinnant's civil->days conversion. Returns days since 1970-01-01.
fn daysFromCivil(year: i64, month: u32, day: u32) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400; // [0, 399]
    const m: i64 = month;
    const doy = @divFloor(153 * (if (month > 2) m - 3 else m + 9) + 2, 5) + @as(i64, day) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ===========================================================================
// Constructed encoders
// ===========================================================================

/// Concatenate already-encoded TLV elements into a SEQUENCE.
/// OWNERSHIP: caller frees.
pub fn sequence(allocator: Allocator, elements: []const []const u8) ![]u8 {
    var total: usize = 0;
    for (elements) |e| total += e.len;
    const content = try allocator.alloc(u8, total);
    defer allocator.free(content);
    var off: usize = 0;
    for (elements) |e| {
        @memcpy(content[off .. off + e.len], e);
        off += e.len;
    }
    return tlv(allocator, tag.sequence, content);
}

/// Wrap an already-encoded inner TLV in an explicit context tag [n].
/// OWNERSHIP: caller frees.
pub fn explicit(allocator: Allocator, tag_number: u8, inner: []const u8) ![]u8 {
    std.debug.assert(tag_number < 31); // COMPTIME-ish: all Kerberos context tags are low-tag form
    // class context (0b10), constructed (0b1) -> 0xA0 | n
    return tlv(allocator, 0xA0 | tag_number, inner);
}

/// Wrap an already-encoded inner TLV in an application tag [APPLICATION n].
/// OWNERSHIP: caller frees.
pub fn application(allocator: Allocator, tag_number: u8, inner: []const u8) ![]u8 {
    std.debug.assert(tag_number < 31);
    // class application (0b01), constructed (0b1) -> 0x60 | n
    return tlv(allocator, 0x60 | tag_number, inner);
}

// ===========================================================================
// Decoding
// ===========================================================================

pub const Class = enum(u2) { universal = 0, application = 1, context = 2, private = 3 };

/// A parsed TLV element. `content` points into the source buffer (BORROW).
pub const Element = struct {
    class: Class,
    constructed: bool,
    tag_number: u8,
    content: []const u8,
    /// Whole element including tag+length+content (points into source).
    raw: []const u8,

    /// Interpret content as a signed INTEGER.
    pub fn integer(self: Element) Error!i64 {
        return decodeInt(self.content);
    }

    /// Interpret content as an INTEGER, returning i32 (with range check).
    pub fn integer32(self: Element) Error!i32 {
        const v = try self.integer();
        if (v > std.math.maxInt(i32) or v < std.math.minInt(i32)) return Error.InvalidInteger;
        return @intCast(v);
    }

    /// OCTET STRING / GeneralString content (BORROW: points into source).
    pub fn bytes(self: Element) []const u8 {
        return self.content;
    }

    /// Interpret content as GeneralizedTime, returning UTC epoch seconds.
    pub fn generalizedTime(self: Element) Error!i64 {
        return decodeGeneralizedTime(self.content);
    }

    /// Interpret content as a BIT STRING. Returns the value bytes (after the
    /// unused-bits octet) and the significant bit length.
    pub fn bitString(self: Element) Error!struct { bytes: []const u8, bit_length: usize } {
        if (self.content.len < 1) return Error.InvalidBitString;
        const unused = self.content[0];
        if (unused > 7) return Error.InvalidBitString;
        const value = self.content[1..];
        return .{ .bytes = value, .bit_length = value.len * 8 - unused };
    }

    /// For a constructed element, the single inner TLV (used to unwrap
    /// explicit context tags and application tags).
    pub fn inner(self: Element) Error!Element {
        return (try read(self.content)).elem;
    }

    /// Iterate the child TLVs of a constructed element (e.g. a SEQUENCE).
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

/// Read one TLV from the front of `buf`. Returns the element and the bytes
/// after it. BORROW: the returned element references `buf`.
pub fn read(buf: []const u8) Error!struct { elem: Element, rest: []const u8 } {
    if (buf.len < 2) return Error.Truncated;
    const id = buf[0];
    const tag_number = id & 0x1F;
    if (tag_number == 0x1F) return Error.HighTagNumberForm;

    var idx: usize = 1;
    const first_len = buf[idx];
    idx += 1;
    var length: usize = 0;
    if (first_len < 0x80) {
        length = first_len;
    } else {
        const count = first_len & 0x7F;
        if (count == 0 or count > 8) return Error.InvalidLength;
        if (buf.len < idx + count) return Error.Truncated;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            length = (length << 8) | buf[idx + i];
        }
        idx += count;
    }
    // Compare by SUBTRACTION, never `idx + length`: `length` is up to eight
    // attacker-supplied bytes (any u64), so adding first overflows — a panic in
    // a safety-checked build and, in ReleaseFast where the checks are gone, a
    // silent wrap that lets the check pass and then slices with an end below its
    // start. `idx <= buf.len` is already established above, so this cannot
    // underflow.
    if (length > buf.len - idx) return Error.Truncated;
    const elem = Element{
        .class = @enumFromInt(@as(u2, @intCast(id >> 6))),
        .constructed = (id & 0x20) != 0,
        .tag_number = tag_number,
        .content = buf[idx .. idx + length],
        .raw = buf[0 .. idx + length],
    };
    return .{ .elem = elem, .rest = buf[idx + length ..] };
}

/// Decode a signed big-endian two's-complement INTEGER.
fn decodeInt(content: []const u8) Error!i64 {
    if (content.len == 0 or content.len > 8) return Error.InvalidInteger;
    var result: i64 = 0;
    // Sign-extend from the top bit of the first byte.
    if (content[0] & 0x80 != 0) result = -1;
    for (content) |b| {
        result = (result << 8) | b;
    }
    return result;
}

/// Decode GeneralizedTime ("YYYYMMDDHHMMSS[.fff]Z") to UTC epoch seconds.
fn decodeGeneralizedTime(content: []const u8) Error!i64 {
    if (content.len < 15) return Error.InvalidTime;
    const year = try parseDigits(content[0..4]);
    const month = try parseDigits(content[4..6]);
    const day = try parseDigits(content[6..8]);
    const hour = try parseDigits(content[8..10]);
    const minute = try parseDigits(content[10..12]);
    const second = try parseDigits(content[12..14]);
    if (month < 1 or month > 12 or day < 1 or day > 31) return Error.InvalidTime;
    const days = daysFromCivil(@intCast(year), @intCast(month), @intCast(day));
    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

fn parseDigits(s: []const u8) Error!u32 {
    var v: u32 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return Error.InvalidTime;
        v = v * 10 + (c - '0');
    }
    return v;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "encodeLength short and long form" {
    const a = testing.allocator;
    {
        const b = try encodeLength(a, 5);
        defer a.free(b);
        try testing.expectEqualSlices(u8, &.{0x05}, b);
    }
    {
        const b = try encodeLength(a, 127);
        defer a.free(b);
        try testing.expectEqualSlices(u8, &.{0x7F}, b);
    }
    {
        const b = try encodeLength(a, 128);
        defer a.free(b);
        try testing.expectEqualSlices(u8, &.{ 0x81, 0x80 }, b);
    }
    {
        const b = try encodeLength(a, 300);
        defer a.free(b);
        try testing.expectEqualSlices(u8, &.{ 0x82, 0x01, 0x2C }, b);
    }
}

test "encodeInt matches DER" {
    const a = testing.allocator;
    const cases = [_]struct { v: i64, want: []const u8 }{
        .{ .v = 0, .want = &.{ 0x02, 0x01, 0x00 } },
        .{ .v = 5, .want = &.{ 0x02, 0x01, 0x05 } },
        .{ .v = 127, .want = &.{ 0x02, 0x01, 0x7F } },
        .{ .v = 128, .want = &.{ 0x02, 0x02, 0x00, 0x80 } },
        .{ .v = 256, .want = &.{ 0x02, 0x02, 0x01, 0x00 } },
        .{ .v = -1, .want = &.{ 0x02, 0x01, 0xFF } },
        .{ .v = -128, .want = &.{ 0x02, 0x01, 0x80 } },
        .{ .v = 2147483647, .want = &.{ 0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF } },
    };
    for (cases) |c| {
        const b = try encodeInt(a, c.v);
        defer a.free(b);
        try testing.expectEqualSlices(u8, c.want, b);
    }
}

test "integer round trip" {
    const a = testing.allocator;
    const vals = [_]i64{ 0, 1, 127, 128, 255, 256, 65535, 2147483647, -1, -128, -256 };
    for (vals) |v| {
        const b = try encodeInt(a, v);
        defer a.free(b);
        const r = try read(b);
        try testing.expectEqual(v, try r.elem.integer());
    }
}

test "GeneralizedTime round trip and known value" {
    const a = testing.allocator;
    // 2024-01-02 03:04:05 UTC
    const secs: i64 = daysFromCivil(2024, 1, 2) * 86400 + 3 * 3600 + 4 * 60 + 5;
    const b = try encodeGeneralizedTime(a, secs);
    defer a.free(b);
    // tag 0x18, len 0x0F, "20240102030405Z"
    try testing.expectEqual(@as(u8, 0x18), b[0]);
    try testing.expectEqual(@as(u8, 0x0F), b[1]);
    try testing.expectEqualSlices(u8, "20240102030405Z", b[2..]);
    const r = try read(b);
    try testing.expectEqual(secs, try r.elem.generalizedTime());
}

test "sequence and explicit wrapping" {
    const a = testing.allocator;
    const ea = try encodeInt(a, 5);
    defer a.free(ea);
    const eb = try encodeInt(a, 10);
    defer a.free(eb);
    const seq = try sequence(a, &.{ ea, eb });
    defer a.free(seq);
    // SEQUENCE { INTEGER 5, INTEGER 10 }
    try testing.expectEqualSlices(u8, &.{ 0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x0A }, seq);

    const ex = try explicit(a, 1, ea);
    defer a.free(ex);
    try testing.expectEqualSlices(u8, &.{ 0xA1, 0x03, 0x02, 0x01, 0x05 }, ex);

    // Decode the sequence back.
    const r = try read(seq);
    var it = r.elem.iterator();
    const e1 = (try it.next()).?;
    try testing.expectEqual(@as(i64, 5), try e1.integer());
    const e2 = (try it.next()).?;
    try testing.expectEqual(@as(i64, 10), try e2.integer());
    try testing.expect((try it.next()) == null);
}

test "bit string encode/decode" {
    const a = testing.allocator;
    const b = try encodeBitString(a, &.{ 0x00, 0x00, 0x00, 0x10 }, 32);
    defer a.free(b);
    // tag 0x03, len 0x05, unused 0x00, then 4 bytes
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10 }, b);
    const r = try read(b);
    const bs = try r.elem.bitString();
    try testing.expectEqual(@as(usize, 32), bs.bit_length);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x10 }, bs.bytes);
}

test "application wrapping" {
    const a = testing.allocator;
    const ea = try encodeInt(a, 5);
    defer a.free(ea);
    const app = try application(a, 30, ea); // KRB-ERROR app tag
    defer a.free(app);
    // 0x60 | 30 = 0x7E
    try testing.expectEqualSlices(u8, &.{ 0x7E, 0x03, 0x02, 0x01, 0x05 }, app);
    const r = try read(app);
    try testing.expectEqual(Class.application, r.elem.class);
    try testing.expectEqual(@as(u8, 30), r.elem.tag_number);
    const inner_el = try r.elem.inner();
    try testing.expectEqual(@as(i64, 5), try inner_el.integer());
}

// SECURITY REGRESSION TEST. The length field is up to 8 attacker-controlled
// bytes, i.e. any u64. The bounds check `buf.len < idx + length` ADDS them
// first, so a length near maxInt(usize) overflows: in a safety-checked build
// that is a panic, and in ReleaseFast — which is what ships — the addition
// wraps to a small number, the check passes, and `buf[idx..idx+length]` slices
// with an end below its start. Every KDC reply is parsed by this function, from
// whatever host --dc points at, so a hostile or spoofed KDC reaches it directly.
test "read rejects an oversized length instead of overflowing the bounds check" {
    // 0x30 SEQUENCE, 0x88 = long form with 8 length bytes, all 0xFF.
    const evil = [_]u8{ 0x30, 0x88, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    try testing.expectError(Error.Truncated, read(&evil));

    // A more realistic near-miss: length just past the end of the buffer.
    const short = [_]u8{ 0x30, 0x82, 0xFF, 0xFF, 0x01, 0x02 };
    try testing.expectError(Error.Truncated, read(&short));

    // And the boundary case must still parse: length exactly fills the buffer.
    const exact = [_]u8{ 0x30, 0x02, 0xAA, 0xBB };
    const r = try read(&exact);
    try testing.expectEqual(@as(usize, 2), r.elem.content.len);
    try testing.expectEqual(@as(usize, 0), r.rest.len);
}
