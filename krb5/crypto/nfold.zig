//! The n-fold algorithm from RFC 3961, used to stretch/normalise input to the
//! cipher block size during key derivation. Ported faithfully from gokrb5's
//! rfc3961/nfold.go (which itself mirrors the Apache Directory reference).

const std = @import("std");
const Allocator = std.mem.Allocator;

fn getBit(b: []const u8, p: usize) u1 {
    const byte_idx = p / 8;
    const bit_idx: u3 = @intCast(p % 8);
    return @intCast((b[byte_idx] >> (7 - bit_idx)) & 1);
}

fn setBit(b: []u8, p: usize, v: u1) void {
    const byte_idx = p / 8;
    const bit_idx: u3 = @intCast(p % 8);
    if (v == 1) {
        b[byte_idx] |= (@as(u8, 1) << (7 - bit_idx));
    }
}

/// Rotate `b` right by `step` bits into a freshly allocated buffer.
fn rotateRight(allocator: Allocator, b: []const u8, step: usize) ![]u8 {
    const out = try allocator.alloc(u8, b.len);
    @memset(out, 0);
    const bit_len = b.len * 8;
    var i: usize = 0;
    while (i < bit_len) : (i += 1) {
        const v = getBit(b, i);
        setBit(out, (i + step) % bit_len, v);
    }
    return out;
}

/// One's-complement (end-around carry) addition of two equal-length buffers.
fn onesComplementAddition(allocator: Allocator, n1: []const u8, n2: []const u8) ![]u8 {
    const num_bits = n1.len * 8;
    var out = try allocator.alloc(u8, n1.len);
    @memset(out, 0);
    var carry: u32 = 0;
    var i: isize = @as(isize, @intCast(num_bits)) - 1;
    while (i > -1) : (i -= 1) {
        const idx: usize = @intCast(i);
        const s = @as(u32, getBit(n1, idx)) + @as(u32, getBit(n2, idx)) + carry;
        switch (s) {
            0, 1 => {
                setBit(out, idx, @intCast(s));
                carry = 0;
            },
            2 => carry = 1,
            3 => {
                setBit(out, idx, 1);
                carry = 1;
            },
            else => unreachable, // UNREACHABLE: s = a+b+carry with a,b,carry in {0,1}
        }
    }
    if (carry == 1) {
        const carry_arr = try allocator.alloc(u8, n1.len);
        defer allocator.free(carry_arr);
        @memset(carry_arr, 0);
        carry_arr[carry_arr.len - 1] = 1;
        const added = try onesComplementAddition(allocator, out, carry_arr);
        allocator.free(out);
        out = added;
    }
    return out;
}

fn gcd(x_in: usize, y_in: usize) usize {
    var x = x_in;
    var y = y_in;
    while (y != 0) {
        const t = y;
        y = x % y;
        x = t;
    }
    return x;
}

fn lcm(x: usize, y: usize) usize {
    return (x * y) / gcd(x, y);
}

/// Expand `m` to `n` bits using the RFC 3961 n-fold operation.
/// `n` must be a multiple of 8. OWNERSHIP: caller frees the returned slice.
pub fn nfold(allocator: Allocator, m: []const u8, n: usize) ![]u8 {
    const k = m.len * 8;
    const l = lcm(n, k);
    const replicate = l / k;

    var sum_bytes: std.ArrayList(u8) = .empty;
    defer sum_bytes.deinit(allocator);
    var i: usize = 0;
    while (i < replicate) : (i += 1) {
        const rotated = try rotateRight(allocator, m, 13 * i);
        defer allocator.free(rotated);
        try sum_bytes.appendSlice(allocator, rotated);
    }

    var result = try allocator.alloc(u8, n / 8);
    errdefer allocator.free(result);
    @memset(result, 0);
    const sum_len = n / 8;
    var blk: usize = 0;
    while (blk < l / n) : (blk += 1) {
        const chunk = sum_bytes.items[blk * sum_len ..][0..sum_len];
        const added = try onesComplementAddition(allocator, result, chunk);
        allocator.free(result);
        result = added;
    }
    return result;
}

const testing = std.testing;

fn expectNfold(input: []const u8, n: usize, hex: []const u8) !void {
    const out = try nfold(testing.allocator, input, n);
    defer testing.allocator.free(out);
    var buf: [128]u8 = undefined;
    const got = std.fmt.bufPrint(&buf, "{x}", .{out}) catch unreachable;
    try testing.expectEqualStrings(hex, got);
}

test "n-fold RFC 3961 test vectors" {
    try expectNfold("012345", 64, "be072631276b1955");
    try expectNfold("password", 56, "78a07b6caf85fa");
    try expectNfold("Rough Consensus, and Running Code", 64, "bb6ed30870b7f0e0");
    try expectNfold("password", 168, "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e");
    try expectNfold(
        "MASSACHVSETTS INSTITVTE OF TECHNOLOGY",
        192,
        "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b",
    );
    try expectNfold("Q", 168, "518a54a215a8452a518a54a215a8452a518a54a215");
    try expectNfold("ba", 168, "fb25d531ae8974499f52fd92ea9857c4ba24cf297e");
}
