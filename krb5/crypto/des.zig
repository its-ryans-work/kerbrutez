//! DES and 3DES (EDE) in CBC mode. Required for the des3-cbc-sha1-kd etype
//! (etype 16). Not provided by Zig's std.crypto. Implemented from FIPS 46-3
//! with the standard permutation/substitution tables; 3DES matches Go's
//! crypto/des TripleDESCipher (EDE3).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const block_size = 8;

/// A CBC input whose length is not a whole number of blocks. This is a real,
/// reachable input error — NOT a programmer invariant — because the ciphertext
/// comes from the KDC (see tripleDesCbcDecrypt).
pub const Error = error{NotBlockAligned};

// ---- Standard DES tables (1-based bit positions, counted from the MSB) ----

const ip = [64]u8{
    58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
};

const fp = [64]u8{
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9,  49, 17, 57, 25,
};

const e_table = [48]u8{
    32, 1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
    8,  9,  10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
};

const p_table = [32]u8{
    16, 7,  20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
    2,  8,  24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25,
};

const pc1 = [56]u8{
    57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
    10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
    14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4,
};

const pc2 = [48]u8{
    14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10,
    23, 19, 12, 4,  26, 8,  16, 7,  27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
};

const shifts = [16]u3{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

const sboxes = [8][64]u8{
    .{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    .{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    .{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    .{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    .{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    .{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    .{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    .{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
};

/// Generic bit permutation. `in` holds `in_bits` significant bits (MSB-first);
/// `table` gives, for each output bit (MSB-first), the 1-based source bit.
fn permute(in: u64, comptime out_bits: usize, table: []const u8, in_bits: usize) u64 {
    var out: u64 = 0;
    for (table, 0..) |src, j| {
        const bit = (in >> @intCast(in_bits - src)) & 1;
        out |= bit << @intCast(out_bits - 1 - j);
    }
    return out;
}

fn rotl28(v: u32, n: u3) u32 {
    const mask: u32 = 0x0FFF_FFFF; // 28 bits
    return ((v << n) | (v >> @intCast(28 - @as(u32, n)))) & mask;
}

/// A DES key schedule: the 16 round subkeys (48 bits each).
const Schedule = struct { subkeys: [16]u64 };

fn keySchedule(key: u64) Schedule {
    const permuted = permute(key, 56, &pc1, 64);
    var c: u32 = @intCast((permuted >> 28) & 0x0FFF_FFFF);
    var d: u32 = @intCast(permuted & 0x0FFF_FFFF);
    var sched: Schedule = .{ .subkeys = undefined };
    for (0..16) |i| {
        c = rotl28(c, shifts[i]);
        d = rotl28(d, shifts[i]);
        const cd = (@as(u64, c) << 28) | @as(u64, d);
        sched.subkeys[i] = permute(cd, 48, &pc2, 56);
    }
    return sched;
}

fn feistel(r: u32, subkey: u64) u32 {
    const expanded = permute(@as(u64, r), 48, &e_table, 32) ^ subkey;
    var out: u32 = 0;
    for (0..8) |i| {
        const six: u8 = @intCast((expanded >> @intCast(42 - i * 6)) & 0x3F);
        const row: u8 = ((six & 0x20) >> 4) | (six & 0x01);
        const col: u8 = (six >> 1) & 0x0F;
        const val = sboxes[i][@as(usize, row) * 16 + col];
        out |= @as(u32, val) << @intCast(28 - i * 4);
    }
    return @intCast(permute(@as(u64, out), 32, &p_table, 32));
}

fn crypt(block: u64, sched: Schedule, decrypt_mode: bool) u64 {
    const permuted = permute(block, 64, &ip, 64);
    var l: u32 = @intCast((permuted >> 32) & 0xFFFF_FFFF);
    var r: u32 = @intCast(permuted & 0xFFFF_FFFF);
    for (0..16) |round| {
        const idx = if (decrypt_mode) 15 - round else round;
        const new_r = l ^ feistel(r, sched.subkeys[idx]);
        l = r;
        r = new_r;
    }
    // Pre-output is R16 ++ L16 (note the swap).
    const preoutput = (@as(u64, r) << 32) | @as(u64, l);
    return permute(preoutput, 64, &fp, 64);
}

/// Single-DES block (8-byte key, parity bits ignored). Mostly used as a 3DES
/// building block; exposed for testing.
pub const Des = struct {
    sched: Schedule,

    pub fn init(key: *const [8]u8) Des {
        return .{ .sched = keySchedule(std.mem.readInt(u64, key, .big)) };
    }

    pub fn encryptBlock(self: Des, in: *const [8]u8, out: *[8]u8) void {
        const c = crypt(std.mem.readInt(u64, in, .big), self.sched, false);
        std.mem.writeInt(u64, out, c, .big);
    }

    pub fn decryptBlock(self: Des, in: *const [8]u8, out: *[8]u8) void {
        const c = crypt(std.mem.readInt(u64, in, .big), self.sched, true);
        std.mem.writeInt(u64, out, c, .big);
    }
};

/// 3DES EDE with a 24-byte key (K1||K2||K3). Matches Go's TripleDESCipher.
pub const TripleDes = struct {
    k1: Des,
    k2: Des,
    k3: Des,

    pub fn init(key: *const [24]u8) TripleDes {
        return .{
            .k1 = Des.init(key[0..8]),
            .k2 = Des.init(key[8..16]),
            .k3 = Des.init(key[16..24]),
        };
    }

    pub fn encryptBlock(self: TripleDes, in: *const [8]u8, out: *[8]u8) void {
        var t: [8]u8 = undefined;
        self.k1.encryptBlock(in, &t);
        self.k2.decryptBlock(&t, out);
        self.k3.encryptBlock(out, &t);
        @memcpy(out, &t);
    }

    pub fn decryptBlock(self: TripleDes, in: *const [8]u8, out: *[8]u8) void {
        var t: [8]u8 = undefined;
        self.k3.decryptBlock(in, &t);
        self.k2.encryptBlock(&t, out);
        self.k1.decryptBlock(out, &t);
        @memcpy(out, &t);
    }
};

/// 3DES-CBC encrypt with a zero IV (RFC 3961 initial cipher state, all zeros).
/// `data` length must be a multiple of 8. OWNERSHIP: caller frees.
pub fn tripleDesCbcEncrypt(allocator: Allocator, key: *const [24]u8, data: []const u8) ![]u8 {
    // Internal invariant (callers zero-pad), but enforced rather than asserted so
    // it cannot silently corrupt memory in a build with asserts compiled out.
    if (data.len % block_size != 0) return Error.NotBlockAligned;
    const tdes = TripleDes.init(key);
    const out = try allocator.alloc(u8, data.len);
    errdefer allocator.free(out);
    var prev = [_]u8{0} ** 8;
    var off: usize = 0;
    while (off < data.len) : (off += 8) {
        var x: [8]u8 = undefined;
        for (0..8) |i| x[i] = data[off + i] ^ prev[i];
        tdes.encryptBlock(&x, out[off..][0..8]);
        prev = out[off..][0..8].*;
    }
    return out;
}

/// 3DES-CBC decrypt with a zero IV. OWNERSHIP: caller frees.
/// SECURITY: `data` is ATTACKER-CONTROLLED — it is the enc-part ciphertext from
/// an AS-REP, and des3 is in the default advertised etype list, so a hostile or
/// spoofed KDC chooses both the etype and the length. A `std.debug.assert` here
/// was wrong twice over: asserts are for programmer invariants, and they are
/// COMPILED OUT in ReleaseFast, which is what ships. Without the check the final
/// loop iteration reads `data[off..][0..8]` past the end AND writes `out[off+i]`
/// past the end of an allocation sized to `data.len`. Must be a returned error.
pub fn tripleDesCbcDecrypt(allocator: Allocator, key: *const [24]u8, data: []const u8) ![]u8 {
    if (data.len % block_size != 0) return Error.NotBlockAligned;
    const tdes = TripleDes.init(key);
    const out = try allocator.alloc(u8, data.len);
    errdefer allocator.free(out);
    var prev = [_]u8{0} ** 8;
    var off: usize = 0;
    while (off < data.len) : (off += 8) {
        var d: [8]u8 = undefined;
        tdes.decryptBlock(data[off..][0..8], &d);
        for (0..8) |i| out[off + i] = d[i] ^ prev[i];
        prev = data[off..][0..8].*;
    }
    return out;
}

const testing = std.testing;

test "DES known-answer vector" {
    // Classic FIPS example.
    const key = [8]u8{ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    const pt = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const want = [8]u8{ 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };
    const d = Des.init(&key);
    var ct: [8]u8 = undefined;
    d.encryptBlock(&pt, &ct);
    try testing.expectEqualSlices(u8, &want, &ct);
    var back: [8]u8 = undefined;
    d.decryptBlock(&ct, &back);
    try testing.expectEqualSlices(u8, &pt, &back);
}

test "3DES EDE round trip and EEE-equivalence when keys equal" {
    // When K1==K2==K3, 3DES EDE reduces to single DES.
    const k8 = [8]u8{ 0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1 };
    var k24: [24]u8 = undefined;
    @memcpy(k24[0..8], &k8);
    @memcpy(k24[8..16], &k8);
    @memcpy(k24[16..24], &k8);
    const pt = [8]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const want = [8]u8{ 0x85, 0xE8, 0x13, 0x54, 0x0F, 0x0A, 0xB4, 0x05 };
    const t = TripleDes.init(&k24);
    var ct: [8]u8 = undefined;
    t.encryptBlock(&pt, &ct);
    try testing.expectEqualSlices(u8, &want, &ct);
    var back: [8]u8 = undefined;
    t.decryptBlock(&ct, &back);
    try testing.expectEqualSlices(u8, &pt, &back);
}

test "3DES-CBC round trip" {
    const a = testing.allocator;
    var key: [24]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i + 1);
    const msg = "ABCDEFGHIJKLMNOP"; // 16 bytes, 2 blocks
    const ct = try tripleDesCbcEncrypt(a, &key, msg);
    defer a.free(ct);
    const pt = try tripleDesCbcDecrypt(a, &key, ct);
    defer a.free(pt);
    try testing.expectEqualStrings(msg, pt);
}

// SECURITY REGRESSION TEST. `data` here is the AS-REP enc-part ciphertext, and
// des3 sits in the default advertised etype list — so a hostile or spoofed KDC
// picks both the etype and the length. This used to be a `std.debug.assert`,
// which is COMPILED OUT in ReleaseFast (what ships): the final loop iteration
// would then read `data[off..][0..8]` past the end and WRITE `out[off+i]` past
// the end of an allocation sized to `data.len`.
test "tripleDesCbc rejects a non-block-aligned ciphertext instead of running off the end" {
    const a = testing.allocator;
    const key = [_]u8{0x01} ** 24;
    // Every non-aligned length in a block must be refused, not asserted away.
    for ([_]usize{ 1, 7, 9, 15, 17, 23 }) |n| {
        const data = try a.alloc(u8, n);
        defer a.free(data);
        @memset(data, 0xAB);
        try testing.expectError(Error.NotBlockAligned, tripleDesCbcDecrypt(a, &key, data));
        try testing.expectError(Error.NotBlockAligned, tripleDesCbcEncrypt(a, &key, data));
    }
    // Aligned input (including empty) still works.
    for ([_]usize{ 0, 8, 16 }) |n| {
        const data = try a.alloc(u8, n);
        defer a.free(data);
        @memset(data, 0xAB);
        const out = try tripleDesCbcDecrypt(a, &key, data);
        defer a.free(out);
        try testing.expectEqual(n, out.len);
    }
}
