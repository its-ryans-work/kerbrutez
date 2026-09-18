//! AES in CBC mode with CipherText Stealing (CTS), as used by RFC 3962 and
//! RFC 8009 Kerberos encryption. Ported faithfully from jcmturner/aescts (the
//! implementation gokrb5 uses) so output is byte-for-byte compatible.
//!
//! Supports 128-bit and 256-bit AES keys (the only sizes Kerberos AES etypes
//! use). Kerberos always passes an all-zero IV to these routines.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const block_size = 16;

pub const Error = error{ CiphertextTooShort, UnsupportedKeySize, OutOfMemory };

fn encBlock(key: []const u8, in: *const [16]u8, out: *[16]u8) void {
    switch (key.len) {
        16 => std.crypto.core.aes.Aes128.initEnc(key[0..16].*).encrypt(out, in),
        32 => std.crypto.core.aes.Aes256.initEnc(key[0..32].*).encrypt(out, in),
        else => unreachable, // UNREACHABLE: key length validated by caller (16 or 32)
    }
}

fn decBlock(key: []const u8, in: *const [16]u8, out: *[16]u8) void {
    switch (key.len) {
        16 => std.crypto.core.aes.Aes128.initDec(key[0..16].*).decrypt(out, in),
        32 => std.crypto.core.aes.Aes256.initDec(key[0..32].*).decrypt(out, in),
        else => unreachable, // UNREACHABLE: key length validated by caller (16 or 32)
    }
}

fn xor16(dst: *[16]u8, a: *const [16]u8, b: *const [16]u8) void {
    for (0..16) |i| dst[i] = a[i] ^ b[i];
}

/// CBC-encrypt `buf` (length a multiple of 16) in place starting from `iv`.
/// Returns the last ciphertext block.
fn cbcEncInPlace(key: []const u8, iv: [16]u8, buf: []u8) [16]u8 {
    var prev = iv;
    var off: usize = 0;
    while (off < buf.len) : (off += 16) {
        var x: [16]u8 = undefined;
        xor16(&x, buf[off..][0..16], &prev);
        encBlock(key, &x, buf[off..][0..16]);
        prev = buf[off..][0..16].*;
    }
    return prev;
}

/// CBC-decrypt a single block: AES_dec(ct) XOR iv -> out.
fn cbcDecBlock(key: []const u8, iv: *const [16]u8, ct: *const [16]u8, out: *[16]u8) void {
    var d: [16]u8 = undefined;
    decBlock(key, ct, &d);
    xor16(out, &d, iv);
}

fn keyOk(key: []const u8) bool {
    return key.len == 16 or key.len == 32;
}

/// Encrypt `plaintext` with AES-CBC-CTS. Returns the next IV (last full
/// ciphertext block) and the ciphertext (same length as plaintext, except the
/// single-block case which is padded to 16).
/// OWNERSHIP: caller frees `ciphertext`.
pub fn encrypt(
    allocator: Allocator,
    key: []const u8,
    iv: [16]u8,
    plaintext: []const u8,
) Error!struct { next_iv: [16]u8, ciphertext: []u8 } {
    if (!keyOk(key)) return Error.UnsupportedKeySize;
    const l = plaintext.len;

    if (l <= block_size) {
        var m = try allocator.alloc(u8, block_size);
        @memset(m, 0);
        @memcpy(m[0..l], plaintext);
        const last = cbcEncInPlace(key, iv, m);
        return .{ .next_iv = last, .ciphertext = m };
    }

    if (l % block_size == 0) {
        const m = try allocator.alloc(u8, l);
        @memcpy(m, plaintext);
        const last = cbcEncInPlace(key, iv, m);
        // Swap the last two ciphertext blocks (CTS for exact multiples).
        swapLastTwoBlocksInPlace(m);
        return .{ .next_iv = last, .ciphertext = m };
    }

    // General case: zero-pad to a multiple of the block size, then steal.
    const padded_len = (l / block_size + 1) * block_size;
    const m = try allocator.alloc(u8, padded_len);
    defer allocator.free(m);
    @memset(m, 0);
    @memcpy(m[0..l], plaintext);

    // tailBlocks: rb = all but last two blocks, pb = penultimate, lb = last.
    const lb_start = padded_len - block_size;
    const pb_start = padded_len - 2 * block_size;
    const rb = m[0..pb_start]; // may be empty
    const pb = m[pb_start..lb_start];
    const lb = m[lb_start..];

    const ct = try allocator.alloc(u8, l);
    errdefer allocator.free(ct);

    var running_iv = iv;
    var ct_off: usize = 0;
    if (rb.len > 0) {
        running_iv = cbcEncInPlace(key, iv, rb);
        @memcpy(ct[ct_off .. ct_off + rb.len], rb);
        ct_off += rb.len;
    }
    // Encrypt penultimate block with the running IV.
    var pb_ct: [16]u8 = undefined;
    {
        var x: [16]u8 = undefined;
        xor16(&x, pb[0..16], &running_iv);
        encBlock(key, &x, &pb_ct);
    }
    // Encrypt the (zero-padded) last block with IV = penultimate ciphertext.
    var lb_ct: [16]u8 = undefined;
    {
        var x: [16]u8 = undefined;
        xor16(&x, lb[0..16], &pb_ct);
        encBlock(key, &x, &lb_ct);
    }
    // Output order: rb ++ lb_ct ++ pb_ct, truncated to original length.
    var tail: [2 * block_size]u8 = undefined;
    @memcpy(tail[0..block_size], &lb_ct);
    @memcpy(tail[block_size..], &pb_ct);
    const remaining = l - ct_off;
    @memcpy(ct[ct_off..], tail[0..remaining]);
    return .{ .next_iv = lb_ct, .ciphertext = ct };
}

/// Decrypt AES-CBC-CTS ciphertext. OWNERSHIP: caller frees the result.
pub fn decrypt(
    allocator: Allocator,
    key: []const u8,
    iv: [16]u8,
    ciphertext: []const u8,
) Error![]u8 {
    if (!keyOk(key)) return Error.UnsupportedKeySize;
    if (ciphertext.len < block_size) return Error.CiphertextTooShort;

    if (ciphertext.len % block_size == 0) {
        const ct = try allocator.alloc(u8, ciphertext.len);
        defer allocator.free(ct);
        @memcpy(ct, ciphertext);
        if (ct.len > block_size) swapLastTwoBlocksInPlace(ct);
        const out = try allocator.alloc(u8, ciphertext.len);
        errdefer allocator.free(out);
        var prev = iv;
        var off: usize = 0;
        while (off < ct.len) : (off += 16) {
            cbcDecBlock(key, &prev, ct[off..][0..16], out[off..][0..16]);
            prev = ct[off..][0..16].*;
        }
        return out;
    }

    // CTS path: crb = leading full blocks, cpb = penultimate, clb = short last.
    const clb_len = ciphertext.len % block_size;
    const cpb_start = ciphertext.len - clb_len - block_size;
    const clb_start = ciphertext.len - clb_len;
    const crb = ciphertext[0..cpb_start]; // may be empty
    const cpb = ciphertext[cpb_start..clb_start];
    const clb = ciphertext[clb_start..];

    // We reconstruct two full blocks for the stolen tail, so allocate the
    // padded size and truncate to the original length at the end.
    const out = try allocator.alloc(u8, cpb_start + 2 * block_size);
    errdefer allocator.free(out);
    var out_off: usize = 0;

    var v = iv;
    if (crb.len > 0) {
        var prev = iv;
        var off: usize = 0;
        while (off < crb.len) : (off += 16) {
            cbcDecBlock(key, &prev, crb[off..][0..16], out[out_off + off ..][0..16]);
            prev = crb[off..][0..16].*;
        }
        v = crb[crb.len - block_size ..][0..16].*;
        out_off += crb.len;
    }

    // Decrypt cpb with the original IV; its tail recovers the stolen bytes.
    var pb: [16]u8 = undefined;
    {
        const cpb_blk: [16]u8 = cpb[0..16].*;
        cbcDecBlock(key, &iv, &cpb_blk, &pb);
    }
    const npb = block_size - clb_len;
    // Build full last ciphertext block: clb ++ pb[tail npb bytes].
    var clb_full: [16]u8 = undefined;
    @memcpy(clb_full[0..clb_len], clb);
    @memcpy(clb_full[clb_len..], pb[block_size - npb ..]);

    // Decrypt the (now full) last block in the penultimate position (IV = v).
    var lb: [16]u8 = undefined;
    {
        cbcDecBlock(key, &v, &clb_full, &lb);
    }
    @memcpy(out[out_off..][0..16], &lb);
    out_off += block_size;

    // Decrypt penultimate ciphertext in the last position (IV = clb_full).
    var last: [16]u8 = undefined;
    {
        const cpb_blk: [16]u8 = cpb[0..16].*;
        cbcDecBlock(key, &clb_full, &cpb_blk, &last);
    }
    @memcpy(out[out_off..][0..16], &last);

    // Truncate to ciphertext length.
    return allocator.realloc(out, ciphertext.len);
}

fn swapLastTwoBlocksInPlace(b: []u8) void {
    std.debug.assert(b.len >= 2 * block_size);
    std.debug.assert(b.len % block_size == 0);
    var tmp: [16]u8 = undefined;
    const last = b[b.len - block_size ..][0..16];
    const penult = b[b.len - 2 * block_size ..][0..16];
    @memcpy(&tmp, last);
    @memcpy(last, penult);
    @memcpy(penult, &tmp);
}

const testing = std.testing;

test "AES-128 CBC-CTS RFC 3962 Appendix B vectors" {
    const a = testing.allocator;
    const key = [_]u8{ 0x63, 0x68, 0x69, 0x63, 0x6b, 0x65, 0x6e, 0x20, 0x74, 0x65, 0x72, 0x69, 0x79, 0x61, 0x6b, 0x69 };
    const iv = [_]u8{0} ** 16;
    const Case = struct { plain: []const u8, cipher: []const u8, next_iv: []const u8 };
    const cases = [_]Case{
        .{ .plain = "4920776f756c64206c696b652074686520", .cipher = "c6353568f2bf8cb4d8a580362da7ff7f97", .next_iv = "c6353568f2bf8cb4d8a580362da7ff7f" },
        .{ .plain = "4920776f756c64206c696b65207468652047656e6572616c20476175277320", .cipher = "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5", .next_iv = "fc00783e0efdb2c1d445d4c8eff7ed22" },
        .{ .plain = "4920776f756c64206c696b65207468652047656e6572616c2047617527732043", .cipher = "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584", .next_iv = "39312523a78662d5be7fcbcc98ebf5a8" },
        .{ .plain = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c", .cipher = "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5", .next_iv = "b3fffd940c16a18c1b5549d2f838029e" },
        .{ .plain = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20", .cipher = "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8", .next_iv = "9dad8bbb96c4cdc03bc103e1a194bbd8" },
        .{ .plain = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e", .cipher = "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8", .next_iv = "4807efe836ee89a526730dbc2f7bc840" },
    };
    var plain_buf: [256]u8 = undefined;
    var hex_buf: [512]u8 = undefined;
    for (cases) |c| {
        const plain = try std.fmt.hexToBytes(&plain_buf, c.plain);
        const r = try encrypt(a, &key, iv, plain);
        defer a.free(r.ciphertext);
        const got_ct = try std.fmt.bufPrint(&hex_buf, "{x}", .{r.ciphertext});
        try testing.expectEqualStrings(c.cipher, got_ct);
        var iv_hex: [32]u8 = undefined;
        const got_iv = try std.fmt.bufPrint(&iv_hex, "{x}", .{&r.next_iv});
        try testing.expectEqualStrings(c.next_iv, got_iv);

        // And decrypt round-trips.
        var ct_buf: [256]u8 = undefined;
        const ct = try std.fmt.hexToBytes(&ct_buf, c.cipher);
        const dec = try decrypt(a, &key, iv, ct);
        defer a.free(dec);
        try testing.expectEqualSlices(u8, plain, dec);
    }
}

test "AES-256 CBC-CTS round trip" {
    const a = testing.allocator;
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i);
    const iv = [_]u8{0} ** 16;
    const msg = "This is a longer message that spans multiple AES blocks!!";
    const r = try encrypt(a, &key, iv, msg);
    defer a.free(r.ciphertext);
    const dec = try decrypt(a, &key, iv, r.ciphertext);
    defer a.free(dec);
    try testing.expectEqualStrings(msg, dec);
}
