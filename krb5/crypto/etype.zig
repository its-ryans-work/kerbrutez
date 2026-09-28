//! Kerberos encryption types (RFC 3961/3962/4757/8009).
//!
//! One `EType` enum value per supported etype; the methods dispatch to the
//! correct algorithm family. All routines that produce variable-length output
//! take an allocator and return owned slices (OWNERSHIP: caller frees).
//!
//! Families:
//!   * rc4_hmac (23)                  — RFC 4757
//!   * aes{128,256}_cts_hmac_sha1_96  — RFC 3961 DK + RFC 3962 AES-CTS
//!   * aes{128,256}_cts_hmac_sha{256,384} — RFC 8009 (SP800-108 KDF)
//!   * des3_cbc_sha1_kd (16)          — RFC 3961 DK + 3DES-CBC

const std = @import("std");
const Allocator = std.mem.Allocator;

const iana = @import("../iana/constants.zig");
const md4 = @import("md4.zig");
const rc4 = @import("rc4.zig");
const nfold_mod = @import("nfold.zig");
const cts = @import("cts.zig");
const des = @import("des.zig");

const Md5 = std.crypto.hash.Md5;
const Sha1 = std.crypto.hash.Sha1;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Sha384 = std.crypto.hash.sha2.Sha384;

pub const Error = error{
    UnsupportedEType,
    IncorrectKeySize,
    IntegrityCheckFailed,
    CiphertextTooShort,
    InvalidS2KParams,
} || Allocator.Error || cts.Error || des.Error;

pub const EType = enum(i32) {
    des3_cbc_sha1_kd = 16,
    aes128_cts_hmac_sha1_96 = 17,
    aes256_cts_hmac_sha1_96 = 18,
    aes128_cts_hmac_sha256_128 = 19,
    aes256_cts_hmac_sha384_192 = 20,
    rc4_hmac = 23,

    /// Resolve an etype ID to an EType, or null if unsupported.
    pub fn fromId(etype_id: i32) ?EType {
        return switch (etype_id) {
            16, 17, 18, 19, 20, 23 => @enumFromInt(etype_id),
            else => null,
        };
    }

    pub fn id(self: EType) i32 {
        return @intFromEnum(self);
    }

    /// Encryption key length in bytes.
    pub fn keyByteSize(self: EType) usize {
        return switch (self) {
            .des3_cbc_sha1_kd => 24,
            .aes128_cts_hmac_sha1_96, .aes128_cts_hmac_sha256_128 => 16,
            .aes256_cts_hmac_sha1_96, .aes256_cts_hmac_sha384_192 => 32,
            .rc4_hmac => 16,
        };
    }

    /// Key seed length in bits (input to RandomToKey).
    pub fn keySeedBitLength(self: EType) usize {
        return switch (self) {
            .des3_cbc_sha1_kd => 21 * 8,
            .aes256_cts_hmac_sha384_192 => 192, // note: base/Ke key is 256-bit
            else => self.keyByteSize() * 8,
        };
    }

    /// Integrity (HMAC) output length in bits.
    pub fn hmacBitLength(self: EType) usize {
        return switch (self) {
            .des3_cbc_sha1_kd => 160,
            .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => 96,
            .aes128_cts_hmac_sha256_128 => 128,
            .aes256_cts_hmac_sha384_192 => 192,
            .rc4_hmac => 128,
        };
    }

    /// Confounder size in bytes.
    pub fn confounderByteSize(self: EType) usize {
        return switch (self) {
            .des3_cbc_sha1_kd => 8,
            .rc4_hmac => 8,
            else => 16, // AES block size
        };
    }

    /// Default PBKDF2 iteration count when the KDC advertises no s2kparams.
    pub fn defaultS2KIterations(self: EType) u32 {
        return switch (self) {
            .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => 4096, // RFC 3962
            .aes128_cts_hmac_sha256_128, .aes256_cts_hmac_sha384_192 => 32768, // RFC 8009
            else => 0,
        };
    }
};

// ===========================================================================
// Small helpers
// ===========================================================================

/// Key-derivation usage constant: 4-byte BE usage ++ the family octet.
fn usageConstant(out: *[5]u8, usage: u32, octet: u8) void {
    std.mem.writeInt(u32, out[0..4], usage, .big);
    out[4] = octet;
}

/// HMAC over `data` with `key` for hash H, writing the full digest to `out`.
fn hmac(comptime H: type, key: []const u8, data: []const u8, out: []u8) void {
    const M = std.crypto.auth.hmac.Hmac(H);
    var mac: [M.mac_length]u8 = undefined;
    M.create(&mac, data, key);
    @memcpy(out[0..M.mac_length], &mac);
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ===========================================================================
// RFC 3961 derive-random / derive-key (AES-SHA1 and DES3)
// ===========================================================================

/// Basic (no confounder/HMAC) cipher used inside DR: AES-CTS for AES etypes,
/// 3DES-CBC for des3. `data` length equals one cipher block.
/// OWNERSHIP: caller frees.
fn encryptBasic(allocator: Allocator, et: EType, key: []const u8, data: []const u8) Error![]u8 {
    switch (et) {
        .des3_cbc_sha1_kd => {
            std.debug.assert(key.len == 24);
            return des.tripleDesCbcEncrypt(allocator, key[0..24], data);
        },
        .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => {
            const r = try cts.encrypt(allocator, key, [_]u8{0} ** 16, data);
            return r.ciphertext;
        },
        else => unreachable, // UNREACHABLE: only called for 3961 families
    }
}

fn cipherBlockBits(et: EType) usize {
    return switch (et) {
        .des3_cbc_sha1_kd => 64,
        else => 128,
    };
}

/// DR(key, constant) k-truncated to the key seed length. OWNERSHIP: caller frees.
fn deriveRandom3961(allocator: Allocator, et: EType, key: []const u8, constant: []const u8) Error![]u8 {
    const seed_bytes = et.keySeedBitLength() / 8;
    const nf = try nfold_mod.nfold(allocator, constant, cipherBlockBits(et));
    defer allocator.free(nf);

    const out = try allocator.alloc(u8, seed_bytes);
    errdefer allocator.free(out);

    var block = try encryptBasic(allocator, et, key, nf);
    var filled: usize = 0;
    while (true) {
        const take = @min(block.len, seed_bytes - filled);
        @memcpy(out[filled .. filled + take], block[0..take]);
        filled += take;
        if (filled >= seed_bytes) {
            allocator.free(block);
            break;
        }
        const next = try encryptBasic(allocator, et, key, block);
        allocator.free(block);
        block = next;
    }
    return out;
}

/// DK(key, constant) = RandomToKey(DR(key, constant)). OWNERSHIP: caller frees.
fn deriveKey3961(allocator: Allocator, et: EType, key: []const u8, constant: []const u8) Error![]u8 {
    const dr = try deriveRandom3961(allocator, et, key, constant);
    if (et == .des3_cbc_sha1_kd) {
        defer allocator.free(dr);
        return des3RandomToKey(allocator, dr);
    }
    return dr; // AES RandomToKey is the identity.
}

// ---- DES3 random-to-key (parity stretch) ----

fn calcEvenParity(b: u8) struct { low: u1, byte: u8 } {
    const lowest: u1 = @intCast(b & 1);
    var c: u32 = 0;
    var p: u3 = 1;
    while (true) {
        if (b & (@as(u8, 1) << p) != 0) c += 1;
        if (p == 7) break;
        p += 1;
    }
    var nb = b;
    if (c % 2 == 0) nb |= 1 else nb &= ~@as(u8, 1);
    return .{ .low = lowest, .byte = nb };
}

/// Expand 7 bytes to 8 with DES parity bits (gokrb5 stretch56Bits).
fn stretch56(in7: []const u8, out8: *[8]u8) void {
    var lb: u8 = 0;
    var i: usize = 0;
    while (i < 7) : (i += 1) {
        const r = calcEvenParity(in7[i]);
        out8[i] = r.byte;
        const shift: u3 = @intCast(i + 1);
        if (r.low != 0) {
            lb |= (@as(u8, 1) << shift);
        } else {
            lb &= ~(@as(u8, 1) << shift);
        }
    }
    out8[7] = calcEvenParity(lb).byte;
}

const des_weak_keys = [_][8]u8{
    .{ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
    .{ 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE },
    .{ 0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1 },
    .{ 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E },
    .{ 0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E },
    .{ 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01 },
    .{ 0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1 },
    .{ 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01 },
    .{ 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE },
    .{ 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01 },
    .{ 0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1 },
    .{ 0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E },
    .{ 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE },
    .{ 0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E },
    .{ 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE },
    .{ 0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1 },
};

fn fixWeakKey(b: *[8]u8) void {
    for (des_weak_keys) |w| {
        if (std.mem.eql(u8, b, &w)) {
            b[7] ^= 0xF0;
            return;
        }
    }
}

fn des3RandomToKey(allocator: Allocator, b: []const u8) Error![]u8 {
    std.debug.assert(b.len == 21);
    const out = try allocator.alloc(u8, 24);
    var blk: [8]u8 = undefined;
    inline for (0..3) |i| {
        stretch56(b[i * 7 .. i * 7 + 7], &blk);
        fixWeakKey(&blk);
        @memcpy(out[i * 8 .. i * 8 + 8], &blk);
    }
    return out;
}

// ===========================================================================
// RFC 8009 key derivation (SP800-108 counter-mode KDF with HMAC-SHA-2)
// ===========================================================================

fn kdfHmacSha2(allocator: Allocator, et: EType, key: []const u8, label: []const u8, kl_bits: usize) Error![]u8 {
    // input = 0x00000001 || label || 0x00 || (empty context) || 4-byte BE kl
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(allocator);
    try input.appendSlice(allocator, &[_]u8{ 0, 0, 0, 1 });
    try input.appendSlice(allocator, label);
    try input.append(allocator, 0);
    var kb: [4]u8 = undefined;
    std.mem.writeInt(u32, &kb, @intCast(kl_bits), .big);
    try input.appendSlice(allocator, &kb);

    const out = try allocator.alloc(u8, kl_bits / 8);
    errdefer allocator.free(out);
    switch (et) {
        .aes128_cts_hmac_sha256_128 => {
            var mac: [Sha256.digest_length]u8 = undefined;
            hmac(Sha256, key, input.items, &mac);
            @memcpy(out, mac[0 .. kl_bits / 8]);
        },
        .aes256_cts_hmac_sha384_192 => {
            var mac: [Sha384.digest_length]u8 = undefined;
            hmac(Sha384, key, input.items, &mac);
            @memcpy(out, mac[0 .. kl_bits / 8]);
        },
        else => unreachable, // UNREACHABLE: only RFC 8009 etypes call this
    }
    return out;
}

fn deriveKey8009(allocator: Allocator, et: EType, key: []const u8, label: []const u8) Error![]u8 {
    var kl = et.keySeedBitLength();
    if (et == .aes256_cts_hmac_sha384_192) {
        // Ke (label ends 0xAA) and the StringToKey base key ("kerberos") are
        // 256-bit; Kc/Ki are 192-bit.
        if (std.mem.eql(u8, label, "kerberos")) {
            kl = 256;
        } else if (label.len > 0 and label[label.len - 1] == 0xAA) {
            kl = 256;
        } else {
            kl = 192;
        }
    }
    return kdfHmacSha2(allocator, et, key, label, kl);
}

fn rfc8009SaltPrefix(et: EType) []const u8 {
    return switch (et) {
        .aes128_cts_hmac_sha256_128 => "aes128-cts-hmac-sha256-128",
        .aes256_cts_hmac_sha384_192 => "aes256-cts-hmac-sha384-192",
        else => unreachable, // UNREACHABLE: only RFC 8009 etypes have salt prefixes
    };
}

// ===========================================================================
// Unified DeriveKey dispatch (used for Ke/Kc/Ki across families)
// ===========================================================================

fn deriveKey(allocator: Allocator, et: EType, key: []const u8, constant: []const u8) Error![]u8 {
    return switch (et) {
        .aes128_cts_hmac_sha256_128, .aes256_cts_hmac_sha384_192 => deriveKey8009(allocator, et, key, constant),
        .des3_cbc_sha1_kd, .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => deriveKey3961(allocator, et, key, constant),
        .rc4_hmac => unreachable, // UNREACHABLE: rc4 has no usage-based key derivation
    };
}

// ===========================================================================
// s2kparams
// ===========================================================================

/// Cap on PBKDF2 iterations for one string-to-key. A hostile or spoofed KDC can
/// advertise an s2kparams count up to 0xFFFFFFFF, which would run PBKDF2 for
/// ~an hour and hang the worker thread that received the reply — a cheap remote
/// DoS on a spray. Real AD uses 4096 and RFC 8009 uses 32768; 1,000,000 is far
/// above any legitimate policy while keeping the worst case well under a second.
const max_pbkdf2_iters: u32 = 1_000_000;

/// PBKDF2 iteration count from the KDC-advertised s2kparams. s2kparams is the
/// RAW 4-byte big-endian wire value from PA-ETYPE-INFO2 (NOT hex text) — reading
/// it as an 8-char hex string ignored every real KDC's value (silent
/// false-negative: a valid password fails to decrypt a valid AS-REP) and let a
/// spoofed KDC pass "ffffffff" for 4-billion iterations. Absent/malformed =>
/// `default_iters`; a 0 count (RFC 3962's "2^32") and anything over the cap are
/// clamped to `max_pbkdf2_iters`.
fn s2kIterations(s2kparams: []const u8, default_iters: u32) u32 {
    const raw = if (s2kparams.len == 4) std.mem.readInt(u32, s2kparams[0..4], .big) else default_iters;
    const iters = if (raw == 0) max_pbkdf2_iters else raw;
    return @min(iters, max_pbkdf2_iters);
}

// ===========================================================================
// StringToKey
// ===========================================================================

/// Derive the long-term key from a password and salt.
/// OWNERSHIP: caller frees the returned key.
pub fn stringToKey(allocator: Allocator, et: EType, secret: []const u8, salt: []const u8, s2kparams: []const u8) Error![]u8 {
    switch (et) {
        .rc4_hmac => return ntHash(allocator, secret),
        .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => {
            const iters = s2kIterations(s2kparams, et.defaultS2KIterations());
            const tkey = try allocator.alloc(u8, et.keyByteSize());
            defer allocator.free(tkey);
            std.crypto.pwhash.pbkdf2(tkey, secret, salt, iters, std.crypto.auth.hmac.Hmac(Sha1)) catch return Error.InvalidS2KParams;
            return deriveKey3961(allocator, et, tkey, "kerberos");
        },
        .aes128_cts_hmac_sha256_128, .aes256_cts_hmac_sha384_192 => {
            const iters = s2kIterations(s2kparams, et.defaultS2KIterations());
            // saltp = ename || 0x00 || salt
            var saltp: std.ArrayList(u8) = .empty;
            defer saltp.deinit(allocator);
            try saltp.appendSlice(allocator, rfc8009SaltPrefix(et));
            try saltp.append(allocator, 0);
            try saltp.appendSlice(allocator, salt);
            const kl: usize = if (et == .aes256_cts_hmac_sha384_192) 32 else et.keyByteSize();
            const tkey = try allocator.alloc(u8, kl);
            defer allocator.free(tkey);
            switch (et) {
                .aes128_cts_hmac_sha256_128 => std.crypto.pwhash.pbkdf2(tkey, secret, saltp.items, iters, std.crypto.auth.hmac.Hmac(Sha256)) catch return Error.InvalidS2KParams,
                .aes256_cts_hmac_sha384_192 => std.crypto.pwhash.pbkdf2(tkey, secret, saltp.items, iters, std.crypto.auth.hmac.Hmac(Sha384)) catch return Error.InvalidS2KParams,
                else => unreachable,
            }
            return deriveKey8009(allocator, et, tkey, "kerberos");
        },
        .des3_cbc_sha1_kd => {
            // tkey = DES3RandomToKey(nfold(secret ++ salt, 168)); DK(tkey, "kerberos")
            var s: std.ArrayList(u8) = .empty;
            defer s.deinit(allocator);
            try s.appendSlice(allocator, secret);
            try s.appendSlice(allocator, salt);
            const nf = try nfold_mod.nfold(allocator, s.items, et.keySeedBitLength());
            defer allocator.free(nf);
            const tkey = try des3RandomToKey(allocator, nf);
            defer allocator.free(tkey);
            return deriveKey3961(allocator, et, tkey, "kerberos");
        },
    }
}

/// NT hash: MD4 of the UTF-16LE encoding of the password.
/// OWNERSHIP: caller frees.
fn ntHash(allocator: Allocator, secret: []const u8) Error![]u8 {
    var utf16: std.ArrayList(u8) = .empty;
    defer utf16.deinit(allocator);
    const view = std.unicode.Utf8View.init(secret) catch {
        // Fall back to treating each byte as a code point (gokrb5 iterates runes).
        for (secret) |c| {
            try utf16.append(allocator, c);
            try utf16.append(allocator, 0);
        }
        const out = try allocator.alloc(u8, md4.digest_length);
        md4.Md4.hash(utf16.items, out[0..md4.digest_length]);
        return out;
    };
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        var le: [2]u8 = undefined;
        std.mem.writeInt(u16, &le, @truncate(cp), .little);
        try utf16.appendSlice(allocator, &le);
    }
    const out = try allocator.alloc(u8, md4.digest_length);
    md4.Md4.hash(utf16.items, out[0..md4.digest_length]);
    return out;
}

// ===========================================================================
// Encrypt / Decrypt message
// ===========================================================================

/// Encrypt a message with a caller-supplied confounder (deterministic; used by
/// tests and by `encryptMessage`). OWNERSHIP: caller frees the result.
pub fn encryptMessageWithConfounder(
    allocator: Allocator,
    et: EType,
    key: []const u8,
    message: []const u8,
    usage: u32,
    confounder: []const u8,
) Error![]u8 {
    if (key.len != et.keyByteSize()) return Error.IncorrectKeySize;
    switch (et) {
        .rc4_hmac => return rc4Encrypt(allocator, key, message, usage, confounder),
        .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96, .des3_cbc_sha1_kd => return rfc3961Encrypt(allocator, et, key, message, usage, confounder),
        .aes128_cts_hmac_sha256_128, .aes256_cts_hmac_sha384_192 => return rfc8009Encrypt(allocator, et, key, message, usage, confounder),
    }
}

/// Decrypt and integrity-check an encrypted message; strips the confounder.
/// OWNERSHIP: caller frees the returned plaintext.
pub fn decryptMessage(allocator: Allocator, et: EType, key: []const u8, ciphertext: []const u8, usage: u32) Error![]u8 {
    if (key.len != et.keyByteSize()) return Error.IncorrectKeySize;
    switch (et) {
        .rc4_hmac => return rc4Decrypt(allocator, key, ciphertext, usage),
        .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96, .des3_cbc_sha1_kd => return rfc3961Decrypt(allocator, et, key, ciphertext, usage),
        .aes128_cts_hmac_sha256_128, .aes256_cts_hmac_sha384_192 => return rfc8009Decrypt(allocator, et, key, ciphertext, usage),
    }
}

// ---- RFC 3961 (AES-SHA1 and DES3): HMAC over plaintext ----

fn rfc3961Encrypt(allocator: Allocator, et: EType, key: []const u8, message: []const u8, usage: u32, confounder: []const u8) Error![]u8 {
    // plain = confounder || message (zero-padded to block for DES3)
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(allocator);
    try plain.appendSlice(allocator, confounder);
    try plain.appendSlice(allocator, message);
    if (et == .des3_cbc_sha1_kd) {
        const rem = plain.items.len % 8;
        if (rem != 0) try plain.appendNTimes(allocator, 0, 8 - rem);
    }

    var ke_c: [5]u8 = undefined;
    usageConstant(&ke_c, usage, 0xAA);
    const ke = try deriveKey(allocator, et, key, &ke_c);
    defer allocator.free(ke);

    const ct = try cipherEncrypt(allocator, et, ke, plain.items);
    defer allocator.free(ct);

    const ih = try integrityHash(allocator, et, key, plain.items, usage);
    defer allocator.free(ih);

    const out = try allocator.alloc(u8, ct.len + ih.len);
    @memcpy(out[0..ct.len], ct);
    @memcpy(out[ct.len..], ih);
    return out;
}

fn rfc3961Decrypt(allocator: Allocator, et: EType, key: []const u8, ciphertext: []const u8, usage: u32) Error![]u8 {
    const hl = et.hmacBitLength() / 8;
    if (ciphertext.len < hl) return Error.CiphertextTooShort;
    const ct = ciphertext[0 .. ciphertext.len - hl];
    const mac = ciphertext[ciphertext.len - hl ..];

    var ke_c: [5]u8 = undefined;
    usageConstant(&ke_c, usage, 0xAA);
    const ke = try deriveKey(allocator, et, key, &ke_c);
    defer allocator.free(ke);

    const plain = try cipherDecrypt(allocator, et, ke, ct);
    defer allocator.free(plain);

    const ih = try integrityHash(allocator, et, key, plain, usage);
    defer allocator.free(ih);
    if (!constantTimeEqual(ih, mac)) return Error.IntegrityCheckFailed;

    const cz = et.confounderByteSize();
    return allocator.dupe(u8, plain[cz..]);
}

/// HMAC over plaintext keyed by Ki = DK(key, usage||0x55), truncated.
fn integrityHash(allocator: Allocator, et: EType, key: []const u8, plain: []const u8, usage: u32) Error![]u8 {
    var ki_c: [5]u8 = undefined;
    usageConstant(&ki_c, usage, 0x55);
    const ki = try deriveKey(allocator, et, key, &ki_c);
    defer allocator.free(ki);
    const hl = et.hmacBitLength() / 8;
    const out = try allocator.alloc(u8, hl);
    errdefer allocator.free(out);
    var full: [Sha1.digest_length]u8 = undefined;
    hmac(Sha1, ki, plain, &full); // AES-SHA1 and DES3 both use SHA-1 here
    @memcpy(out, full[0..hl]);
    return out;
}

// ---- RFC 8009: HMAC over iv||ciphertext ----

fn rfc8009Encrypt(allocator: Allocator, et: EType, key: []const u8, message: []const u8, usage: u32, confounder: []const u8) Error![]u8 {
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(allocator);
    try plain.appendSlice(allocator, confounder);
    try plain.appendSlice(allocator, message);

    var ke_c: [5]u8 = undefined;
    usageConstant(&ke_c, usage, 0xAA);
    const ke = try deriveKey(allocator, et, key, &ke_c);
    defer allocator.free(ke);

    const r = try cts.encrypt(allocator, ke, [_]u8{0} ** 16, plain.items);
    defer allocator.free(r.ciphertext);

    const ih = try rfc8009IntegrityHash(allocator, et, key, r.ciphertext, usage);
    defer allocator.free(ih);

    const out = try allocator.alloc(u8, r.ciphertext.len + ih.len);
    @memcpy(out[0..r.ciphertext.len], r.ciphertext);
    @memcpy(out[r.ciphertext.len..], ih);
    return out;
}

fn rfc8009Decrypt(allocator: Allocator, et: EType, key: []const u8, ciphertext: []const u8, usage: u32) Error![]u8 {
    const hl = et.hmacBitLength() / 8;
    if (ciphertext.len < hl) return Error.CiphertextTooShort;
    const ct = ciphertext[0 .. ciphertext.len - hl];
    const mac = ciphertext[ciphertext.len - hl ..];

    const ih = try rfc8009IntegrityHash(allocator, et, key, ct, usage);
    defer allocator.free(ih);
    if (!constantTimeEqual(ih, mac)) return Error.IntegrityCheckFailed;

    var ke_c: [5]u8 = undefined;
    usageConstant(&ke_c, usage, 0xAA);
    const ke = try deriveKey(allocator, et, key, &ke_c);
    defer allocator.free(ke);

    const plain = try cts.decrypt(allocator, ke, [_]u8{0} ** 16, ct);
    defer allocator.free(plain);
    const cz = et.confounderByteSize();
    return allocator.dupe(u8, plain[cz..]);
}

/// HMAC over (zero-IV || ciphertext) keyed by Ki, truncated.
fn rfc8009IntegrityHash(allocator: Allocator, et: EType, key: []const u8, ct: []const u8, usage: u32) Error![]u8 {
    var ki_c: [5]u8 = undefined;
    usageConstant(&ki_c, usage, 0x55);
    const ki = try deriveKey(allocator, et, key, &ki_c);
    defer allocator.free(ki);

    var ib: std.ArrayList(u8) = .empty;
    defer ib.deinit(allocator);
    try ib.appendNTimes(allocator, 0, et.confounderByteSize()); // IV (zeros)
    try ib.appendSlice(allocator, ct);

    const hl = et.hmacBitLength() / 8;
    const out = try allocator.alloc(u8, hl);
    errdefer allocator.free(out);
    switch (et) {
        .aes128_cts_hmac_sha256_128 => {
            var full: [Sha256.digest_length]u8 = undefined;
            hmac(Sha256, ki, ib.items, &full);
            @memcpy(out, full[0..hl]);
        },
        .aes256_cts_hmac_sha384_192 => {
            var full: [Sha384.digest_length]u8 = undefined;
            hmac(Sha384, ki, ib.items, &full);
            @memcpy(out, full[0..hl]);
        },
        else => unreachable, // UNREACHABLE: only RFC 8009 etypes
    }
    return out;
}

// ---- bare cipher used by RFC 3961 encrypt/decrypt ----

fn cipherEncrypt(allocator: Allocator, et: EType, key: []const u8, plain: []const u8) Error![]u8 {
    return switch (et) {
        .des3_cbc_sha1_kd => des.tripleDesCbcEncrypt(allocator, key[0..24], plain),
        .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => blk: {
            const r = try cts.encrypt(allocator, key, [_]u8{0} ** 16, plain);
            break :blk r.ciphertext;
        },
        else => unreachable, // UNREACHABLE: only 3961 families
    };
}

fn cipherDecrypt(allocator: Allocator, et: EType, key: []const u8, ct: []const u8) Error![]u8 {
    return switch (et) {
        .des3_cbc_sha1_kd => des.tripleDesCbcDecrypt(allocator, key[0..24], ct),
        .aes128_cts_hmac_sha1_96, .aes256_cts_hmac_sha1_96 => cts.decrypt(allocator, key, [_]u8{0} ** 16, ct),
        else => unreachable, // UNREACHABLE: only 3961 families
    };
}

// ---- RC4-HMAC (RFC 4757) ----

fn usageToMsMsgType(usage: u32) [4]u8 {
    var u = usage;
    switch (usage) {
        3, 9 => u = 8,
        23 => u = 13,
        else => {},
    }
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, u, .little);
    return b;
}

fn rc4Encrypt(allocator: Allocator, key: []const u8, message: []const u8, usage: u32, confounder: []const u8) Error![]u8 {
    const t = usageToMsMsgType(usage);
    var k2: [Md5.digest_length]u8 = undefined;
    hmac(Md5, key, &t, &k2);

    const toenc = try allocator.alloc(u8, confounder.len + message.len);
    defer allocator.free(toenc);
    @memcpy(toenc[0..confounder.len], confounder);
    @memcpy(toenc[confounder.len..], message);

    var chksum: [Md5.digest_length]u8 = undefined;
    hmac(Md5, &k2, toenc, &chksum);
    var k3: [Md5.digest_length]u8 = undefined;
    hmac(Md5, &k2, &chksum, &k3);

    const out = try allocator.alloc(u8, chksum.len + toenc.len);
    errdefer allocator.free(out);
    @memcpy(out[0..chksum.len], &chksum);
    @memcpy(out[chksum.len..], toenc);
    var cipher = rc4.Rc4.init(&k3);
    cipher.xor(out[chksum.len..]);
    return out;
}

fn rc4Decrypt(allocator: Allocator, key: []const u8, ciphertext: []const u8, usage: u32) Error![]u8 {
    if (ciphertext.len < Md5.digest_length + 8) return Error.CiphertextTooShort;
    const checksum = ciphertext[0..Md5.digest_length];
    const ct = ciphertext[Md5.digest_length..];
    const t = usageToMsMsgType(usage);
    var k2: [Md5.digest_length]u8 = undefined;
    hmac(Md5, key, &t, &k2);
    var k3: [Md5.digest_length]u8 = undefined;
    hmac(Md5, &k2, checksum, &k3);

    const pt = try allocator.alloc(u8, ct.len);
    defer allocator.free(pt);
    @memcpy(pt, ct);
    var cipher = rc4.Rc4.init(&k3);
    cipher.xor(pt);

    var verify: [Md5.digest_length]u8 = undefined;
    hmac(Md5, &k2, pt, &verify);
    if (!constantTimeEqual(&verify, checksum)) return Error.IntegrityCheckFailed;
    return allocator.dupe(u8, pt[8..]); // strip 8-byte confounder
}

// ===========================================================================
// Checksums (Kc-keyed; used for AP-REQ authenticators / TGS — included for
// library completeness).
// ===========================================================================

/// Keyed checksum over `data`. OWNERSHIP: caller frees.
pub fn getChecksumHash(allocator: Allocator, et: EType, key: []const u8, data: []const u8, usage: u32) Error![]u8 {
    switch (et) {
        .rc4_hmac => return rc4Checksum(allocator, key, data, usage),
        else => {
            var kc_c: [5]u8 = undefined;
            usageConstant(&kc_c, usage, 0x99);
            const kc = try deriveKey(allocator, et, key, &kc_c);
            defer allocator.free(kc);
            const hl = et.hmacBitLength() / 8;
            const out = try allocator.alloc(u8, hl);
            errdefer allocator.free(out);
            switch (et) {
                .aes128_cts_hmac_sha256_128 => {
                    var full: [Sha256.digest_length]u8 = undefined;
                    hmac(Sha256, kc, data, &full);
                    @memcpy(out, full[0..hl]);
                },
                .aes256_cts_hmac_sha384_192 => {
                    var full: [Sha384.digest_length]u8 = undefined;
                    hmac(Sha384, kc, data, &full);
                    @memcpy(out, full[0..hl]);
                },
                else => { // AES-SHA1, DES3
                    var full: [Sha1.digest_length]u8 = undefined;
                    hmac(Sha1, kc, data, &full);
                    @memcpy(out, full[0..hl]);
                },
            }
            return out;
        },
    }
}

fn rc4Checksum(allocator: Allocator, key: []const u8, data: []const u8, usage: u32) Error![]u8 {
    // Ksign = HMAC-MD5(key, "signaturekey\0")
    const sign_const = "signaturekey" ++ [_]u8{0};
    var ksign: [Md5.digest_length]u8 = undefined;
    hmac(Md5, key, sign_const, &ksign);
    // tmp = MD5(UsageToMSMsgType(usage) || data)
    const t = usageToMsMsgType(usage);
    var md5_in: std.ArrayList(u8) = .empty;
    defer md5_in.deinit(allocator);
    try md5_in.appendSlice(allocator, &t);
    try md5_in.appendSlice(allocator, data);
    var tmp: [Md5.digest_length]u8 = undefined;
    Md5.hash(md5_in.items, &tmp, .{});
    // HMAC-MD5(Ksign, tmp)
    const out = try allocator.alloc(u8, Md5.digest_length);
    errdefer allocator.free(out);
    hmac(Md5, &ksign, &tmp, out[0..Md5.digest_length]);
    return out;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

fn expectKeyHexParams(et: EType, secret: []const u8, salt: []const u8, s2kparams: []const u8, want_hex: []const u8) !void {
    const a = testing.allocator;
    const key = try stringToKey(a, et, secret, salt, s2kparams);
    defer a.free(key);
    var buf: [128]u8 = undefined;
    const got = try std.fmt.bufPrint(&buf, "{x}", .{key});
    try testing.expectEqualStrings(want_hex, got);
}

// The literal `"password"` / `"ATHENA.MIT.EDUraeburn"` below are standard
// string-to-key known-answer test vectors (the NT-hash test value and RFC 3962
// Appendix B), NOT real credentials — they're fixed by the spec and must match.
test "RC4 NT-hash string-to-key" {
    // NT hash of "password" (MD4 of UTF-16LE) — salt ignored. Standard known value.
    try expectKeyHexParams(.rc4_hmac, "password", "", "", "8846f7eaee8fb117ad06bdd830b7586c");
}

test "AES string-to-key RFC 3962 Appendix B" {
    const salt = "ATHENA.MIT.EDUraeburn";
    // s2kparams is the RAW 4-byte big-endian wire value (NOT hex text).
    // iteration count 1 (0x00000001)
    try expectKeyHexParams(.aes128_cts_hmac_sha1_96, "password", salt, &[_]u8{ 0, 0, 0, 1 }, "42263c6e89f4fc28b8df68ee09799f15");
    try expectKeyHexParams(.aes256_cts_hmac_sha1_96, "password", salt, &[_]u8{ 0, 0, 0, 1 }, "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161");
    // iteration count 2
    try expectKeyHexParams(.aes128_cts_hmac_sha1_96, "password", salt, &[_]u8{ 0, 0, 0, 2 }, "c651bf29e2300ac27fa469d693bdda13");
    try expectKeyHexParams(.aes256_cts_hmac_sha1_96, "password", salt, &[_]u8{ 0, 0, 0, 2 }, "a2e16d16b36069c135d5e9d2e25f896102685618b95914b467c67622225824ff");
    // iteration count 1200 (0x000004b0)
    try expectKeyHexParams(.aes128_cts_hmac_sha1_96, "password", salt, &[_]u8{ 0, 0, 0x04, 0xb0 }, "4c01cd46d632d01e6dbe230a01ed642a");
    try expectKeyHexParams(.aes256_cts_hmac_sha1_96, "password", salt, &[_]u8{ 0, 0, 0x04, 0xb0 }, "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a");
}

test "s2kIterations reads the raw wire value, defaults when absent, and clamps a hostile count" {
    // Raw 4-byte big-endian, honoured exactly.
    try testing.expectEqual(@as(u32, 1), s2kIterations(&[_]u8{ 0, 0, 0, 1 }, 4096));
    try testing.expectEqual(@as(u32, 1200), s2kIterations(&[_]u8{ 0, 0, 0x04, 0xb0 }, 4096));
    // Absent/malformed length => default.
    try testing.expectEqual(@as(u32, 4096), s2kIterations(&[_]u8{}, 4096));
    try testing.expectEqual(@as(u32, 32768), s2kIterations(&[_]u8{ 0, 1 }, 32768)); // wrong length
    // A hostile/spoofed 0xFFFFFFFF (and RFC's 0 == 2^32) are clamped, not run.
    try testing.expectEqual(max_pbkdf2_iters, s2kIterations(&[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, 4096));
    try testing.expectEqual(max_pbkdf2_iters, s2kIterations(&[_]u8{ 0, 0, 0, 0 }, 4096));
}

test "RFC 8009 KDF DeriveKey test vectors" {
    const a = testing.allocator;
    // aes128-cts-hmac-sha256-128 base key.
    var bk128: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bk128, "3705d96080c17728a0e800eab6e0d23c");
    {
        var kc_c: [5]u8 = undefined;
        usageConstant(&kc_c, 2, 0x99);
        const kc = try deriveKey(a, .aes128_cts_hmac_sha256_128, &bk128, &kc_c);
        defer a.free(kc);
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings("b31a018a48f54776f403e9a396325dc3", try std.fmt.bufPrint(&buf, "{x}", .{kc}));
    }
    {
        var ke_c: [5]u8 = undefined;
        usageConstant(&ke_c, 2, 0xAA);
        const ke = try deriveKey(a, .aes128_cts_hmac_sha256_128, &bk128, &ke_c);
        defer a.free(ke);
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings("9b197dd1e8c5609d6e67c3e37c62c72e", try std.fmt.bufPrint(&buf, "{x}", .{ke}));
    }
    {
        var ki_c: [5]u8 = undefined;
        usageConstant(&ki_c, 2, 0x55);
        const ki = try deriveKey(a, .aes128_cts_hmac_sha256_128, &bk128, &ki_c);
        defer a.free(ki);
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings("9fda0e56ab2d85e1569a688696c26a6c", try std.fmt.bufPrint(&buf, "{x}", .{ki}));
    }

    // aes256-cts-hmac-sha384-192 base key (Ke is 256-bit, Kc/Ki are 192-bit).
    var bk256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bk256, "6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52");
    {
        var kc_c: [5]u8 = undefined;
        usageConstant(&kc_c, 2, 0x99);
        const kc = try deriveKey(a, .aes256_cts_hmac_sha384_192, &bk256, &kc_c);
        defer a.free(kc);
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings("ef5718be86cc84963d8bbb5031e9f5c4ba41f28faf69e73d", try std.fmt.bufPrint(&buf, "{x}", .{kc}));
    }
    {
        var ke_c: [5]u8 = undefined;
        usageConstant(&ke_c, 2, 0xAA);
        const ke = try deriveKey(a, .aes256_cts_hmac_sha384_192, &bk256, &ke_c);
        defer a.free(ke);
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings("56ab22bee63d82d7bc5227f6773f8ea7a5eb1c825160c38312980c442e5c7e49", try std.fmt.bufPrint(&buf, "{x}", .{ke}));
    }
    {
        var ki_c: [5]u8 = undefined;
        usageConstant(&ki_c, 2, 0x55);
        const ki = try deriveKey(a, .aes256_cts_hmac_sha384_192, &bk256, &ki_c);
        defer a.free(ki);
        var buf: [64]u8 = undefined;
        try testing.expectEqualStrings("69b16514e3cd8e56b82010d5c73012b622c4d00ffc23ed1f", try std.fmt.bufPrint(&buf, "{x}", .{ki}));
    }
}

test "encrypt/decrypt round trip for all etypes" {
    const a = testing.allocator;
    const etypes = [_]EType{
        .des3_cbc_sha1_kd,
        .aes128_cts_hmac_sha1_96,
        .aes256_cts_hmac_sha1_96,
        .aes128_cts_hmac_sha256_128,
        .aes256_cts_hmac_sha384_192,
        .rc4_hmac,
    };
    const message = "The quick brown fox jumps over the lazy Kerberos KDC.";
    const confounder = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    for (etypes) |et| {
        // Synthetic round-trip fixture (encrypt-then-decrypt), not a real credential.
        const key = try stringToKey(a, et, "S3cr3tP@ss", "EXAMPLE.COMuser", "");
        defer a.free(key);
        try testing.expectEqual(et.keyByteSize(), key.len);
        const ct = try encryptMessageWithConfounder(a, et, key, message, 1, confounder[0..et.confounderByteSize()]);
        defer a.free(ct);
        const pt = try decryptMessage(a, et, key, ct, 1);
        defer a.free(pt);
        // DES3 zero-pads the plaintext to the block size and (per Kerberos)
        // does not strip the pad on decrypt; the ASN.1 length governs. So the
        // recovered message is `message` possibly followed by <8 zero bytes.
        try testing.expect(std.mem.startsWith(u8, pt, message));
        try testing.expect(pt.len - message.len < 8);
        for (pt[message.len..]) |b| try testing.expectEqual(@as(u8, 0), b);

        // Tampering must fail the integrity check.
        const bad = try a.dupe(u8, ct);
        defer a.free(bad);
        bad[bad.len - 1] ^= 0xFF;
        try testing.expectError(Error.IntegrityCheckFailed, decryptMessage(a, et, key, bad, 1));
    }
}

// End-to-end proof of the des3 reachability claim: this is the exact entry point
// `Client.verifyDecrypt` calls with the AS-REP enc-part, using the etype the KDC
// chose. A hostile KDC can select des3 (it is in the default advertised list)
// and return any ciphertext length it likes.
test "decryptMessage survives a hostile des3 ciphertext of arbitrary length" {
    const a = testing.allocator;
    const key = [_]u8{0x02} ** 24; // des3 key size
    // Long enough to clear the HMAC-length check, then a body that is not a
    // whole number of DES blocks.
    var ct: [29]u8 = undefined;
    @memset(&ct, 0xCD);
    const r = decryptMessage(a, .des3_cbc_sha1_kd, &key, &ct, 8);
    try testing.expectError(error.NotBlockAligned, r);

    // Anything shorter than the integrity tag is still a clean length error.
    var tiny: [4]u8 = undefined;
    @memset(&tiny, 0xCD);
    try testing.expectError(Error.CiphertextTooShort, decryptMessage(a, .des3_cbc_sha1_kd, &key, &tiny, 8));
}
