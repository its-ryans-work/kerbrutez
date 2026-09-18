//! MD4 (RFC 1320). Required for the RC4-HMAC string-to-key (the "NT hash"),
//! which is MD4 over the UTF-16LE password. Not provided by Zig's std.crypto.

const std = @import("std");

pub const digest_length = 16;
pub const block_length = 64;

pub const Md4 = struct {
    s: [4]u32 = .{ 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 },
    buf: [block_length]u8 = undefined,
    buf_len: usize = 0,
    total_len: u64 = 0,

    pub fn init() Md4 {
        return .{};
    }

    /// One-shot hash convenience.
    pub fn hash(message: []const u8, out: *[digest_length]u8) void {
        var h = Md4.init();
        h.update(message);
        h.final(out);
    }

    pub fn update(self: *Md4, data: []const u8) void {
        self.total_len += data.len;
        var input = data;
        // Fill any partial buffer first.
        if (self.buf_len != 0) {
            const need = block_length - self.buf_len;
            const take = @min(need, input.len);
            @memcpy(self.buf[self.buf_len .. self.buf_len + take], input[0..take]);
            self.buf_len += take;
            input = input[take..];
            if (self.buf_len == block_length) {
                self.process(&self.buf);
                self.buf_len = 0;
            }
        }
        while (input.len >= block_length) {
            self.process(input[0..block_length]);
            input = input[block_length..];
        }
        if (input.len > 0) {
            @memcpy(self.buf[0..input.len], input);
            self.buf_len = input.len;
        }
    }

    pub fn final(self: *Md4, out: *[digest_length]u8) void {
        const bit_len = self.total_len *% 8;
        // Append 0x80 then zero-pad to 56 mod 64.
        var pad: [block_length]u8 = [_]u8{0} ** block_length;
        pad[0] = 0x80;
        const pad_len: usize = if (self.buf_len < 56) 56 - self.buf_len else 120 - self.buf_len;
        self.update(pad[0..pad_len]);
        // Append the 64-bit little-endian bit length.
        var len_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_bytes, bit_len, .little);
        self.update(&len_bytes);
        std.debug.assert(self.buf_len == 0);
        for (self.s, 0..) |word, i| {
            std.mem.writeInt(u32, out[i * 4 ..][0..4], word, .little);
        }
    }

    fn process(self: *Md4, block: *const [block_length]u8) void {
        var x: [16]u32 = undefined;
        for (0..16) |i| {
            x[i] = std.mem.readInt(u32, block[i * 4 ..][0..4], .little);
        }
        var a = self.s[0];
        var b = self.s[1];
        var c = self.s[2];
        var d = self.s[3];

        // Round 1: F(b,c,d) = (b & c) | (~b & d)
        const r1 = [_]u5{ 3, 7, 11, 19 };
        inline for (0..16) |i| {
            const f = (b & c) | (~b & d);
            const s = r1[i % 4];
            const t = a +% f +% x[i];
            a = d;
            d = c;
            c = b;
            b = std.math.rotl(u32, t, s);
        }

        // Round 2: G(b,c,d) = (b & c) | (b & d) | (c & d); add 0x5a827999
        const r2_k = [_]usize{ 0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15 };
        const r2_s = [_]u5{ 3, 5, 9, 13 };
        inline for (0..16) |i| {
            const g = (b & c) | (b & d) | (c & d);
            const s = r2_s[i % 4];
            const t = a +% g +% x[r2_k[i]] +% 0x5a827999;
            a = d;
            d = c;
            c = b;
            b = std.math.rotl(u32, t, s);
        }

        // Round 3: H(b,c,d) = b ^ c ^ d; add 0x6ed9eba1
        const r3_k = [_]usize{ 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15 };
        const r3_s = [_]u5{ 3, 9, 11, 15 };
        inline for (0..16) |i| {
            const h = b ^ c ^ d;
            const s = r3_s[i % 4];
            const t = a +% h +% x[r3_k[i]] +% 0x6ed9eba1;
            a = d;
            d = c;
            c = b;
            b = std.math.rotl(u32, t, s);
        }

        self.s[0] +%= a;
        self.s[1] +%= b;
        self.s[2] +%= c;
        self.s[3] +%= d;
    }
};

const testing = std.testing;

fn expectHash(message: []const u8, hex: []const u8) !void {
    var out: [digest_length]u8 = undefined;
    Md4.hash(message, &out);
    var buf: [digest_length * 2]u8 = undefined;
    const got = std.fmt.bufPrint(&buf, "{x}", .{&out}) catch unreachable;
    try testing.expectEqualStrings(hex, got);
}

test "MD4 RFC 1320 test vectors" {
    try expectHash("", "31d6cfe0d16ae931b73c59d7e0c089c0");
    try expectHash("a", "bde52cb31de33e46245e05fbdbd6fb24");
    try expectHash("abc", "a448017aaf21d8525fc10ae87aa6729d");
    try expectHash("message digest", "d9130a8164549fe818874806e1c7014b");
    try expectHash("abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9");
    try expectHash(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "043f8582f241db351ce627e153e7f0e4",
    );
}

test "MD4 streaming matches one-shot" {
    const msg = "The quick brown fox jumps over the lazy dog";
    var one: [digest_length]u8 = undefined;
    Md4.hash(msg, &one);
    var h = Md4.init();
    h.update(msg[0..10]);
    h.update(msg[10..]);
    var streamed: [digest_length]u8 = undefined;
    h.final(&streamed);
    try testing.expectEqualSlices(u8, &one, &streamed);
}
