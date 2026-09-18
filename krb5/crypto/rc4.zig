//! RC4 stream cipher. Required for the rc4-hmac (arcfour-hmac-md5) etype.
//! Not provided by Zig's std.crypto.

const std = @import("std");

pub const Rc4 = struct {
    s: [256]u8,
    i: u8 = 0,
    j: u8 = 0,

    /// Initialize the cipher with `key` (the KSA).
    pub fn init(key: []const u8) Rc4 {
        var r: Rc4 = .{ .s = undefined };
        for (&r.s, 0..) |*v, idx| v.* = @intCast(idx);
        var j: u8 = 0;
        var i: usize = 0;
        while (i < 256) : (i += 1) {
            j = j +% r.s[i] +% key[i % key.len];
            std.mem.swap(u8, &r.s[i], &r.s[j]);
        }
        return r;
    }

    /// XOR the keystream into `data` in place (the PRGA). Encrypt == decrypt.
    pub fn xor(self: *Rc4, data: []u8) void {
        for (data) |*b| {
            self.i +%= 1;
            self.j +%= self.s[self.i];
            std.mem.swap(u8, &self.s[self.i], &self.s[self.j]);
            const k = self.s[self.s[self.i] +% self.s[self.j]];
            b.* ^= k;
        }
    }
};

const testing = std.testing;

fn expectStream(key: []const u8, plaintext: []const u8, hex: []const u8) !void {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..plaintext.len], plaintext);
    var c = Rc4.init(key);
    c.xor(buf[0..plaintext.len]);
    var hexbuf: [128]u8 = undefined;
    const got = std.fmt.bufPrint(&hexbuf, "{x}", .{buf[0..plaintext.len]}) catch unreachable;
    try testing.expectEqualStrings(hex, got);
}

test "RC4 known test vectors" {
    try expectStream("Key", "Plaintext", "bbf316e8d940af0ad3");
    try expectStream("Wiki", "pedia", "1021bf0420");
    try expectStream("Secret", "Attack at dawn", "45a01f645fc35b383552544b9bf5");
}

test "RC4 decrypt is encrypt" {
    const key = "testkey123";
    const msg = "the quick brown fox";
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..msg.len], msg);
    var enc = Rc4.init(key);
    enc.xor(buf[0..msg.len]);
    var dec = Rc4.init(key);
    dec.xor(buf[0..msg.len]);
    try testing.expectEqualStrings(msg, buf[0..msg.len]);
}
