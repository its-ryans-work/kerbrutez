//! Differential-test helper: encrypts fixed inputs with the krb5 etype crypto
//! and prints the ciphertext hex, so a gokrb5 harness can confirm it decrypts.
//! Built ad hoc (see tools/diff_test.sh).

const std = @import("std");
const krb5 = @import("krb5");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var out = std.Io.File.stdout().writer(io, &buf);
    var w = &out.interface;

    const message = "hello kerberos preauth";

    // etype 18 (AES256): 32-byte key, 16-byte confounder.
    {
        var key: [32]u8 = undefined;
        for (&key, 0..) |*b, i| b.* = @intCast(i + 1);
        var confounder: [16]u8 = undefined;
        for (&confounder, 0..) |*b, i| b.* = @intCast(0xA0 + i);
        const ct = try krb5.etype.encryptMessageWithConfounder(gpa, .aes256_cts_hmac_sha1_96, &key, message, 1, &confounder);
        defer gpa.free(ct);
        try w.print("ETYPE18 {x}\n", .{ct});
    }
    // etype 23 (RC4): 16-byte key, 8-byte confounder.
    {
        var key: [16]u8 = undefined;
        for (&key, 0..) |*b, i| b.* = @intCast(i + 1);
        var confounder: [8]u8 = undefined;
        for (&confounder, 0..) |*b, i| b.* = @intCast(0xB0 + i);
        const ct = try krb5.etype.encryptMessageWithConfounder(gpa, .rc4_hmac, &key, message, 1, &confounder);
        defer gpa.free(ct);
        try w.print("ETYPE23 {x}\n", .{ct});
    }
    try w.flush();
}

var buf: [4096]u8 = undefined;
