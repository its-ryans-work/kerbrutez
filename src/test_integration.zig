//! Live integration tests against a real KDC.
//!
//! These are the only tests that need real credentials, so the credentials live
//! in a git-ignored `.env` file (see `.env.example`), never in source. When
//! `.env` is missing — or a required key isn't set — each test returns
//! `error.SkipZigTest`, so `zig build test` passes everywhere without a lab.
//! When `.env` is present, they run an actual Kerberos exchange against it.

const std = @import("std");
const krb5 = @import("krb5");

/// Read `.env` from the current working directory (the repo root under
/// `zig build test`). Returns null if it doesn't exist. OWNERSHIP: caller frees.
fn readEnv(allocator: std.mem.Allocator, io: std.Io) ?[]u8 {
    var f = std.Io.Dir.cwd().openFile(io, ".env", .{}) catch return null;
    defer f.close(io);
    var buf: [4096]u8 = undefined;
    var r = f.reader(io, &buf);
    return r.interface.allocRemaining(allocator, .limited(1 << 20)) catch null;
}

/// Look up `KEY=value` in the `.env` contents (trims surrounding quotes/space).
fn envValue(content: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const k = std.mem.trim(u8, line[0..eq], " \t");
        if (!std.mem.eql(u8, k, key)) continue;
        const v = std.mem.trim(u8, line[eq + 1 ..], " \t\"'");
        return if (v.len == 0) null else v;
    }
    return null;
}

test "integration: userenum recognises a valid username (skips without .env)" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const content = readEnv(allocator, io) orelse return error.SkipZigTest;
    defer allocator.free(content);
    const domain = envValue(content, "KERBRUTEZ_TEST_DOMAIN") orelse return error.SkipZigTest;
    const dc = envValue(content, "KERBRUTEZ_TEST_DC") orelse return error.SkipZigTest;
    const valid_user = envValue(content, "KERBRUTEZ_TEST_VALID_USER") orelse return error.SkipZigTest;

    var config = try krb5.config.Config.init(allocator, domain, dc, .all);
    defer config.deinit();
    var client = krb5.client.Client.init(allocator, io, &config);

    switch (client.testUsername(valid_user)) {
        // No-pre-auth account: exists (and is AS-REP-roastable).
        .exists_no_preauth => |roast| roast.deinit(),
        // Pre-auth required => the username exists.
        .krb_error => |info| try std.testing.expectEqual(
            krb5.iana.error_code.kdc_err_preauth_required,
            info.code,
        ),
        // Lab unreachable — skip rather than fail a transient outage.
        .network_error => return error.SkipZigTest,
    }
}

test "integration: a valid credential logs in (skips without .env creds)" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const content = readEnv(allocator, io) orelse return error.SkipZigTest;
    defer allocator.free(content);
    const domain = envValue(content, "KERBRUTEZ_TEST_DOMAIN") orelse return error.SkipZigTest;
    const dc = envValue(content, "KERBRUTEZ_TEST_DC") orelse return error.SkipZigTest;
    const user = envValue(content, "KERBRUTEZ_TEST_USER") orelse return error.SkipZigTest;
    const pass = envValue(content, "KERBRUTEZ_TEST_PASS") orelse return error.SkipZigTest;

    var config = try krb5.config.Config.init(allocator, domain, dc, .all);
    defer config.deinit();
    var client = krb5.client.Client.init(allocator, io, &config);

    switch (client.login(user, pass)) {
        .valid => {}, // success
        // A valid-but-expired password is still a successful authentication.
        .krb_error => |e| try std.testing.expectEqual(krb5.iana.error_code.kdc_err_key_expired, e.code),
        .network_error => return error.SkipZigTest,
        .decrypt_error => return error.LoginRejectedBadPassword, // configured creds are wrong
    }
}
