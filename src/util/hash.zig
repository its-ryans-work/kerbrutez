//! AS-REP-roast hashcat formatting, mirroring kerbrute's util/hash.go.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{CipherTooShort} || Allocator.Error;

/// Format an AS-REP encrypted part as a hashcat `$krb5asrep$` string:
///   $krb5asrep$<etype>$<cname>@<crealm>:<hex(cipher[0:16])>$<hex(cipher[16:])>
/// OWNERSHIP: caller frees the returned string.
pub fn asRepToHashcat(
    allocator: Allocator,
    etype: i32,
    cname: []const u8,
    crealm: []const u8,
    cipher: []const u8,
) Error![]u8 {
    if (cipher.len < 16) return Error.CipherTooShort;
    return std.fmt.allocPrint(allocator, "$krb5asrep${d}${s}@{s}:{x}${x}", .{
        etype,
        cname,
        crealm,
        cipher[0..16],
        cipher[16..],
    });
}

/// hashcat `-m` mode for an AS-REP-roast hash of the given etype:
///   23 (RC4) -> 18200
///   anything else -> null
///
/// AES AS-REPs deliberately return NULL, because hashcat has no mode that
/// cracks them (verified against hashcat v7.1.2):
///   * 19600/19700 are TGS-REP modes. Feeding them a `$krb5asrep$18$...` hash
///     is rejected outright: "Separator unmatched ... No hashes loaded". These
///     are what this function used to return, so the tool was printing a `-m`
///     that could not even load the hash.
///   * 19800/19900 are "Pre-Auth" modes taking `$krb5pa$...` — the encrypted
///     AS-REQ timestamp, a different artifact entirely.
///   * 18200 PARSES an AES hash (its parser only keys on the `$krb5asrep$`
///     prefix), which makes it the most dangerous wrong answer: it is the
///     etype-23 mode, so it would grind RC4 candidates against AES data and
///     never crack it, while looking like a normal exhausted run.
/// Callers should tell the operator to use John the Ripper's krb5asrep format,
/// or to re-run with `--etype rc4` for a crackable RC4 AS-REP.
pub fn asRepHashcatMode(etype: i32) ?u32 {
    return switch (etype) {
        23 => 18200,
        else => null,
    };
}

/// Format a TGS-REP service-ticket enc-part as a hashcat `$krb5tgs$` string,
/// byte-for-byte matching impacket's GetUserSPNs `outputTGS`:
///   RC4 (23):     $krb5tgs$23$*user$realm$spn*$<hex(cipher[:16])>$<hex(cipher[16:])>
///   AES (17/18):  $krb5tgs$<et>$user$realm$*spn*$<hex(cipher[-12:])>$<hex(cipher[:-12])>
/// The SPN's ':' (host:port) is replaced with '~' per impacket. OWNERSHIP:
/// caller frees the returned string.
pub fn tgsToHashcat(
    allocator: Allocator,
    etype: i32,
    username: []const u8,
    realm: []const u8,
    spn: []const u8,
    cipher: []const u8,
) Error![]u8 {
    // impacket: spn.replace(':', '~')
    const spn_t = try allocator.dupe(u8, spn);
    defer allocator.free(spn_t);
    for (spn_t) |*c| {
        if (c.* == ':') c.* = '~';
    }

    if (etype == 23) {
        if (cipher.len < 16) return Error.CipherTooShort;
        // checksum = cipher[:16], edata = cipher[16:]; asterisks wrap user..spn.
        return std.fmt.allocPrint(allocator, "$krb5tgs$23$*{s}${s}${s}*${x}${x}", .{
            username, realm, spn_t, cipher[0..16], cipher[16..],
        });
    }
    // AES (17/18) and any other: checksum = cipher[-12:], edata = cipher[:-12];
    // asterisks wrap only the spn.
    if (cipher.len < 12) return Error.CipherTooShort;
    const split = cipher.len - 12;
    return std.fmt.allocPrint(allocator, "$krb5tgs${d}${s}${s}$*{s}*${x}${x}", .{
        etype, username, realm, spn_t, cipher[split..], cipher[0..split],
    });
}

/// hashcat `-m` mode for a kerberoast (TGS-REP) hash of the given etype:
///   23 (RC4)    -> 13100
///   17 (AES128) -> 19600
///   18 (AES256) -> 19700
/// Returns null for an etype hashcat has no TGS mode for.
pub fn tgsHashcatMode(etype: i32) ?u32 {
    return switch (etype) {
        23 => 13100,
        17 => 19600,
        18 => 19700,
        else => null,
    };
}

const testing = std.testing;

test "tgsToHashcat RC4 (23) matches impacket outputTGS byte-for-byte" {
    const a = testing.allocator;
    var cipher: [20]u8 = undefined;
    for (&cipher, 0..) |*b, i| b.* = @intCast(i); // 00 01 .. 13
    const h = try tgsToHashcat(a, 23, "sql_svc", "NORTH.SEVENKINGDOMS.LOCAL", "MSSQLSvc/host:1433", &cipher);
    defer a.free(h);
    // RC4: *user$realm$spn*  ;  ':' -> '~'  ;  split at 16 bytes.
    try testing.expectEqualStrings(
        "$krb5tgs$23$*sql_svc$NORTH.SEVENKINGDOMS.LOCAL$MSSQLSvc/host~1433*$000102030405060708090a0b0c0d0e0f$10111213",
        h,
    );
}

test "tgsToHashcat AES256 (18) matches impacket outputTGS byte-for-byte" {
    const a = testing.allocator;
    var cipher: [20]u8 = undefined;
    for (&cipher, 0..) |*b, i| b.* = @intCast(i); // 00 01 .. 13
    const h = try tgsToHashcat(a, 18, "sql_svc", "NORTH.SEVENKINGDOMS.LOCAL", "MSSQLSvc/host:1433", &cipher);
    defer a.free(h);
    // AES: user$realm$*spn*  ;  checksum = last 12 bytes, edata = preceding 8.
    try testing.expectEqualStrings(
        "$krb5tgs$18$sql_svc$NORTH.SEVENKINGDOMS.LOCAL$*MSSQLSvc/host~1433*$08090a0b0c0d0e0f10111213$0001020304050607",
        h,
    );
    try testing.expectError(Error.CipherTooShort, tgsToHashcat(a, 18, "u", "R", "s", "short"[0..5]));
}

test "tgsHashcatMode maps etypes to hashcat kerberoast modes" {
    try testing.expectEqual(@as(?u32, 13100), tgsHashcatMode(23));
    try testing.expectEqual(@as(?u32, 19600), tgsHashcatMode(17));
    try testing.expectEqual(@as(?u32, 19700), tgsHashcatMode(18));
    try testing.expectEqual(@as(?u32, null), tgsHashcatMode(16));
}

test "asRepHashcatMode maps etypes to hashcat modes" {
    try testing.expectEqual(@as(?u32, 18200), asRepHashcatMode(23));
    // AES AS-REPs have NO hashcat mode. 19600/19700 are TGS-REP modes and were
    // returned here before — hashcat rejects a $krb5asrep$ hash in those modes
    // ("Separator unmatched"), so the tool printed an unusable -m. Verified
    // against hashcat v7.1.2.
    try testing.expectEqual(@as(?u32, null), asRepHashcatMode(17));
    try testing.expectEqual(@as(?u32, null), asRepHashcatMode(18));
    try testing.expectEqual(@as(?u32, null), asRepHashcatMode(16));
}

test "asRepToHashcat format" {
    const a = testing.allocator;
    var cipher: [20]u8 = undefined;
    for (&cipher, 0..) |*b, i| b.* = @intCast(i);
    const h = try asRepToHashcat(a, 23, "user", "EXAMPLE.COM", &cipher);
    defer a.free(h);
    try testing.expectEqualStrings(
        "$krb5asrep$23$user@EXAMPLE.COM:000102030405060708090a0b0c0d0e0f$10111213",
        h,
    );
    try testing.expectError(Error.CipherTooShort, asRepToHashcat(a, 23, "u", "R", "short"));
}

