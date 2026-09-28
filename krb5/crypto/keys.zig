//! Password-to-key derivation dispatch (mirrors gokrb5 crypto.GetKeyFromPassword).
//! Computes the salt (default principal salt, or override from PA-DATA) and
//! runs the etype's string-to-key.

const std = @import("std");
const Allocator = std.mem.Allocator;
const EType = @import("etype.zig").EType;
const etype_mod = @import("etype.zig");
const PrincipalName = @import("../types/principal_name.zig").PrincipalName;
const PAData = @import("../types/pa_data.zig").PAData;
const pa_data = @import("../types/pa_data.zig");

pub const Error = error{ UnsupportedEType, MalformedETypeInfo, MalformedETypeInfo2 } ||
    etype_mod.Error || @import("../asn1/der.zig").Error;

/// Cap on the string-to-key salt length. A real salt (REALM + sAMAccountName) is
/// well under this; the bound stops a hostile/spoofed KDC's oversized PA-DATA
/// salt from amplifying through the des3 n-fold (~168x) into a memory DoS.
const max_salt_bytes: usize = 4096;

/// Derive the long-term key for `etype_id` from `password`, choosing the salt
/// from PA-DATA (PA-ETYPE-INFO2 > PA-ETYPE-INFO > PA-PW-SALT) or, failing that,
/// the principal's default salt (realm ++ name components).
///
/// OWNERSHIP: caller frees the returned key.
pub fn getKeyFromPassword(
    allocator: Allocator,
    password: []const u8,
    cname: PrincipalName,
    realm: []const u8,
    etype_id: i32,
    padata: []const PAData,
) Error![]u8 {
    const et = EType.fromId(etype_id) orelse return Error.UnsupportedEType;
    const info = try pa_data.extractSaltInfo(padata);

    // Choose the salt: PA-DATA override, else the default principal salt.
    var owned_salt: ?[]u8 = null;
    defer if (owned_salt) |s| allocator.free(s);
    const salt: []const u8 = if (info.salt) |s| s else blk: {
        owned_salt = try cname.getSalt(allocator, realm);
        break :blk owned_salt.?;
    };
    // A legitimate salt is REALM+sAMAccountName, a few hundred bytes at most. The
    // salt comes from the KDC's PA-ETYPE-INFO2, so a hostile/spoofed KDC could
    // send a huge one; the des3 n-fold string-to-key replicates it up to ~168x,
    // so cap it to keep a single derivation from ballooning memory (DoS).
    if (salt.len > max_salt_bytes) return Error.InvalidS2KParams;

    // Raw 4-byte wire s2kparams from PA-ETYPE-INFO2, or empty when the KDC sent
    // none (stringToKey then uses the etype's default iteration count).
    const s2kparams = info.s2kparams orelse &[_]u8{};
    return etype_mod.stringToKey(allocator, et, password, salt, s2kparams);
}

const testing = std.testing;

// NOTE: the literal `"password"` / `"raeburn"` / `"ATHENA.MIT.EDU"` below are the
// canonical RFC 3962 Appendix B string-to-key known-answer test vectors — NOT a
// real credential. They are fixed by the RFC and must be used verbatim.
test "getKeyFromPassword uses default principal salt with no PA-DATA" {
    const a = testing.allocator;
    const cname = PrincipalName{ .name_type = 1, .name_string = &.{"raeburn"} };
    // No PA-DATA -> salt = "ATHENA.MIT.EDU" ++ "raeburn".
    const k1 = try getKeyFromPassword(a, "password", cname, "ATHENA.MIT.EDU", 18, &.{});
    defer a.free(k1);
    // Must equal stringToKey with the explicit salt.
    const k2 = try etype_mod.stringToKey(a, .aes256_cts_hmac_sha1_96, "password", "ATHENA.MIT.EDUraeburn", "");
    defer a.free(k2);
    try testing.expectEqualSlices(u8, k2, k1);
}

test "getKeyFromPassword honours PA-PW-SALT override" {
    const a = testing.allocator;
    const cname = PrincipalName{ .name_type = 1, .name_string = &.{"ignored"} };
    const pas = [_]PAData{.{ .pa_data_type = 3, .pa_data_value = "ATHENA.MIT.EDUraeburn" }}; // PA_PW_SALT
    const k1 = try getKeyFromPassword(a, "password", cname, "WRONG.REALM", 17, &pas);
    defer a.free(k1);
    const k2 = try etype_mod.stringToKey(a, .aes128_cts_hmac_sha1_96, "password", "ATHENA.MIT.EDUraeburn", "");
    defer a.free(k2);
    try testing.expectEqualSlices(u8, k2, k1);
}
