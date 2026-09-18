//! RFC 4120 §5.9.1 KRB-ERROR.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");
const iana = @import("../iana/constants.zig");

pub const Error = error{ NotKRBError, WrongMessageType } || der.Error;

/// Parsed KRB-ERROR. String/byte fields BORROW from the source buffer, which
/// the caller must keep alive for the lifetime of this value.
pub const KRBError = struct {
    pvno: i32 = 0,
    msg_type: i32 = 0,
    error_code: i32 = 0,
    crealm: []const u8 = &.{},
    realm: []const u8 = &.{},
    /// e-data — typically a PA-DATA sequence (carries PA-ETYPE-INFO2 etc).
    edata: []const u8 = &.{},
    etext: []const u8 = &.{},

    /// Parse a KRB-ERROR from full wire bytes (APPLICATION[30]).
    /// BORROW: fields point into `bytes`.
    pub fn unmarshal(bytes: []const u8) Error!KRBError {
        const r = der.read(bytes) catch return Error.NotKRBError;
        if (r.elem.class != .application or r.elem.tag_number != iana.asn_app_tag.krb_error) {
            return Error.NotKRBError;
        }
        const seq = try r.elem.inner();
        var ke = KRBError{};
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                0 => ke.pvno = try (try field.inner()).integer32(),
                1 => ke.msg_type = try (try field.inner()).integer32(),
                // 2,3,4,5 (ctime/cusec/stime/susec) are not needed.
                6 => ke.error_code = try (try field.inner()).integer32(),
                7 => ke.crealm = (try field.inner()).bytes(),
                9 => ke.realm = (try field.inner()).bytes(),
                11 => ke.etext = (try field.inner()).bytes(),
                12 => ke.edata = (try field.inner()).bytes(),
                else => {},
            }
        }
        if (ke.msg_type != iana.msg_type.krb_error) return Error.WrongMessageType;
        return ke;
    }
};

/// MS-KILE §2.2.1 KERB-ERROR-DATA `data-type` for the extended NTSTATUS error.
const kerb_err_type_extended: i32 = 3;

/// NTSTATUS codes Active Directory reports inside a KDC_ERR_CLIENT_REVOKED.
///
/// WHY THIS MATTERS: the Kerberos error code alone (18, CLIENT_REVOKED) is the
/// same for a locked-out account, a disabled account and an expired one. Only
/// this NTSTATUS separates them — and confusing "disabled" with "locked" makes a
/// lockout-safety cap fire on accounts nobody locked.
pub const nt_status = struct {
    pub const account_restriction: u32 = 0xC000006E;
    pub const invalid_logon_hours: u32 = 0xC000006F;
    pub const invalid_workstation: u32 = 0xC0000070;
    pub const password_expired: u32 = 0xC0000071;
    pub const account_disabled: u32 = 0xC0000072;
    pub const account_expired: u32 = 0xC0000193;
    pub const password_must_change: u32 = 0xC0000224;
    pub const account_locked_out: u32 = 0xC0000234;
};

/// Extract the NTSTATUS Windows embeds in a KRB-ERROR e-data, or null when the
/// KDC didn't send one (MIT/Samba/Heimdal generally don't).
///
/// Wire shape (observed live against Windows Server AD):
///   SEQUENCE { [1] INTEGER data-type (3), [2] OCTET STRING data-value }
/// where data-value is KERB_EXT_ERROR { status: u32 LE, klininfo: u32, flags: u32 }.
/// e.g. `3015 a103020103 a20e040c 340200c0 00000000 01000000`
///      -> data-type 3, status 0xC0000234 (STATUS_ACCOUNT_LOCKED_OUT).
pub fn extendedNtStatus(edata: []const u8) ?u32 {
    if (edata.len == 0) return null;
    const r = der.read(edata) catch return null;
    // e-data IS the SEQUENCE here (no application wrapper), so iterate its
    // children directly rather than unwrapping an inner element.
    var it = r.elem.iterator();
    var data_type: ?i32 = null;
    var data_value: ?[]const u8 = null;
    while (it.next() catch null) |field| {
        const inner = field.inner() catch continue;
        switch (field.tag_number) {
            1 => data_type = inner.integer32() catch continue,
            2 => data_value = inner.bytes(),
            else => {},
        }
    }
    if (data_type != kerb_err_type_extended) return null;
    const v = data_value orelse return null;
    if (v.len < 4) return null;
    return std.mem.readInt(u32, v[0..4], .little);
}

/// True if the response bytes look like a KRB-ERROR (APPLICATION[30]).
pub fn isKRBError(bytes: []const u8) bool {
    if (bytes.len < 2) return false;
    return bytes[0] == (0x60 | iana.asn_app_tag.krb_error); // 0x7E
}

const testing = std.testing;

test "isKRBError tag detection" {
    try testing.expect(isKRBError(&.{ 0x7E, 0x10 }));
    try testing.expect(!isKRBError(&.{ 0x6B, 0x10 })); // AS-REP app tag 11
}

// The two e-data blobs below are VERBATIM CAPTURES from a live Windows Server
// AD DC (GOAD north.sevenkingdoms.local), not hand-written fixtures: both came
// back as KDC_ERR_CLIENT_REVOKED (18), and only the NTSTATUS distinguishes the
// disabled account from the locked-out one. Keeping the real bytes here is what
// makes this a regression test for "a disabled account tripped the panic-stop".
test "extendedNtStatus separates locked-out from disabled (live AD captures)" {
    // Guest — a DISABLED account. status = 0xC0000072.
    const disabled = [_]u8{
        0x30, 0x15, 0xa1, 0x03, 0x02, 0x01, 0x03, 0xa2, 0x0e, 0x04, 0x0c,
        0x72, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    };
    try testing.expectEqual(@as(?u32, nt_status.account_disabled), extendedNtStatus(&disabled));

    // samwell.tarly — genuinely LOCKED OUT by our own spray. status = 0xC0000234.
    const locked = [_]u8{
        0x30, 0x15, 0xa1, 0x03, 0x02, 0x01, 0x03, 0xa2, 0x0e, 0x04, 0x0c,
        0x34, 0x02, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    };
    try testing.expectEqual(@as(?u32, nt_status.account_locked_out), extendedNtStatus(&locked));
}

test "extendedNtStatus returns null when the KDC sends no extended error" {
    try testing.expectEqual(@as(?u32, null), extendedNtStatus(&.{})); // no e-data
    try testing.expectEqual(@as(?u32, null), extendedNtStatus(&.{ 0x30, 0x00 })); // empty seq
    // A PA-DATA style e-data (MIT/Samba): data-type is not 3 -> no NTSTATUS.
    const padata_ish = [_]u8{ 0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04, 0x00 };
    try testing.expectEqual(@as(?u32, null), extendedNtStatus(&padata_ish));
}
