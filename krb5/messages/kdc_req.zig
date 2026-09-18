//! RFC 4120 §5.4.1 KDC-REQ (we build AS-REQ).
//!
//! Marshalling is deterministic given the parameters (nonce, till, etc.), so
//! the client supplies those; this keeps the encoding byte-for-byte testable
//! against gokrb5.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");
const iana = @import("../iana/constants.zig");
const PrincipalName = @import("../types/principal_name.zig").PrincipalName;
const PAData = @import("../types/pa_data.zig").PAData;
const pa_data = @import("../types/pa_data.zig");
const KrbFlags = @import("../types/kerberos_flags.zig").KrbFlags;

pub const ASReqParams = struct {
    realm: []const u8,
    cname: PrincipalName,
    sname: PrincipalName,
    nonce: i32,
    /// Ticket end time as UTC epoch seconds (the [5] Till field).
    till_epoch: i64,
    etypes: []const i32,
    kdc_options: KrbFlags,
    /// Pre-auth data; empty means the [3] PAData field is omitted.
    padata: []const PAData = &.{},
};

/// Marshal an AS-REQ to its full wire bytes (APPLICATION[10]).
/// OWNERSHIP: caller frees.
pub fn marshalASReq(allocator: Allocator, p: ASReqParams) ![]u8 {
    const body = try marshalReqBody(allocator, p);
    defer allocator.free(body);
    const field4 = try der.explicit(allocator, 4, body);
    defer allocator.free(field4);

    const pvno = try der.encodeInt(allocator, iana.pvno);
    defer allocator.free(pvno);
    const field1 = try der.explicit(allocator, 1, pvno);
    defer allocator.free(field1);

    const mt = try der.encodeInt(allocator, iana.msg_type.krb_as_req);
    defer allocator.free(mt);
    const field2 = try der.explicit(allocator, 2, mt);
    defer allocator.free(field2);

    // The [3] PAData field is always emitted, even when empty, to match
    // gokrb5/kerbrute (NewASReq sets a non-nil empty PADataSequence, which Go's
    // asn1 marshals as an empty SEQUENCE rather than omitting the field).
    const pa_seq = try pa_data.marshalSequence(allocator, p.padata);
    defer allocator.free(pa_seq);
    const field3 = try der.explicit(allocator, 3, pa_seq);
    defer allocator.free(field3);

    var fields: std.ArrayList([]const u8) = .empty;
    defer fields.deinit(allocator);
    try fields.append(allocator, field1);
    try fields.append(allocator, field2);
    try fields.append(allocator, field3);
    try fields.append(allocator, field4);

    const seq = try der.sequence(allocator, fields.items);
    defer allocator.free(seq);
    return der.application(allocator, iana.asn_app_tag.as_req, seq);
}

/// KDC-REQ-BODY fields. `cname` is optional: present for AS-REQ, omitted for
/// TGS-REQ (where the client identity comes from the AP-REQ's ticket instead).
pub const ReqBody = struct {
    kdc_options: KrbFlags,
    cname: ?PrincipalName = null,
    realm: []const u8,
    sname: PrincipalName,
    till_epoch: i64,
    nonce: i32,
    etypes: []const i32,
};

/// Marshal a KDC-REQ-BODY SEQUENCE shared by AS-REQ and TGS-REQ. Field order
/// [0][1?][2][3][5][7][8]; [1] CName is emitted only when present.
/// OWNERSHIP: caller frees.
pub fn marshalKdcReqBody(allocator: Allocator, b: ReqBody) ![]u8 {
    var fields: std.ArrayList([]const u8) = .empty;
    defer {
        for (fields.items) |f| allocator.free(f);
        fields.deinit(allocator);
    }

    // [0] KDCOptions BIT STRING
    {
        const opts = try der.encodeBitString(allocator, &b.kdc_options.bytes, KrbFlags.bit_length);
        defer allocator.free(opts);
        try fields.append(allocator, try der.explicit(allocator, 0, opts));
    }
    // [1] CName (AS-REQ only)
    if (b.cname) |cn| {
        const cname_b = try cn.marshal(allocator);
        defer allocator.free(cname_b);
        try fields.append(allocator, try der.explicit(allocator, 1, cname_b));
    }
    // [2] Realm GeneralString
    {
        const realm_gs = try der.encodeGeneralString(allocator, b.realm);
        defer allocator.free(realm_gs);
        try fields.append(allocator, try der.explicit(allocator, 2, realm_gs));
    }
    // [3] SName
    {
        const sname_b = try b.sname.marshal(allocator);
        defer allocator.free(sname_b);
        try fields.append(allocator, try der.explicit(allocator, 3, sname_b));
    }
    // [5] Till GeneralizedTime
    {
        const till = try der.encodeGeneralizedTime(allocator, b.till_epoch);
        defer allocator.free(till);
        try fields.append(allocator, try der.explicit(allocator, 5, till));
    }
    // [7] Nonce INTEGER
    {
        const nonce = try der.encodeInt(allocator, b.nonce);
        defer allocator.free(nonce);
        try fields.append(allocator, try der.explicit(allocator, 7, nonce));
    }
    // [8] EType SEQUENCE OF INTEGER
    {
        var etype_ints: std.ArrayList([]u8) = .empty;
        defer {
            for (etype_ints.items) |e| allocator.free(e);
            etype_ints.deinit(allocator);
        }
        for (b.etypes) |e| try etype_ints.append(allocator, try der.encodeInt(allocator, e));
        const etype_seq = try der.sequence(allocator, etype_ints.items);
        defer allocator.free(etype_seq);
        try fields.append(allocator, try der.explicit(allocator, 8, etype_seq));
    }

    return der.sequence(allocator, fields.items);
}

/// Marshal the KDC-REQ-BODY for an AS-REQ. OWNERSHIP: caller frees.
fn marshalReqBody(allocator: Allocator, p: ASReqParams) ![]u8 {
    return marshalKdcReqBody(allocator, .{
        .kdc_options = p.kdc_options,
        .cname = p.cname,
        .realm = p.realm,
        .sname = p.sname,
        .till_epoch = p.till_epoch,
        .nonce = p.nonce,
        .etypes = p.etypes,
    });
}

const testing = std.testing;

fn fixedParams() ASReqParams {
    var opts = KrbFlags{};
    opts.setFlag(iana.flags.renewable_ok);
    return .{
        .realm = "EXAMPLE.COM",
        .cname = .{ .name_type = iana.name_type.krb_nt_principal, .name_string = &.{"user"} },
        .sname = .{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = &.{ "krbtgt", "EXAMPLE.COM" } },
        .nonce = 305419896, // 0x12345678
        .till_epoch = 1704164645, // 2024-01-02 03:04:05 UTC
        .etypes = &.{ 18, 17, 16, 23 },
        .kdc_options = opts,
    };
}

test "AS-REQ (no pre-auth) is byte-for-byte identical to gokrb5" {
    const a = testing.allocator;
    const b = try marshalASReq(a, fixedParams());
    defer a.free(b);
    // Reference produced by gokrb5 v8 messages.ASReq.Marshal with identical
    // fixed inputs (empty PADataSequence). See tools/ diff harness.
    const want = "6a818d30818aa103020105a20302010aa3023000a47a3078a00703050000000010a111300fa003020101a10830061b0475736572a20d1b0b4558414d504c452e434f4da320301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da511180f32303234303130323033303430355aa706020412345678a80e300c020112020111020110020117";
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(want, try std.fmt.bufPrint(&buf, "{x}", .{b}));
}

test "AS-REQ (with PA-ENC-TIMESTAMP) is byte-for-byte identical to gokrb5" {
    const a = testing.allocator;
    var p = fixedParams();
    p.padata = &.{.{ .pa_data_type = 2, .pa_data_value = &.{ 0xDE, 0xAD, 0xBE, 0xEF } }};
    const b = try marshalASReq(a, p);
    defer a.free(b);
    const want = "6a819c308199a103020105a20302010aa311300f300da103020102a2060404deadbeefa47a3078a00703050000000010a111300fa003020101a10830061b0475736572a20d1b0b4558414d504c452e434f4da320301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da511180f32303234303130323033303430355aa706020412345678a80e300c020112020111020110020117";
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(want, try std.fmt.bufPrint(&buf, "{x}", .{b}));
}
