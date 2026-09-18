//! RFC 4120 §5.5.1 / §5.4.1 — the TGS-REQ path (kerberoast).
//!
//! A TGS-REQ proves the client already holds a TGT: it carries a PA-TGS-REQ
//! pre-auth element wrapping an AP-REQ (the TGT + an Authenticator encrypted
//! with the TGT session key), and a req-body whose [3] SName is the *service*
//! we want a ticket for. The KDC answers with a TGS-REP containing a service
//! Ticket whose enc-part is encrypted with the service account's long-term key
//! — the kerberoast material.
//!
//! Marshalling is deterministic given the inputs (nonce, times, confounder), so
//! the client supplies them; this keeps the encoding testable.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");
const iana = @import("../iana/constants.zig");
const PrincipalName = @import("../types/principal_name.zig").PrincipalName;
const EncryptedData = @import("../types/encrypted_data.zig").EncryptedData;
const PAData = @import("../types/pa_data.zig").PAData;
const pa_data = @import("../types/pa_data.zig");
const kdc_req = @import("kdc_req.zig");

/// Marshal an Authenticator (APPLICATION[2]) for an AP-REQ. We emit the minimal
/// set kerberoast needs: vno, crealm, cname, cusec, ctime (cksum/subkey are
/// OPTIONAL and omitted). OWNERSHIP: caller frees.
pub fn marshalAuthenticator(
    allocator: Allocator,
    crealm: []const u8,
    cname: PrincipalName,
    cusec: i32,
    ctime_epoch: i64,
) ![]u8 {
    var fields: std.ArrayList([]const u8) = .empty;
    defer {
        for (fields.items) |f| allocator.free(f);
        fields.deinit(allocator);
    }
    // [0] authenticator-vno INTEGER (5)
    {
        const v = try der.encodeInt(allocator, iana.pvno);
        defer allocator.free(v);
        try fields.append(allocator, try der.explicit(allocator, 0, v));
    }
    // [1] crealm GeneralString
    {
        const r = try der.encodeGeneralString(allocator, crealm);
        defer allocator.free(r);
        try fields.append(allocator, try der.explicit(allocator, 1, r));
    }
    // [2] cname PrincipalName
    {
        const cn = try cname.marshal(allocator);
        defer allocator.free(cn);
        try fields.append(allocator, try der.explicit(allocator, 2, cn));
    }
    // [4] cusec INTEGER
    {
        const u = try der.encodeInt(allocator, cusec);
        defer allocator.free(u);
        try fields.append(allocator, try der.explicit(allocator, 4, u));
    }
    // [5] ctime GeneralizedTime
    {
        const t = try der.encodeGeneralizedTime(allocator, ctime_epoch);
        defer allocator.free(t);
        try fields.append(allocator, try der.explicit(allocator, 5, t));
    }
    const seq = try der.sequence(allocator, fields.items);
    defer allocator.free(seq);
    return der.application(allocator, iana.asn_app_tag.authenticator, seq);
}

/// Marshal an AP-REQ (APPLICATION[14]) carrying the TGT and an already-encrypted
/// Authenticator. `ticket_raw` is the full Ticket element (APPLICATION[1]).
/// `ap_options` defaults to all-zero. OWNERSHIP: caller frees.
pub fn marshalApReq(allocator: Allocator, ticket_raw: []const u8, authenticator: EncryptedData) ![]u8 {
    var fields: std.ArrayList([]const u8) = .empty;
    defer {
        for (fields.items) |f| allocator.free(f);
        fields.deinit(allocator);
    }
    // [0] pvno INTEGER (5)
    {
        const v = try der.encodeInt(allocator, iana.pvno);
        defer allocator.free(v);
        try fields.append(allocator, try der.explicit(allocator, 0, v));
    }
    // [1] msg-type INTEGER (14)
    {
        const m = try der.encodeInt(allocator, iana.msg_type.krb_ap_req);
        defer allocator.free(m);
        try fields.append(allocator, try der.explicit(allocator, 1, m));
    }
    // [2] ap-options APOptions (BIT STRING, 32 bits, all zero)
    {
        const opts = try der.encodeBitString(allocator, &[_]u8{ 0, 0, 0, 0 }, 32);
        defer allocator.free(opts);
        try fields.append(allocator, try der.explicit(allocator, 2, opts));
    }
    // [3] ticket (the TGT, already a complete APPLICATION[1] element)
    try fields.append(allocator, try der.explicit(allocator, 3, ticket_raw));
    // [4] authenticator EncryptedData
    {
        const ed = try authenticator.marshal(allocator);
        defer allocator.free(ed);
        try fields.append(allocator, try der.explicit(allocator, 4, ed));
    }
    const seq = try der.sequence(allocator, fields.items);
    defer allocator.free(seq);
    return der.application(allocator, iana.asn_app_tag.ap_req, seq);
}

/// Marshal a TGS-REQ (APPLICATION[12]): the AP-REQ goes in a PA-TGS-REQ
/// pre-auth element, and `body` is the KDC-REQ-BODY (SName = the target SPN).
/// OWNERSHIP: caller frees.
pub fn marshalTGSReq(allocator: Allocator, ap_req: []const u8, body: kdc_req.ReqBody) ![]u8 {
    // [1] pvno
    const pvno = try der.encodeInt(allocator, iana.pvno);
    defer allocator.free(pvno);
    const field1 = try der.explicit(allocator, 1, pvno);
    defer allocator.free(field1);

    // [2] msg-type (12)
    const mt = try der.encodeInt(allocator, iana.msg_type.krb_tgs_req);
    defer allocator.free(mt);
    const field2 = try der.explicit(allocator, 2, mt);
    defer allocator.free(field2);

    // [3] padata: one PA-TGS-REQ (type 1) whose value is the AP-REQ.
    const pa = [_]PAData{.{ .pa_data_type = iana.pa_type.pa_tgs_req, .pa_data_value = ap_req }};
    const pa_seq = try pa_data.marshalSequence(allocator, &pa);
    defer allocator.free(pa_seq);
    const field3 = try der.explicit(allocator, 3, pa_seq);
    defer allocator.free(field3);

    // [4] req-body
    const body_b = try kdc_req.marshalKdcReqBody(allocator, body);
    defer allocator.free(body_b);
    const field4 = try der.explicit(allocator, 4, body_b);
    defer allocator.free(field4);

    const seq = try der.sequence(allocator, &.{ field1, field2, field3, field4 });
    defer allocator.free(seq);
    return der.application(allocator, iana.asn_app_tag.tgs_req, seq);
}

/// Split a service principal name "a/b/c" into its components for an SName.
/// OWNERSHIP: caller frees the slice (the parts borrow `spn`).
pub fn splitSpn(allocator: Allocator, spn: []const u8) ![]const []const u8 {
    var parts: std.ArrayList([]const u8) = .empty;
    errdefer parts.deinit(allocator);
    var it = std.mem.splitScalar(u8, spn, '/');
    while (it.next()) |p| try parts.append(allocator, p);
    return parts.toOwnedSlice(allocator);
}

const testing = std.testing;

test "Authenticator round-trips through the DER reader" {
    const a = testing.allocator;
    const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &.{"alice"} };
    const b = try marshalAuthenticator(a, "EXAMPLE.LOCAL", cname, 123456, 1704164645);
    defer a.free(b);
    const r = try der.read(b);
    try testing.expect(r.elem.class == .application);
    try testing.expectEqual(@as(u32, iana.asn_app_tag.authenticator), r.elem.tag_number);
}

test "splitSpn splits service/host:port" {
    const a = testing.allocator;
    const parts = try splitSpn(a, "MSSQLSvc/db.example.local:1433");
    defer a.free(parts);
    try testing.expectEqual(@as(usize, 2), parts.len);
    try testing.expectEqualStrings("MSSQLSvc", parts[0]);
    try testing.expectEqualStrings("db.example.local:1433", parts[1]);
}

test "TGS-REQ marshals to APPLICATION[12] and re-reads" {
    const a = testing.allocator;
    const ap_req = [_]u8{ 0x6E, 0x02, 0x05, 0x00 }; // dummy AP-REQ bytes
    var opts = @import("../types/kerberos_flags.zig").KrbFlags{};
    const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = &.{ "MSSQLSvc", "host:1433" } };
    const b = try marshalTGSReq(a, &ap_req, .{
        .kdc_options = opts,
        .cname = null,
        .realm = "NORTH.SEVENKINGDOMS.LOCAL",
        .sname = sname,
        .till_epoch = 1704164645,
        .nonce = 0x12345678,
        .etypes = &.{ 18, 17, 23 },
    });
    defer a.free(b);
    _ = &opts;
    const r = try der.read(b);
    try testing.expect(r.elem.class == .application);
    try testing.expectEqual(@as(u32, iana.asn_app_tag.tgs_req), r.elem.tag_number);
}
