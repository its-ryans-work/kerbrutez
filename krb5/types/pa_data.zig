//! RFC 4120 §5.2.7 pre-authentication data types.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");
const iana = @import("../iana/constants.zig");

/// PA-DATA ::= SEQUENCE { [1] padata-type INTEGER, [2] padata-value OCTET STRING }
pub const PAData = struct {
    pa_data_type: i32,
    /// BORROW or OWNED depending on construction.
    pa_data_value: []const u8,

    /// OWNERSHIP: caller frees.
    pub fn marshal(self: PAData, allocator: Allocator) ![]u8 {
        const t = try der.encodeInt(allocator, self.pa_data_type);
        defer allocator.free(t);
        const field1 = try der.explicit(allocator, 1, t);
        defer allocator.free(field1);
        const v = try der.encodeOctetString(allocator, self.pa_data_value);
        defer allocator.free(v);
        const field2 = try der.explicit(allocator, 2, v);
        defer allocator.free(field2);
        return der.sequence(allocator, &.{ field1, field2 });
    }

    /// Parse from a SEQUENCE element. BORROW: value points into source.
    pub fn unmarshal(seq: der.Element) !PAData {
        var pa = PAData{ .pa_data_type = 0, .pa_data_value = &.{} };
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                1 => pa.pa_data_type = try (try field.inner()).integer32(),
                2 => pa.pa_data_value = (try field.inner()).bytes(),
                else => {},
            }
        }
        return pa;
    }
};

/// Marshal a sequence of PA-DATA into a SEQUENCE OF. OWNERSHIP: caller frees.
pub fn marshalSequence(allocator: Allocator, items: []const PAData) ![]u8 {
    var encoded: std.ArrayList([]u8) = .empty;
    defer {
        for (encoded.items) |e| allocator.free(e);
        encoded.deinit(allocator);
    }
    for (items) |pa| try encoded.append(allocator, try pa.marshal(allocator));
    return der.sequence(allocator, encoded.items);
}

/// Parse a SEQUENCE OF PA-DATA. BORROW: values point into the source buffer.
/// OWNERSHIP: caller frees the returned slice (not the borrowed values).
pub fn unmarshalSequence(allocator: Allocator, seq: der.Element) ![]PAData {
    var list: std.ArrayList(PAData) = .empty;
    errdefer list.deinit(allocator);
    var it = seq.iterator();
    while (try it.next()) |elem| {
        try list.append(allocator, try PAData.unmarshal(elem));
    }
    return list.toOwnedSlice(allocator);
}

/// PA-ENC-TS-ENC ::= SEQUENCE { [0] patimestamp GeneralizedTime, [1] pausec INTEGER OPTIONAL }
/// Marshalled form is what gets encrypted for PA-ENC-TIMESTAMP pre-auth.
/// OWNERSHIP: caller frees.
pub fn marshalPAEncTSEnc(allocator: Allocator, epoch_secs: i64, usec: i32) ![]u8 {
    const ts = try der.encodeGeneralizedTime(allocator, epoch_secs);
    defer allocator.free(ts);
    const field0 = try der.explicit(allocator, 0, ts);
    defer allocator.free(field0);
    if (usec != 0) {
        const u = try der.encodeInt(allocator, usec);
        defer allocator.free(u);
        const field1 = try der.explicit(allocator, 1, u);
        defer allocator.free(field1);
        return der.sequence(allocator, &.{ field0, field1 });
    }
    return der.sequence(allocator, &.{field0});
}

/// A salt (and possibly an etype/s2kparams override) extracted from PA-DATA.
/// All slices BORROW from the source PA-DATA values.
pub const SaltInfo = struct {
    etype: ?i32 = null,
    salt: ?[]const u8 = null,
    s2kparams: ?[]const u8 = null,
};

/// Which pre-authentication mechanisms a KDC advertised (in the e-data of a
/// KDC_ERR_PREAUTH_REQUIRED, or a METHOD-DATA). Used to classify an account:
/// PKINIT-only accounts can't be password-sprayed, FAST-armored realms need an
/// armor ticket we don't build.
pub const PreauthMechanisms = struct {
    /// PA-ENC-TIMESTAMP offered ⇒ classic password pre-auth is possible.
    enc_timestamp: bool = false,
    /// PA-ETYPE-INFO/INFO2 present (salt/etype hints).
    etype_info: bool = false,
    /// PA-PK-AS-REQ present ⇒ PKINIT (certificate/smartcard) accepted/required.
    pkinit: bool = false,
    /// PA-FX-FAST present ⇒ the realm enforces FAST armoring.
    fast: bool = false,
    /// PA-FX-COOKIE present ⇒ a stateful multi-round exchange is in progress.
    fast_cookie: bool = false,
    /// PA-ENCRYPTED-CHALLENGE (FAST encrypted challenge) present.
    encrypted_challenge: bool = false,

    /// PKINIT looks *required* rather than merely offered: a certificate
    /// mechanism is present and classic PA-ENC-TIMESTAMP is not — the account is
    /// not password-sprayable.
    pub fn pkinitRequired(self: PreauthMechanisms) bool {
        return self.pkinit and !self.enc_timestamp;
    }

    /// FAST looks *enforced* rather than merely offered: armoring is advertised
    /// and classic PA-ENC-TIMESTAMP is not — a non-FAST spray will be rejected.
    /// (Many KDCs, e.g. Samba, advertise PA-FX-FAST *alongside* PA-ENC-TIMESTAMP;
    /// that is FAST-aware, not FAST-enforced, and classic spraying still works.)
    pub fn fastEnforced(self: PreauthMechanisms) bool {
        return self.fast and !self.enc_timestamp;
    }
};

/// Classify the pre-auth mechanisms in a PA-DATA sequence (e.g. from a
/// KDC_ERR_PREAUTH_REQUIRED e-data).
pub fn detectMechanisms(pas: []const PAData) PreauthMechanisms {
    var m = PreauthMechanisms{};
    for (pas) |pa| {
        switch (pa.pa_data_type) {
            iana.pa_type.pa_enc_timestamp => m.enc_timestamp = true,
            iana.pa_type.pa_etype_info, iana.pa_type.pa_etype_info2 => m.etype_info = true,
            iana.pa_type.pa_pk_as_req, iana.pa_type.pa_pk_as_req_old, iana.pa_type.pa_pk_as_rep => m.pkinit = true,
            iana.pa_type.pa_fx_fast => m.fast = true,
            iana.pa_type.pa_fx_cookie => m.fast_cookie = true,
            iana.pa_type.pa_encrypted_challenge => m.encrypted_challenge = true,
            else => {},
        }
    }
    return m;
}

/// Parse a KDC e-data field (a SEQUENCE OF PA-DATA) and classify it. Returns an
/// empty result on malformed/empty e-data. OWNERSHIP: uses `allocator` for the
/// transient PA-DATA slice, which is freed before returning.
pub fn detectMechanismsFromEdata(allocator: Allocator, edata: []const u8) PreauthMechanisms {
    if (edata.len == 0) return .{};
    const r = der.read(edata) catch return .{};
    const pas = unmarshalSequence(allocator, r.elem) catch return .{};
    defer allocator.free(pas);
    return detectMechanisms(pas);
}

/// Inspect a PA-DATA sequence for salt/etype info, mirroring gokrb5's
/// GetKeyFromPassword preference order (PA-ETYPE-INFO2 > PA-ETYPE-INFO >
/// PA-PW-SALT). BORROW: returned slices point into the PA-DATA values.
pub fn extractSaltInfo(pas: []const PAData) !SaltInfo {
    var info = SaltInfo{};
    var best_type: i32 = -1;
    for (pas) |pa| {
        if (pa.pa_data_type < best_type) continue;
        switch (pa.pa_data_type) {
            iana.pa_type.pa_pw_salt => {
                best_type = pa.pa_data_type;
                info.salt = pa.pa_data_value;
            },
            iana.pa_type.pa_etype_info => {
                best_type = pa.pa_data_type;
                const e = try parseETypeInfoFirst(pa.pa_data_value);
                info.etype = e.etype;
                info.salt = e.salt;
            },
            iana.pa_type.pa_etype_info2 => {
                best_type = pa.pa_data_type;
                const e = try parseETypeInfo2First(pa.pa_data_value);
                info.etype = e.etype;
                info.salt = e.salt;
                info.s2kparams = e.s2kparams;
            },
            else => {},
        }
    }
    return info;
}

const ETypeInfoEntry = struct { etype: i32, salt: ?[]const u8 };
const ETypeInfo2Entry = struct { etype: i32, salt: ?[]const u8, s2kparams: ?[]const u8 };

/// Parse the first entry of a PA-ETYPE-INFO (SEQUENCE OF ETYPE-INFO-ENTRY).
fn parseETypeInfoFirst(value: []const u8) !ETypeInfoEntry {
    const r = try der.read(value);
    var it = r.elem.iterator();
    const entry = (try it.next()) orelse return error.MalformedETypeInfo;
    var out = ETypeInfoEntry{ .etype = 0, .salt = null };
    var eit = entry.iterator();
    while (try eit.next()) |field| {
        switch (field.tag_number) {
            0 => out.etype = try (try field.inner()).integer32(),
            1 => out.salt = (try field.inner()).bytes(), // OCTET STRING salt
            else => {},
        }
    }
    return out;
}

/// Parse the first entry of a PA-ETYPE-INFO2 (SEQUENCE OF ETYPE-INFO2-ENTRY).
fn parseETypeInfo2First(value: []const u8) !ETypeInfo2Entry {
    const r = try der.read(value);
    var it = r.elem.iterator();
    const entry = (try it.next()) orelse return error.MalformedETypeInfo2;
    var out = ETypeInfo2Entry{ .etype = 0, .salt = null, .s2kparams = null };
    var eit = entry.iterator();
    while (try eit.next()) |field| {
        switch (field.tag_number) {
            0 => out.etype = try (try field.inner()).integer32(),
            1 => out.salt = (try field.inner()).bytes(), // GeneralString salt
            2 => out.s2kparams = (try field.inner()).bytes(),
            else => {},
        }
    }
    return out;
}

const testing = std.testing;

test "PAData marshal/unmarshal round trip" {
    const a = testing.allocator;
    const pa = PAData{ .pa_data_type = 2, .pa_data_value = &.{ 0xDE, 0xAD, 0xBE, 0xEF } };
    const b = try pa.marshal(a);
    defer a.free(b);
    const r = try der.read(b);
    const parsed = try PAData.unmarshal(r.elem);
    try testing.expectEqual(@as(i32, 2), parsed.pa_data_type);
    try testing.expectEqualSlices(u8, &.{ 0xDE, 0xAD, 0xBE, 0xEF }, parsed.pa_data_value);
}

test "detectMechanisms classifies password vs PKINIT vs FAST" {
    // Normal account: PA-ENC-TIMESTAMP + PA-ETYPE-INFO2.
    const normal = [_]PAData{
        .{ .pa_data_type = iana.pa_type.pa_enc_timestamp, .pa_data_value = &.{} },
        .{ .pa_data_type = iana.pa_type.pa_etype_info2, .pa_data_value = &.{} },
    };
    const m1 = detectMechanisms(&normal);
    try testing.expect(m1.enc_timestamp and m1.etype_info);
    try testing.expect(!m1.pkinitRequired() and !m1.fast);

    // Smartcard-required: PA-PK-AS-REQ present, no PA-ENC-TIMESTAMP.
    const pkinit = [_]PAData{
        .{ .pa_data_type = iana.pa_type.pa_pk_as_req, .pa_data_value = &.{} },
        .{ .pa_data_type = iana.pa_type.pa_etype_info2, .pa_data_value = &.{} },
    };
    const m2 = detectMechanisms(&pkinit);
    try testing.expect(m2.pkinit and m2.pkinitRequired());

    // FAST-armored realm.
    const fast = [_]PAData{
        .{ .pa_data_type = iana.pa_type.pa_fx_fast, .pa_data_value = &.{} },
        .{ .pa_data_type = iana.pa_type.pa_fx_cookie, .pa_data_value = &.{} },
    };
    const m3 = detectMechanisms(&fast);
    try testing.expect(m3.fast and m3.fast_cookie and m3.fastEnforced());

    // FAST offered ALONGSIDE classic pre-auth (e.g. Samba) ⇒ not enforced.
    const fast_offered = [_]PAData{
        .{ .pa_data_type = iana.pa_type.pa_enc_timestamp, .pa_data_value = &.{} },
        .{ .pa_data_type = iana.pa_type.pa_fx_fast, .pa_data_value = &.{} },
    };
    const m4 = detectMechanisms(&fast_offered);
    try testing.expect(m4.fast and !m4.fastEnforced());
}

test "detectMechanismsFromEdata parses a wire PA-DATA sequence" {
    const a = testing.allocator;
    const pas = [_]PAData{.{ .pa_data_type = iana.pa_type.pa_pk_as_req, .pa_data_value = &.{ 1, 2 } }};
    const seq = try marshalSequence(a, &pas);
    defer a.free(seq);
    const m = detectMechanismsFromEdata(a, seq);
    try testing.expect(m.pkinit);
    try testing.expect(detectMechanismsFromEdata(a, &.{}).pkinit == false); // empty edata
}

test "PAEncTSEnc marshal shape" {
    const a = testing.allocator;
    // 2024-01-02 03:04:05, usec 123456
    const secs: i64 = 1704164645;
    const b = try marshalPAEncTSEnc(a, secs, 123456);
    defer a.free(b);
    const r = try der.read(b);
    var it = r.elem.iterator();
    const f0 = (try it.next()).?;
    try testing.expectEqual(@as(u8, 0), f0.tag_number);
    const ts = try f0.inner();
    try testing.expectEqual(der.tag.generalized_time, ts.raw[0]);
    const f1 = (try it.next()).?;
    try testing.expectEqual(@as(u8, 1), f1.tag_number);
    try testing.expectEqual(@as(i64, 123456), try (try f1.inner()).integer());
}
