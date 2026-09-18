//! RFC 4120 §5.4.2 KDC-REP (we parse AS-REP) and the encrypted EncKDCRepPart.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");
const iana = @import("../iana/constants.zig");
const PrincipalName = @import("../types/principal_name.zig").PrincipalName;
const EncryptedData = @import("../types/encrypted_data.zig").EncryptedData;
const EncryptionKey = @import("../types/encrypted_data.zig").EncryptionKey;
const PAData = @import("../types/pa_data.zig").PAData;
const pa_data = @import("../types/pa_data.zig");

pub const Error = error{ NotASRep, WrongMessageType, MalformedASRep, MalformedPrincipalName } || der.Error || Allocator.Error;

/// A parsed AS-REP. `padata` and `cname.name_string` are OWNED (allocated with
/// the provided allocator; free with `deinit`). `crealm` and `enc_part.cipher`
/// BORROW from the source buffer, which must stay alive.
pub const ASRep = struct {
    allocator: Allocator,
    pvno: i32 = 0,
    msg_type: i32 = 0,
    padata: []PAData = &.{},
    crealm: []const u8 = &.{},
    cname: PrincipalName = .{ .name_type = 0, .name_string = &.{} },
    /// Raw Ticket bytes (field [5], APPLICATION[1]) — re-embedded verbatim in
    /// the AP-REQ of a follow-up TGS-REQ. BORROWS the source buffer.
    ticket_raw: []const u8 = &.{},
    enc_part: EncryptedData = .{ .etype = 0, .cipher = &.{} },

    /// Parse an AS-REP from full wire bytes (APPLICATION[11]).
    pub fn unmarshal(allocator: Allocator, bytes: []const u8) Error!ASRep {
        const r = der.read(bytes) catch return Error.NotASRep;
        if (r.elem.class != .application or r.elem.tag_number != iana.asn_app_tag.as_rep) {
            return Error.NotASRep;
        }
        const seq = try r.elem.inner();
        var rep = ASRep{ .allocator = allocator };
        errdefer rep.deinit();
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                0 => rep.pvno = try (try field.inner()).integer32(),
                1 => rep.msg_type = try (try field.inner()).integer32(),
                2 => rep.padata = try pa_data.unmarshalSequence(allocator, try field.inner()),
                3 => rep.crealm = (try field.inner()).bytes(),
                4 => rep.cname = try PrincipalName.unmarshal(allocator, try field.inner()),
                5 => rep.ticket_raw = (try field.inner()).raw, // the Ticket (APPLICATION[1])
                6 => rep.enc_part = try EncryptedData.unmarshal(try field.inner()),
                else => {},
            }
        }
        if (rep.msg_type != iana.msg_type.krb_as_rep) return Error.WrongMessageType;
        return rep;
    }

    pub fn deinit(self: *ASRep) void {
        if (self.padata.len > 0) self.allocator.free(self.padata);
        if (self.cname.name_string.len > 0) self.cname.deinit(self.allocator);
        self.padata = &.{};
        self.cname = .{ .name_type = 0, .name_string = &.{} };
    }
};

/// True if the response bytes look like an AS-REP (APPLICATION[11]).
pub fn isASRep(bytes: []const u8) bool {
    if (bytes.len < 2) return false;
    return bytes[0] == (0x60 | iana.asn_app_tag.as_rep); // 0x6B
}

/// True if the response bytes look like a TGS-REP (APPLICATION[13]).
pub fn isTGSRep(bytes: []const u8) bool {
    if (bytes.len < 2) return false;
    return bytes[0] == (0x60 | iana.asn_app_tag.tgs_rep); // 0x6D
}

/// A parsed TGS-REP. We only need the service Ticket (field [5]) — its enc-part
/// is the kerberoast material. `ticket_raw`/`crealm` BORROW the source buffer;
/// `cname` is OWNED (free with `deinit`).
pub const TGSRep = struct {
    allocator: Allocator,
    crealm: []const u8 = &.{},
    cname: PrincipalName = .{ .name_type = 0, .name_string = &.{} },
    /// Raw service Ticket bytes (field [5], APPLICATION[1]).
    ticket_raw: []const u8 = &.{},
    enc_part: EncryptedData = .{ .etype = 0, .cipher = &.{} },

    pub fn unmarshal(allocator: Allocator, bytes: []const u8) Error!TGSRep {
        const r = der.read(bytes) catch return Error.NotASRep;
        if (r.elem.class != .application or r.elem.tag_number != iana.asn_app_tag.tgs_rep) {
            return Error.NotASRep;
        }
        const seq = try r.elem.inner();
        var rep = TGSRep{ .allocator = allocator };
        errdefer rep.deinit();
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                3 => rep.crealm = (try field.inner()).bytes(),
                4 => rep.cname = try PrincipalName.unmarshal(allocator, try field.inner()),
                5 => rep.ticket_raw = (try field.inner()).raw,
                6 => rep.enc_part = try EncryptedData.unmarshal(try field.inner()),
                else => {},
            }
        }
        return rep;
    }

    pub fn deinit(self: *TGSRep) void {
        if (self.cname.name_string.len > 0) self.cname.deinit(self.allocator);
        self.cname = .{ .name_type = 0, .name_string = &.{} };
    }
};

/// The decrypted EncKDCRepPart — we extract the fields needed to verify the
/// reply. String fields BORROW from the decrypted buffer.
pub const EncKDCRepPart = struct {
    nonce: i32 = 0,
    srealm: []const u8 = &.{},
    sname: ?PrincipalName = null,
    auth_time: i64 = 0,
    key: ?EncryptionKey = null,
    allocator: Allocator,

    /// Parse the decrypted EncKDCRepPart (APPLICATION[25] or [26]).
    pub fn unmarshal(allocator: Allocator, bytes: []const u8) Error!EncKDCRepPart {
        const r = der.read(bytes) catch return Error.MalformedASRep;
        if (r.elem.class != .application) return Error.MalformedASRep;
        // Some implementations tag this 26 even for AS-REP; accept 25 or 26.
        if (r.elem.tag_number != iana.asn_app_tag.enc_as_rep_part and
            r.elem.tag_number != iana.asn_app_tag.enc_tgs_rep_part)
        {
            return Error.MalformedASRep;
        }
        const seq = try r.elem.inner();
        var part = EncKDCRepPart{ .allocator = allocator };
        errdefer part.deinit();
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                0 => part.key = try EncryptionKey.unmarshal(try field.inner()),
                2 => part.nonce = try (try field.inner()).integer32(),
                5 => part.auth_time = try (try field.inner()).generalizedTime(),
                9 => part.srealm = (try field.inner()).bytes(),
                10 => part.sname = try PrincipalName.unmarshal(allocator, try field.inner()),
                else => {},
            }
        }
        return part;
    }

    pub fn deinit(self: *EncKDCRepPart) void {
        if (self.sname) |sn| {
            if (sn.name_string.len > 0) sn.deinit(self.allocator);
        }
        self.sname = null;
    }
};

const testing = std.testing;

test "isASRep / not-asrep detection" {
    try testing.expect(isASRep(&.{ 0x6B, 0x10 }));
    try testing.expect(!isASRep(&.{ 0x7E, 0x10 })); // KRB-ERROR
    try testing.expectError(Error.NotASRep, ASRep.unmarshal(testing.allocator, &.{ 0x7E, 0x02, 0x30, 0x00 }));
}

test "parse + key-derive + decrypt a real gokrb5 AS-REP" {
    const a = testing.allocator;
    const keys = @import("../crypto/keys.zig");
    const etype_mod = @import("../crypto/etype.zig");

    // AS-REP and key generated by gokrb5 (password "Sup3rSecret!", etype 18,
    // PA-ETYPE-INFO2 salt "EXAMPLE.COMtestuser-CUSTOMSALT").
    const asrep_hex = "6b82018630820182a003020105a10302010ba23830363034a103020113a22d042b30293027a003020112a1201b1e4558414d504c452e434f4d74657374757365722d435553544f4d53414c54a30d1b0b4558414d504c452e434f4da4153013a003020101a10c300a1b087465737475736572a54e614c304aa003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da3123010a003020112a103020101a2040402cafea681c53081c2a003020112a281ba0481b7b757a926def7d1287346bdf37885790880d05730056b00b2d7d7bc4c73fa7cda66c2afb0f089a83d6917d73960d60d2ca89184ffdc5bcaec95d0f25892a1bd725b0197e8e6f9e9bfdd54fbf4c8db321dac819a172b2edb155a660cb9f5c2fd6a4eebd5d101df076c34b15425246a7a6f9d9c54857587e20de79d2d3fe54b4f5002c2b170187274f63ef5150b9edf40ebad7bee04880f81cf4d37d84216f59c6ded22e0a2425d1873c2e238261d10ef25b1a51893d407fd";
    var asrep_buf: [512]u8 = undefined;
    const asrep_bytes = try std.fmt.hexToBytes(&asrep_buf, asrep_hex);

    var rep = try ASRep.unmarshal(a, asrep_bytes);
    defer rep.deinit();
    try testing.expectEqual(@as(i32, 11), rep.msg_type);
    try testing.expectEqualStrings("EXAMPLE.COM", rep.crealm);
    try testing.expectEqualStrings("testuser", rep.cname.name_string[0]);
    try testing.expectEqual(@as(i32, 18), rep.enc_part.etype);

    // Field [5] Ticket is captured raw and is itself parseable (this is the TGT
    // that a follow-up TGS-REQ re-embeds in its AP-REQ).
    const ticket_mod = @import("ticket.zig");
    try testing.expect(rep.ticket_raw.len > 0);
    var tgt = try ticket_mod.Ticket.unmarshal(a, rep.ticket_raw);
    defer tgt.deinit();
    try testing.expectEqualStrings("EXAMPLE.COM", tgt.realm);
    try testing.expectEqualStrings("krbtgt", tgt.sname.name_string[0]);

    // Derive the key from the password using the AS-REP's PA-DATA salt.
    const key = try keys.getKeyFromPassword(a, "Sup3rSecret!", rep.cname, rep.crealm, rep.enc_part.etype, rep.padata);
    defer a.free(key);
    var keyhex: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "aa46ac43a4818cd6ea812b3ed6917767a0ece11570ea4138c225b61cc653fbd8",
        try std.fmt.bufPrint(&keyhex, "{x}", .{key}),
    );

    // Decrypt the encrypted part (usage 3) and parse it.
    const plain = try etype_mod.decryptMessage(a, .aes256_cts_hmac_sha1_96, key, rep.enc_part.cipher, 3);
    defer a.free(plain);
    var part = try EncKDCRepPart.unmarshal(a, plain);
    defer part.deinit();
    try testing.expectEqual(@as(i32, 305419896), part.nonce);
    try testing.expectEqualStrings("EXAMPLE.COM", part.srealm);
    try testing.expectEqualStrings("krbtgt", part.sname.?.name_string[0]);
}
