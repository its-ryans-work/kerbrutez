//! RFC 4120 §5.3 Ticket (APPLICATION[1]).
//!
//! A Ticket is carried opaquely inside AS-REP/TGS-REP (field [5]). We parse it
//! for two purposes:
//!   * the TGT from an AS-REP — its raw bytes are re-embedded in the AP-REQ of a
//!     subsequent TGS-REQ;
//!   * the service ticket from a TGS-REP — its `enc-part` is the kerberoast
//!     material (encrypted with the service account's long-term key), which we
//!     format as a `$krb5tgs$` hash.
//!
//! We never decrypt `enc-part`; we only need its etype + cipher for the hash.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");
const iana = @import("../iana/constants.zig");
const PrincipalName = @import("../types/principal_name.zig").PrincipalName;
const EncryptedData = @import("../types/encrypted_data.zig").EncryptedData;

pub const Error = error{ NotATicket, MalformedTicket, MalformedPrincipalName } || der.Error || Allocator.Error;

/// A parsed Kerberos Ticket. `sname` is OWNED (free with `deinit`); `realm` and
/// `enc_part.cipher` BORROW from the source buffer, which must outlive this.
pub const Ticket = struct {
    allocator: Allocator,
    tkt_vno: i32 = 0,
    realm: []const u8 = &.{},
    sname: PrincipalName = .{ .name_type = 0, .name_string = &.{} },
    enc_part: EncryptedData = .{ .etype = 0, .cipher = &.{} },

    /// Parse a Ticket from wire bytes (APPLICATION[1]).
    pub fn unmarshal(allocator: Allocator, bytes: []const u8) Error!Ticket {
        const r = der.read(bytes) catch return Error.NotATicket;
        if (r.elem.class != .application or r.elem.tag_number != iana.asn_app_tag.ticket) {
            return Error.NotATicket;
        }
        const seq = try r.elem.inner();
        var t = Ticket{ .allocator = allocator };
        errdefer t.deinit();
        var it = seq.iterator();
        while (try it.next()) |field| {
            switch (field.tag_number) {
                0 => t.tkt_vno = try (try field.inner()).integer32(),
                1 => t.realm = (try field.inner()).bytes(),
                2 => t.sname = try PrincipalName.unmarshal(allocator, try field.inner()),
                3 => t.enc_part = try EncryptedData.unmarshal(try field.inner()),
                else => {},
            }
        }
        if (t.tkt_vno != 0 and t.tkt_vno != iana.pvno) return Error.MalformedTicket;
        return t;
    }

    pub fn deinit(self: *Ticket) void {
        if (self.sname.name_string.len > 0) self.sname.deinit(self.allocator);
        self.sname = .{ .name_type = 0, .name_string = &.{} };
    }

    /// The SPN as "a/b/..." (the sname components joined by '/'), e.g.
    /// "krbtgt/EXAMPLE.COM" or "MSSQLSvc/host.dom:1433". OWNERSHIP: caller frees.
    pub fn spnString(self: Ticket, allocator: Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (self.sname.name_string, 0..) |part, i| {
            if (i > 0) try out.append(allocator, '/');
            try out.appendSlice(allocator, part);
        }
        return out.toOwnedSlice(allocator);
    }
};

const testing = std.testing;

test "parse a real TGT (Ticket) extracted from a gokrb5 AS-REP" {
    const a = testing.allocator;
    // The [5] Ticket from the AS-REP test vector in kdc_rep.zig: APPLICATION[1]
    // SEQUENCE { tkt-vno 5, realm EXAMPLE.COM, sname krbtgt/EXAMPLE.COM,
    // enc-part EncryptedData(etype 18) }.
    const tkt_hex = "614c304aa003020105a10d1b0b4558414d504c452e434f4da220301ea003020102a11730151b066b72627467741b0b4558414d504c452e434f4da3123010a003020112a103020101a2040402cafe";
    var buf: [256]u8 = undefined;
    const bytes = try std.fmt.hexToBytes(&buf, tkt_hex);

    var t = try Ticket.unmarshal(a, bytes);
    defer t.deinit();
    try testing.expectEqual(@as(i32, 5), t.tkt_vno);
    try testing.expectEqualStrings("EXAMPLE.COM", t.realm);
    try testing.expectEqual(@as(usize, 2), t.sname.name_string.len);
    try testing.expectEqualStrings("krbtgt", t.sname.name_string[0]);
    try testing.expectEqual(@as(i32, 18), t.enc_part.etype);

    const spn = try t.spnString(a);
    defer a.free(spn);
    try testing.expectEqualStrings("krbtgt/EXAMPLE.COM", spn);
}

test "reject a non-Ticket element" {
    try testing.expectError(Error.NotATicket, Ticket.unmarshal(testing.allocator, &.{ 0x6B, 0x02, 0x30, 0x00 }));
}
