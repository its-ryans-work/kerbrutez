//! RFC 4120 §5.2.2 PrincipalName.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("../asn1/der.zig");

pub const PrincipalName = struct {
    name_type: i32,
    /// The name components. BORROW for constructed values; OWNED (allocated)
    /// when produced by `unmarshal` (free with `deinit`).
    name_string: []const []const u8,

    /// DER-encode as SEQUENCE { [0] INTEGER, [1] SEQUENCE OF GeneralString }.
    /// OWNERSHIP: caller frees.
    pub fn marshal(self: PrincipalName, allocator: Allocator) ![]u8 {
        const nt = try der.encodeInt(allocator, self.name_type);
        defer allocator.free(nt);
        const field0 = try der.explicit(allocator, 0, nt);
        defer allocator.free(field0);

        var gs_list: std.ArrayList([]u8) = .empty;
        defer {
            for (gs_list.items) |g| allocator.free(g);
            gs_list.deinit(allocator);
        }
        for (self.name_string) |n| {
            try gs_list.append(allocator, try der.encodeGeneralString(allocator, n));
        }
        const seq_of = try der.sequence(allocator, gs_list.items);
        defer allocator.free(seq_of);
        const field1 = try der.explicit(allocator, 1, seq_of);
        defer allocator.free(field1);

        return der.sequence(allocator, &.{ field0, field1 });
    }

    /// Parse a PrincipalName from its SEQUENCE element. OWNERSHIP: the returned
    /// value owns `name_string`; free with `deinit`.
    pub fn unmarshal(allocator: Allocator, seq: der.Element) !PrincipalName {
        var it = seq.iterator();
        const f0 = (try it.next()) orelse return error.MalformedPrincipalName;
        const name_type = try (try f0.inner()).integer32();
        const f1 = (try it.next()) orelse return error.MalformedPrincipalName;
        const seq_of = try f1.inner();

        var names: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (names.items) |n| allocator.free(n);
            names.deinit(allocator);
        }
        var sit = seq_of.iterator();
        while (try sit.next()) |gs| {
            try names.append(allocator, try allocator.dupe(u8, gs.bytes()));
        }
        return .{ .name_type = name_type, .name_string = try names.toOwnedSlice(allocator) };
    }

    pub fn deinit(self: PrincipalName, allocator: Allocator) void {
        for (self.name_string) |n| allocator.free(n);
        allocator.free(self.name_string);
    }

    /// The default Kerberos salt for this principal: realm ++ each component.
    /// OWNERSHIP: caller frees.
    pub fn getSalt(self: PrincipalName, allocator: Allocator, realm: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, realm);
        for (self.name_string) |n| try out.appendSlice(allocator, n);
        return out.toOwnedSlice(allocator);
    }

    /// The principal name joined with "/". OWNERSHIP: caller frees.
    pub fn principalNameString(self: PrincipalName, allocator: Allocator) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        for (self.name_string, 0..) |n, i| {
            if (i != 0) try out.append(allocator, '/');
            try out.appendSlice(allocator, n);
        }
        return out.toOwnedSlice(allocator);
    }

    /// Compare two principal names for equality of components (name_type is
    /// not significant per RFC 4120 §6.2).
    pub fn eql(self: PrincipalName, other: PrincipalName) bool {
        if (self.name_string.len != other.name_string.len) return false;
        for (self.name_string, other.name_string) |a, b| {
            if (!std.mem.eql(u8, a, b)) return false;
        }
        return true;
    }
};

const testing = std.testing;

test "PrincipalName marshal/unmarshal round trip" {
    const a = testing.allocator;
    const pn = PrincipalName{ .name_type = 2, .name_string = &.{ "krbtgt", "EXAMPLE.COM" } };
    const bytes = try pn.marshal(a);
    defer a.free(bytes);

    const r = try der.read(bytes);
    const parsed = try PrincipalName.unmarshal(a, r.elem);
    defer parsed.deinit(a);
    try testing.expectEqual(@as(i32, 2), parsed.name_type);
    try testing.expect(parsed.eql(pn));

    const salt = try pn.getSalt(a, "EXAMPLE.COM");
    defer a.free(salt);
    try testing.expectEqualStrings("EXAMPLE.COMkrbtgtEXAMPLE.COM", salt);

    const s = try pn.principalNameString(a);
    defer a.free(s);
    try testing.expectEqualStrings("krbtgt/EXAMPLE.COM", s);
}
