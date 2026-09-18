//! A small native LDAP v3 client (RFC 4511) — bind, search and modify over
//! plain TCP. Dependency-free (std + the local BER codec) so it can be reused
//! independently of the Kerberos library. Used by kerbrutez for user sourcing,
//! UAC filtering, SPN enumeration and (targeted-roast) SPN write/restore.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = std.Io.net;
const ber = @import("ber.zig");

pub const ldap = @This();
pub const ber_codec = ber;

/// Largest single LDAP message we will accept from the server. One
/// SearchResultEntry is kilobytes; this is generous by orders of magnitude and
/// exists so a declared length cannot drive an unbounded allocation.
pub const max_message_bytes: usize = 16 * 1024 * 1024;
/// Caps on one search conversation, so a server cannot keep us in the read loop
/// forever (see `search`).
pub const max_messages: usize = 1_000_000;
pub const max_entries: usize = 500_000;

pub const Error = error{
    TooManyMessages,
    TooManyEntries,
    ConnectFailed,
    SendFailed,
    RecvFailed,
    MalformedResponse,
    BindFailed,
} || Allocator.Error || ber.Error;

/// LDAP search scopes.
pub const Scope = enum(i64) { base = 0, single_level = 1, whole_subtree = 2 };

/// AD userAccountControl flag bits we care about.
pub const uac = struct {
    pub const accountdisable: u32 = 0x0002;
    pub const lockout: u32 = 0x0010;
    pub const dont_expire_password: u32 = 0x10000;
    pub const trusted_for_delegation: u32 = 0x80000;
    pub const password_expired: u32 = 0x800000;
    pub const dont_require_preauth: u32 = 0x400000;
    pub const trusted_to_auth_for_delegation: u32 = 0x1000000;
};

pub const Attribute = struct {
    name: []u8,
    values: [][]u8,
};

pub const Entry = struct {
    dn: []u8,
    attributes: []Attribute,

    /// First value of `name` (case-insensitive attr match), or null.
    pub fn first(self: Entry, name: []const u8) ?[]const u8 {
        for (self.attributes) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, name) and attr.values.len > 0) return attr.values[0];
        }
        return null;
    }
    /// All values of `name`, or an empty slice.
    pub fn all(self: Entry, name: []const u8) [][]u8 {
        for (self.attributes) |attr| {
            if (std.ascii.eqlIgnoreCase(attr.name, name)) return attr.values;
        }
        return &.{};
    }
};

/// A set of parsed entries owning all their memory (free with `deinit`).
pub const SearchResult = struct {
    allocator: Allocator,
    entries: []Entry,
    result_code: i64,

    pub fn deinit(self: SearchResult) void {
        for (self.entries) |e| {
            self.allocator.free(e.dn);
            for (e.attributes) |attr| {
                self.allocator.free(attr.name);
                for (attr.values) |v| self.allocator.free(v);
                self.allocator.free(attr.values);
            }
            self.allocator.free(e.attributes);
        }
        self.allocator.free(self.entries);
    }
};

pub const Client = struct {
    io: Io,
    allocator: Allocator,
    stream: net.Stream,
    reader: net.Stream.Reader = undefined,
    writer: net.Stream.Writer = undefined,
    rbuf: [16384]u8 = undefined,
    wbuf: [16384]u8 = undefined,
    msg_id: i32 = 0,
    open: bool = false,

    /// Initialise `self` in place by connecting to `host:port` (plain LDAP).
    /// The client stores a streaming reader referencing its own buffers, so it
    /// MUST live at a stable address (pass a pointer to fixed storage).
    pub fn connect(self: *Client, io: Io, allocator: Allocator, host: []const u8, port: u16) Error!void {
        const addr = net.IpAddress.resolve(io, host, port) catch return Error.ConnectFailed;
        self.* = .{
            .io = io,
            .allocator = allocator,
            .stream = net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp }) catch return Error.ConnectFailed,
            .msg_id = 0,
            .open = true,
        };
        self.reader = self.stream.reader(io, &self.rbuf);
        self.writer = self.stream.writer(io, &self.wbuf);
    }

    pub fn deinit(self: *Client) void {
        if (self.open) {
            self.unbind() catch {};
            self.stream.close(self.io);
            self.open = false;
        }
    }

    fn nextId(self: *Client) i32 {
        self.msg_id += 1;
        return self.msg_id;
    }

    fn sendMessage(self: *Client, bytes: []const u8) Error!void {
        self.writer.interface.writeAll(bytes) catch return Error.SendFailed;
        self.writer.interface.flush() catch return Error.SendFailed;
    }

    /// Read exactly one LDAPMessage (framed by its BER length).
    /// OWNERSHIP: caller frees.
    fn readMessage(self: *Client, allocator: Allocator) Error![]u8 {
        var header: [10]u8 = undefined;
        self.reader.interface.readSliceAll(header[0..2]) catch return Error.RecvFailed;
        var header_len: usize = 2;
        var body_len: usize = 0;
        if (header[1] < 0x80) {
            body_len = header[1];
        } else {
            const count: usize = header[1] & 0x7F;
            if (count == 0 or count > 8) return Error.MalformedResponse;
            self.reader.interface.readSliceAll(header[2 .. 2 + count]) catch return Error.RecvFailed;
            header_len = 2 + count;
            var i: usize = 0;
            while (i < count) : (i += 1) body_len = (body_len << 8) | header[2 + i];
        }
        // SAME OVERFLOW CLASS as the DER/BER length check: `body_len` is up to
        // eight bytes chosen by whatever host --ldap-server points at, so
        // `header_len + body_len` can wrap. In ReleaseFast (checks removed) a
        // wrapped `total` smaller than `header_len` makes `out[header_len..]`
        // a slice whose start is past its end. Cap first, THEN add.
        if (body_len > max_message_bytes) return Error.MalformedResponse;
        const total = header_len + body_len;
        const out = try allocator.alloc(u8, total);
        errdefer allocator.free(out);
        @memcpy(out[0..header_len], header[0..header_len]);
        self.reader.interface.readSliceAll(out[header_len..]) catch return Error.RecvFailed;
        return out;
    }

    /// Simple bind. Empty `name`/`password` = anonymous (null) bind.
    /// Returns the LDAP resultCode (0 = success).
    pub fn bind(self: *Client, name: []const u8, password: []const u8) Error!i64 {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const id = self.nextId();

        const version = try ber.integer(a, 3);
        const dn = try ber.octetString(a, name);
        const auth = try ber.contextPrimitive(a, 0, password); // simple [0]
        const bind_req = try ber.application(a, 0, &.{ version, dn, auth }); // BindRequest [APP 0]
        const msg_id = try ber.integer(a, id);
        const message = try ber.sequence(a, &.{ msg_id, bind_req });

        try self.sendMessage(message);

        const resp = try self.readMessage(a);
        // SEQUENCE { messageID, [APPLICATION 1] BindResponse { resultCode ENUMERATED, ... } }
        const top = (try ber.read(resp)).elem;
        var it = top.iterator();
        _ = try it.next(); // messageID
        const op = (try it.next()) orelse return Error.MalformedResponse;
        var op_it = op.iterator();
        const rc = (try op_it.next()) orelse return Error.MalformedResponse;
        return rc.integer() catch Error.MalformedResponse;
    }

    /// Unbind and signal the server we're done.
    pub fn unbind(self: *Client) Error!void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const id = self.nextId();
        const msg_id = try ber.integer(a, id);
        // UnbindRequest is [APPLICATION 2] NULL (primitive, empty).
        const unbind_req = try ber.tlv(a, 0x42, &.{});
        const message = try ber.sequence(a, &.{ msg_id, unbind_req });
        try self.sendMessage(message);
    }

    /// Perform a search. `filter` is pre-encoded BER (see the filter helpers).
    /// OWNERSHIP: caller frees the returned `SearchResult`.
    pub fn search(self: *Client, base: []const u8, scope: Scope, filter: []const u8, attributes: []const []const u8) Error!SearchResult {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const id = self.nextId();

        const base_os = try ber.octetString(a, base);
        const scope_e = try ber.enumerated(a, @intFromEnum(scope));
        const deref = try ber.enumerated(a, 0); // neverDerefAliases
        const size_limit = try ber.integer(a, 0);
        const time_limit = try ber.integer(a, 0);
        const types_only = try ber.boolean(a, false);

        var attr_elems: std.ArrayList([]u8) = .empty;
        for (attributes) |attr| try attr_elems.append(a, try ber.octetString(a, attr));
        const attr_seq = try ber.sequence(a, attr_elems.items);

        const search_req = try ber.application(a, 3, &.{ base_os, scope_e, deref, size_limit, time_limit, types_only, filter, attr_seq });
        const msg_id = try ber.integer(a, id);
        const message = try ber.sequence(a, &.{ msg_id, search_req });

        try self.sendMessage(message);

        var entries: std.ArrayList(Entry) = .empty;
        errdefer {
            for (entries.items) |e| freeEntry(self.allocator, e);
            entries.deinit(self.allocator);
        }
        var result_code: i64 = 0;
        // BOUND THE CONVERSATION. This loop only ended on SearchResultDone, so a
        // server that streams entries forever — or just keeps sending tags that
        // fall through to `else` below — span it indefinitely with no error and,
        // in the `else` case, no memory growth to trip anything. Same shape as
        // the wizard's unbounded prompt loop; the server here is a host on the
        // target network, not something we control.
        var messages: usize = 0;
        while (true) {
            messages += 1;
            if (messages > max_messages) return Error.TooManyMessages;
            if (entries.items.len > max_entries) return Error.TooManyEntries;
            const resp = try self.readMessage(a); // arena-owned (freed at deinit)
            const top = (try ber.read(resp)).elem;
            var it = top.iterator();
            _ = try it.next(); // messageID
            const op = (try it.next()) orelse return Error.MalformedResponse;
            switch (op.tag_number) {
                4 => { // SearchResultEntry
                    const entry = try parseEntry(self.allocator, op);
                    try entries.append(self.allocator, entry);
                },
                5 => { // SearchResultDone
                    var op_it = op.iterator();
                    const rc = (try op_it.next()) orelse return Error.MalformedResponse;
                    result_code = rc.integer() catch 0;
                    break;
                },
                else => {}, // SearchResultReference etc. — ignore
            }
        }
        return .{ .allocator = self.allocator, .entries = try entries.toOwnedSlice(self.allocator), .result_code = result_code };
    }

    pub const ModOp = enum(i64) { add = 0, delete = 1, replace = 2 };

    /// Modify one attribute on `dn`. Used for targeted-roast SPN write/restore.
    /// `values` empty with `.replace` clears the attribute. Returns resultCode.
    pub fn modify(self: *Client, dn: []const u8, op: ModOp, attr: []const u8, values: []const []const u8) Error!i64 {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const id = self.nextId();

        const attr_type = try ber.octetString(a, attr);
        var vals: std.ArrayList([]u8) = .empty;
        for (values) |v| try vals.append(a, try ber.octetString(a, v));
        const vals_set = try ber.set(a, vals.items);
        const partial_attr = try ber.sequence(a, &.{ attr_type, vals_set });
        const op_e = try ber.enumerated(a, @intFromEnum(op));
        const change = try ber.sequence(a, &.{ op_e, partial_attr });
        const changes = try ber.sequence(a, &.{change});
        const obj = try ber.octetString(a, dn);
        const modify_req = try ber.application(a, 6, &.{ obj, changes });
        const msg_id = try ber.integer(a, id);
        const message = try ber.sequence(a, &.{ msg_id, modify_req });

        try self.sendMessage(message);
        const resp = try self.readMessage(a);
        const top = (try ber.read(resp)).elem;
        var it = top.iterator();
        _ = try it.next();
        const opr = (try it.next()) orelse return Error.MalformedResponse;
        var op_it = opr.iterator();
        const rc = (try op_it.next()) orelse return Error.MalformedResponse;
        return rc.integer() catch Error.MalformedResponse;
    }
};

fn freeEntry(allocator: Allocator, e: Entry) void {
    allocator.free(e.dn);
    for (e.attributes) |attr| {
        allocator.free(attr.name);
        for (attr.values) |v| allocator.free(v);
        allocator.free(attr.values);
    }
    allocator.free(e.attributes);
}

/// Parse a SearchResultEntry [APP 4] into an owned Entry.
fn parseEntry(allocator: Allocator, op: ber.Element) Error!Entry {
    var it = op.iterator();
    const dn_elem = (try it.next()) orelse return Error.MalformedResponse;
    const dn = try allocator.dupe(u8, dn_elem.bytes());
    errdefer allocator.free(dn);

    var attrs: std.ArrayList(Attribute) = .empty;
    errdefer {
        for (attrs.items) |attr| {
            allocator.free(attr.name);
            for (attr.values) |v| allocator.free(v);
            allocator.free(attr.values);
        }
        attrs.deinit(allocator);
    }
    const attr_list = (try it.next()) orelse return .{ .dn = dn, .attributes = try attrs.toOwnedSlice(allocator) };
    var al_it = attr_list.iterator();
    while (try al_it.next()) |attr_seq| {
        var ai = attr_seq.iterator();
        const type_elem = (try ai.next()) orelse continue;
        const name = try allocator.dupe(u8, type_elem.bytes());
        errdefer allocator.free(name);
        var values: std.ArrayList([]u8) = .empty;
        errdefer {
            for (values.items) |v| allocator.free(v);
            values.deinit(allocator);
        }
        if (try ai.next()) |vals_set| {
            var vi = vals_set.iterator();
            while (try vi.next()) |val| try values.append(allocator, try allocator.dupe(u8, val.bytes()));
        }
        try attrs.append(allocator, .{ .name = name, .values = try values.toOwnedSlice(allocator) });
    }
    return .{ .dn = dn, .attributes = try attrs.toOwnedSlice(allocator) };
}

// ---- Filter builders (return arena-owned BER) ----

/// `(attr=*)` presence filter [7].
pub fn filterPresent(allocator: Allocator, attr: []const u8) ![]u8 {
    return ber.contextPrimitive(allocator, 7, attr);
}

/// `(attr=value)` equality filter [3]. Self-contained (frees its intermediates).
pub fn filterEquality(allocator: Allocator, attr: []const u8, value: []const u8) ![]u8 {
    const a = try ber.octetString(allocator, attr);
    defer allocator.free(a);
    const v = try ber.octetString(allocator, value);
    defer allocator.free(v);
    return ber.context(allocator, 3, &.{ a, v });
}

/// AND of sub-filters [0].
pub fn filterAnd(allocator: Allocator, filters: []const []const u8) ![]u8 {
    return ber.context(allocator, 0, filters);
}

/// OR of sub-filters [1].
pub fn filterOr(allocator: Allocator, filters: []const []const u8) ![]u8 {
    return ber.context(allocator, 1, filters);
}

/// Derive the default naming context "DC=a,DC=b,DC=c" from a dotted domain.
/// OWNERSHIP: caller frees.
pub fn baseDnFromDomain(allocator: Allocator, domain: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var it = std.mem.tokenizeScalar(u8, domain, '.');
    var firstpart = true;
    while (it.next()) |part| {
        if (!firstpart) try out.append(allocator, ',');
        firstpart = false;
        try out.appendSlice(allocator, "DC=");
        try out.appendSlice(allocator, part);
    }
    return out.toOwnedSlice(allocator);
}

const testing = std.testing;

test "baseDnFromDomain" {
    const a = testing.allocator;
    const dn = try baseDnFromDomain(a, "corp.example.com");
    defer a.free(dn);
    try testing.expectEqualStrings("DC=corp,DC=example,DC=com", dn);
}

test "filter builders produce well-formed BER" {
    const a = testing.allocator;
    const p = try filterPresent(a, "servicePrincipalName");
    defer a.free(p);
    try testing.expectEqual(@as(u8, 0x87), p[0]); // [7] primitive
    const eq = try filterEquality(a, "sAMAccountName", "jon");
    defer a.free(eq);
    try testing.expectEqual(@as(u8, 0xA3), eq[0]); // [3] constructed
    const andf = try filterAnd(a, &.{ p, eq });
    defer a.free(andf);
    try testing.expectEqual(@as(u8, 0xA0), andf[0]); // [0] constructed
}
