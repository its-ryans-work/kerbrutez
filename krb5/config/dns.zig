//! Minimal DNS SRV resolver for locating KDCs when no `--dc` is given.
//! Queries `_kerberos._udp.<REALM>` / `_kerberos._tcp.<REALM>` and returns the
//! targets ordered by SRV priority (then weight), matching gokrb5's
//! Config.GetKDCs DNS path.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = std.Io.net;

pub const Error = error{
    NoNameserver,
    QueryFailed,
    NoRecords,
    MalformedResponse,
} || Allocator.Error;

const srv_type: u16 = 33;
const a_type: u16 = 1;
const ptr_type: u16 = 12;
const class_in: u16 = 1;

const SrvRecord = struct { priority: u16, weight: u16, port: u16, target: []u8 };

/// Look up KDC SRV records for `realm`. `dns_server` overrides the resolver
/// (e.g. point at the AD DNS); when null, /etc/resolv.conf is read. We try the
/// standard `_kerberos._<proto>.<realm>` then the AD-specific
/// `_kerberos._<proto>.dc._msdcs.<realm>`. OWNERSHIP: caller frees the slice and
/// each "host:port" string.
pub fn lookupKDCs(allocator: Allocator, io: Io, realm: []const u8, use_tcp: bool, dns_server: ?[]const u8) Error![][]const u8 {
    const proto = if (use_tcp) "tcp" else "udp";

    const server = if (dns_server) |s| try allocator.dupe(u8, s) else try readNameserver(allocator, io);
    defer allocator.free(server);

    // Standard SRV first, then the AD DC _msdcs variant.
    const std_q = try std.fmt.allocPrint(allocator, "_kerberos._{s}.{s}", .{ proto, realm });
    defer allocator.free(std_q);
    const msdcs_q = try std.fmt.allocPrint(allocator, "_kerberos._{s}.dc._msdcs.{s}", .{ proto, realm });
    defer allocator.free(msdcs_q);

    var records = lookupOne(allocator, io, server, std_q) catch std.ArrayList(SrvRecord).empty;
    if (records.items.len == 0) {
        records.deinit(allocator);
        records = lookupOne(allocator, io, server, msdcs_q) catch return Error.NoRecords;
    }
    defer {
        for (records.items) |rec| allocator.free(rec.target);
        records.deinit(allocator);
    }
    if (records.items.len == 0) return Error.NoRecords;

    // Order by priority ascending, then weight descending.
    std.mem.sort(SrvRecord, records.items, {}, struct {
        fn lessThan(_: void, a: SrvRecord, b: SrvRecord) bool {
            if (a.priority != b.priority) return a.priority < b.priority;
            return a.weight > b.weight;
        }
    }.lessThan);

    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |s| allocator.free(s);
        out.deinit(allocator);
    }
    for (records.items) |r| {
        const host = std.mem.trimEnd(u8, r.target, ".");
        try out.append(allocator, try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, r.port }));
    }
    return out.toOwnedSlice(allocator);
}

/// Resolve `host` to an IPv4 address via a DNS A query, with `port` set on the
/// result. Uses `dns_server` when given (e.g. the AD DNS via --dns), otherwise
/// the first nameserver in /etc/resolv.conf. This exists because
/// std.Io.net.IpAddress.resolve only parses IP literals — it does NOT do DNS —
/// so a KDC hostname (a typed --dc or an SRV target) must be resolved here.
/// OWNERSHIP: returns a value; nothing to free.
pub fn resolveHost(allocator: Allocator, io: Io, host: []const u8, port: u16, dns_server: ?[]const u8) Error!net.IpAddress {
    const server = if (dns_server) |s| try allocator.dupe(u8, s) else try readNameserver(allocator, io);
    defer allocator.free(server);
    const response = try query(allocator, io, server, host, a_type);
    defer allocator.free(response);
    return parseFirstA(response, port) orelse Error.NoRecords;
}

/// The system hosts file, which the OS resolver consults BEFORE DNS.
pub const hosts_path = if (@import("builtin").os.tag == .windows)
    "C:\\Windows\\System32\\drivers\\etc\\hosts"
else
    "/etc/hosts";

/// Resolve `host` from the system hosts file, or null if it isn't there.
///
/// We issue raw DNS queries rather than calling the OS resolver (std.Io.net in
/// Zig 0.16 has no DNS), which means /etc/hosts was invisible to us — yet
/// pinning a target in /etc/hosts is routine on an engagement (the target's own
/// DNS is often unreachable, or the operator wants a name to point somewhere
/// specific). Without this, `--dc dc01.corp.local`, `--socks proxy.local` and
/// hostname webhooks all fail for a host the rest of the system resolves fine.
/// Checked before DNS, matching the usual nsswitch order.
pub fn lookupHostsFile(allocator: Allocator, io: Io, host: []const u8, port: u16) ?net.IpAddress {
    return lookupHostsFileAt(allocator, io, hosts_path, host, port);
}

/// `lookupHostsFile` against an explicit path, so the file-reading half can be
/// tested without depending on the machine's real /etc/hosts.
pub fn lookupHostsFileAt(allocator: Allocator, io: Io, path: []const u8, host: []const u8, port: u16) ?net.IpAddress {
    var file = Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    const content = reader.interface.allocRemaining(allocator, .unlimited) catch return null;
    defer allocator.free(content);
    return parseHostsFile(content, host, port);
}

/// Find `host` among a hosts-file body. Format per line:
///   <ip> <canonical-name> [aliases...]   # comment
/// Host matching is case-insensitive (DNS names are). Only IPv4 is returned,
/// matching the A-record path used everywhere else.
fn parseHostsFile(content: []const u8, host: []const u8, port: u16) ?net.IpAddress {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |raw| {
        const no_comment = if (std.mem.indexOfScalar(u8, raw, '#')) |h| raw[0..h] else raw;
        var fields = std.mem.tokenizeAny(u8, no_comment, " \t\r");
        const ip = fields.next() orelse continue;
        while (fields.next()) |name| {
            if (!std.ascii.eqlIgnoreCase(name, host)) continue;
            // Skip IPv6 entries (e.g. the `::1 localhost` line every hosts file
            // has). The DNS path here resolves A records only, so handing back a
            // v6 address for a name that also has a v4 entry would fail to
            // connect against an IPv4-only KDC — keep the two paths consistent.
            const addr = net.IpAddress.parse(ip, port) catch continue;
            switch (addr) {
                .ip4 => return addr,
                .ip6 => continue,
            }
        }
    }
    return null;
}

/// Reverse-DNS (PTR) lookup of an IPv4 dotted string → the FQDN it maps to
/// (e.g. "10.0.0.10" → "dc01.corp.local"), or null on any failure. Uses
/// `dns_server` when given, else /etc/resolv.conf. OWNERSHIP: caller frees.
pub fn reverseLookup(allocator: Allocator, io: Io, ipv4: []const u8, dns_server: ?[]const u8) ?[]u8 {
    // Build the reverse name "d.c.b.a.in-addr.arpa" from "a.b.c.d".
    var parts: [4][]const u8 = undefined;
    var it = std.mem.splitScalar(u8, ipv4, '.');
    var n: usize = 0;
    while (it.next()) |p| {
        if (n >= 4 or p.len == 0) return null;
        for (p) |c| if (c < '0' or c > '9') return null;
        parts[n] = p;
        n += 1;
    }
    if (n != 4) return null;
    const qname = std.fmt.allocPrint(allocator, "{s}.{s}.{s}.{s}.in-addr.arpa", .{ parts[3], parts[2], parts[1], parts[0] }) catch return null;
    defer allocator.free(qname);

    const server = if (dns_server) |s| (allocator.dupe(u8, s) catch return null) else (readNameserver(allocator, io) catch return null);
    defer allocator.free(server);
    const response = query(allocator, io, server, qname, ptr_type) catch return null;
    defer allocator.free(response);
    return parseFirstPtr(allocator, response);
}

/// Return the name in the first PTR answer (e.g. "dc01.corp.local"), or null.
fn parseFirstPtr(allocator: Allocator, msg: []const u8) ?[]u8 {
    if (msg.len < 12) return null;
    const qd = readU16(msg, 4);
    const an = readU16(msg, 6);
    var off: usize = 12;
    var qi: usize = 0;
    while (qi < qd) : (qi += 1) {
        off = skipName(msg, off) orelse return null;
        off += 4; // QTYPE + QCLASS
    }
    var ai: usize = 0;
    while (ai < an) : (ai += 1) {
        off = skipName(msg, off) orelse return null;
        if (off + 10 > msg.len) return null;
        const rtype = readU16(msg, off);
        const rdlength = readU16(msg, off + 8);
        off += 10;
        if (off + rdlength > msg.len) return null;
        if (rtype == ptr_type) return readName(allocator, msg, off) catch null;
        off += rdlength;
    }
    return null;
}

/// Query one SRV name and parse the records. OWNERSHIP: caller deinits the list
/// and frees each `target`.
fn lookupOne(allocator: Allocator, io: Io, server: []const u8, qname: []const u8) Error!std.ArrayList(SrvRecord) {
    const response = try query(allocator, io, server, qname, srv_type);
    defer allocator.free(response);
    return parseSrvRecords(allocator, response);
}

/// Read the first `nameserver` from /etc/resolv.conf. OWNERSHIP: caller frees.
fn readNameserver(allocator: Allocator, io: Io) Error![]u8 {
    var file = Io.Dir.openFileAbsolute(io, "/etc/resolv.conf", .{}) catch return Error.NoNameserver;
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var reader = file.reader(io, &buf);
    const content = reader.interface.allocRemaining(allocator, .unlimited) catch return Error.NoNameserver;
    defer allocator.free(content);

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (std.mem.startsWith(u8, trimmed, "nameserver")) {
            var parts = std.mem.tokenizeAny(u8, trimmed["nameserver".len..], " \t");
            if (parts.next()) |ns| return allocator.dupe(u8, ns);
        }
    }
    return Error.NoNameserver;
}

/// Build a DNS query, send it over UDP to `server:53`, and return the response.
/// OWNERSHIP: caller frees.
fn query(allocator: Allocator, io: Io, server: []const u8, qname: []const u8, qtype: u16) Error![]u8 {
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(allocator);
    // Header: id, flags (RD=1), qd=1, others 0.
    var idb: [2]u8 = undefined;
    @import("../crypto/rng.zig").bytes(io, &idb) catch {
        idb = .{ 0x13, 0x37 };
    };
    try msg.appendSlice(allocator, &idb);
    try msg.appendSlice(allocator, &[_]u8{ 0x01, 0x00 }); // flags: RD
    try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x01 }); // QDCOUNT=1
    try msg.appendSlice(allocator, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }); // AN/NS/AR=0
    // QNAME labels.
    var labels = std.mem.tokenizeScalar(u8, qname, '.');
    while (labels.next()) |label| {
        try msg.append(allocator, @intCast(label.len));
        try msg.appendSlice(allocator, label);
    }
    try msg.append(allocator, 0); // root
    try msg.appendSlice(allocator, &[_]u8{ @intCast(qtype >> 8), @intCast(qtype & 0xFF) });
    try msg.appendSlice(allocator, &[_]u8{ @intCast(class_in >> 8), @intCast(class_in & 0xFF) });

    // The nameserver itself may be given by NAME (--dns dc01, or a hostname in
    // resolv.conf). IpAddress.resolve only parses literals, so fall back to the
    // hosts file — but NOT to a DNS lookup, which is what this function is.
    const addr = net.IpAddress.resolve(io, server, 53) catch
        lookupHostsFile(allocator, io, server, 53) orelse return Error.QueryFailed;
    const family_unspec: net.IpAddress = switch (addr) {
        .ip4 => .{ .ip4 = net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = net.Ip6Address.unspecified(0) },
    };
    var sock = net.IpAddress.bind(&family_unspec, io, .{ .mode = .dgram, .protocol = .udp }) catch return Error.QueryFailed;
    defer sock.close(io);
    sock.send(io, &addr, msg.items) catch return Error.QueryFailed;
    const timeout: Io.Timeout = .{ .duration = .{ .raw = Io.Duration.fromSeconds(5), .clock = .awake } };
    var rbuf: [4096]u8 = undefined;
    const incoming = sock.receiveTimeout(io, &rbuf, timeout) catch return Error.QueryFailed;
    return allocator.dupe(u8, incoming.data);
}

/// Parse SRV records from a DNS response message.
fn parseSrvRecords(allocator: Allocator, msg: []const u8) Error!std.ArrayList(SrvRecord) {
    var records: std.ArrayList(SrvRecord) = .empty;
    errdefer {
        for (records.items) |r| allocator.free(r.target);
        records.deinit(allocator);
    }
    if (msg.len < 12) return Error.MalformedResponse;
    const qd = readU16(msg, 4);
    const an = readU16(msg, 6);

    var off: usize = 12;
    // Skip questions.
    var i: usize = 0;
    while (i < qd) : (i += 1) {
        off = skipName(msg, off) orelse return Error.MalformedResponse;
        off += 4; // QTYPE + QCLASS
    }
    // Answers.
    i = 0;
    while (i < an) : (i += 1) {
        off = skipName(msg, off) orelse return Error.MalformedResponse;
        if (off + 10 > msg.len) return Error.MalformedResponse;
        const rtype = readU16(msg, off);
        const rdlength = readU16(msg, off + 8);
        off += 10;
        if (off + rdlength > msg.len) return Error.MalformedResponse;
        if (rtype == srv_type and rdlength >= 6) {
            const priority = readU16(msg, off);
            const weight = readU16(msg, off + 2);
            const port = readU16(msg, off + 4);
            const target = try readName(allocator, msg, off + 6);
            try records.append(allocator, .{ .priority = priority, .weight = weight, .port = port, .target = target });
        }
        off += rdlength;
    }
    return records;
}

/// Return the first A record in a DNS response as an IPv4 address with `port`,
/// or null if there's none. Skips CNAMEs / other RR types.
fn parseFirstA(msg: []const u8, port: u16) ?net.IpAddress {
    if (msg.len < 12) return null;
    const qd = readU16(msg, 4);
    const an = readU16(msg, 6);
    var off: usize = 12;
    var qi: usize = 0;
    while (qi < qd) : (qi += 1) {
        off = skipName(msg, off) orelse return null;
        off += 4; // QTYPE + QCLASS
    }
    var ai: usize = 0;
    while (ai < an) : (ai += 1) {
        off = skipName(msg, off) orelse return null;
        if (off + 10 > msg.len) return null;
        const rtype = readU16(msg, off);
        const rdlength = readU16(msg, off + 8);
        off += 10;
        if (off + rdlength > msg.len) return null;
        if (rtype == a_type and rdlength == 4) {
            return .{ .ip4 = .{ .bytes = .{ msg[off], msg[off + 1], msg[off + 2], msg[off + 3] }, .port = port } };
        }
        off += rdlength;
    }
    return null;
}

fn readU16(msg: []const u8, off: usize) u16 {
    return (@as(u16, msg[off]) << 8) | msg[off + 1];
}

/// Skip a (possibly compressed) DNS name; returns the offset after it.
fn skipName(msg: []const u8, start: usize) ?usize {
    var off = start;
    while (off < msg.len) {
        const len = msg[off];
        if (len == 0) return off + 1;
        if (len & 0xC0 == 0xC0) return off + 2; // compression pointer ends the name
        off += 1 + len;
    }
    return null;
}

/// Decode a (possibly compressed) DNS name into a dotted string.
/// OWNERSHIP: caller frees.
fn readName(allocator: Allocator, msg: []const u8, start: usize) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var off = start;
    var jumped = false;
    var guard: usize = 0;
    while (off < msg.len) {
        guard += 1;
        if (guard > 128) return Error.MalformedResponse;
        const len = msg[off];
        if (len == 0) break;
        if (len & 0xC0 == 0xC0) {
            if (off + 1 >= msg.len) return Error.MalformedResponse;
            const ptr = ((@as(usize, len & 0x3F) << 8) | msg[off + 1]);
            off = ptr;
            jumped = true;
            continue;
        }
        if (off + 1 + len > msg.len) return Error.MalformedResponse;
        if (out.items.len != 0) try out.append(allocator, '.');
        try out.appendSlice(allocator, msg[off + 1 .. off + 1 + len]);
        off += 1 + len;
        if (jumped) {
            // continue following the chain
        }
    }
    return out.toOwnedSlice(allocator);
}

const testing = std.testing;

test "parse synthetic SRV response" {
    // A hand-built DNS response: 1 question, 2 SRV answers.
    // Header: id=0x1337, flags=0x8180 (response, RD, RA), qd=1, an=2.
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(testing.allocator);
    const a = testing.allocator;
    try msg.appendSlice(a, &[_]u8{ 0x13, 0x37, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    // Question: _kerberos._tcp.EXAMPLE.COM SRV IN
    const qname = [_][]const u8{ "_kerberos", "_tcp", "EXAMPLE", "COM" };
    for (qname) |label| {
        try msg.append(a, @intCast(label.len));
        try msg.appendSlice(a, label);
    }
    try msg.append(a, 0);
    try msg.appendSlice(a, &[_]u8{ 0x00, 0x21, 0x00, 0x01 }); // type SRV, class IN
    const qname_off: u16 = 12; // question name starts right after header

    // Answer 1: name = pointer to question name (0xC00C), SRV, prio 10 wt 100 port 88 target dc1.EXAMPLE.COM
    inline for (.{ .{ 10, 100, 88, "dc1" }, .{ 5, 100, 88, "dc2" } }) |rec| {
        try msg.appendSlice(a, &[_]u8{ 0xC0, @intCast(qname_off) }); // compressed name
        try msg.appendSlice(a, &[_]u8{ 0x00, 0x21, 0x00, 0x01 }); // SRV IN
        try msg.appendSlice(a, &[_]u8{ 0x00, 0x00, 0x00, 0x3C }); // TTL 60
        // rdata: prio(2) weight(2) port(2) target
        var rdata: std.ArrayList(u8) = .empty;
        defer rdata.deinit(a);
        try rdata.appendSlice(a, &[_]u8{ 0x00, @intCast(rec[0]) });
        try rdata.appendSlice(a, &[_]u8{ 0x00, @intCast(rec[1]) });
        try rdata.appendSlice(a, &[_]u8{ 0x00, @intCast(rec[2]) });
        const tgt = rec[3];
        try rdata.append(a, @intCast(tgt.len));
        try rdata.appendSlice(a, tgt);
        // Reuse the question's EXAMPLE.COM via a pointer to its offset.
        const example_off: u16 = 12 + 1 + 9 + 1 + 4; // header + "_kerberos" + "_tcp"
        try rdata.appendSlice(a, &[_]u8{ 0xC0, @intCast(example_off) });
        try msg.appendSlice(a, &[_]u8{ 0x00, @intCast(rdata.items.len) });
        try msg.appendSlice(a, rdata.items);
    }

    var records = try parseSrvRecords(a, msg.items);
    defer {
        for (records.items) |r| a.free(r.target);
        records.deinit(a);
    }
    try testing.expectEqual(@as(usize, 2), records.items.len);
    try testing.expectEqual(@as(u16, 88), records.items[0].port);
    try testing.expectEqualStrings("dc1.EXAMPLE.COM", records.items[0].target);
    try testing.expectEqualStrings("dc2.EXAMPLE.COM", records.items[1].target);
}

test "parseFirstPtr returns the reverse-DNS name" {
    const a = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(a);
    // Header: id, flags response, qd=1, an=1.
    try msg.appendSlice(a, &[_]u8{ 0x13, 0x37, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    // Question: 10.0.0.10.in-addr.arpa PTR IN
    for ([_][]const u8{ "10", "0", "0", "10", "in-addr", "arpa" }) |l| {
        try msg.append(a, @intCast(l.len));
        try msg.appendSlice(a, l);
    }
    try msg.append(a, 0);
    try msg.appendSlice(a, &[_]u8{ 0x00, 0x0C, 0x00, 0x01 }); // PTR IN
    // Answer: compressed name -> question, PTR, IN, TTL 60, rdata = "dc01.corp.local".
    try msg.appendSlice(a, &[_]u8{ 0xC0, 0x0C });
    try msg.appendSlice(a, &[_]u8{ 0x00, 0x0C, 0x00, 0x01 });
    try msg.appendSlice(a, &[_]u8{ 0x00, 0x00, 0x00, 0x3C });
    var rdata: std.ArrayList(u8) = .empty;
    defer rdata.deinit(a);
    for ([_][]const u8{ "dc01", "corp", "local" }) |l| {
        try rdata.append(a, @intCast(l.len));
        try rdata.appendSlice(a, l);
    }
    try rdata.append(a, 0);
    try msg.appendSlice(a, &[_]u8{ 0x00, @intCast(rdata.items.len) });
    try msg.appendSlice(a, rdata.items);

    const name = parseFirstPtr(a, msg.items) orelse return error.NoPtr;
    defer a.free(name);
    try testing.expectEqualStrings("dc01.corp.local", name);
}

test "parseFirstA: skips CNAME and returns the A record" {
    // Regression for the hostname/SRV KDC bug: a DC's A record (often preceded by
    // a CNAME) must be parsed out of a DNS response. This is the resolution that
    // std.Io.net.IpAddress.resolve does NOT do.
    const a = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(a);
    // Header: id=0x1337, flags=0x8180 (response/RD/RA), qd=1, an=2.
    try msg.appendSlice(a, &[_]u8{ 0x13, 0x37, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00 });
    // Question name (12 bytes, starts at offset 12): dc.example  A IN
    const labels = [_][]const u8{ "dc", "example" };
    for (labels) |label| {
        try msg.append(a, @intCast(label.len));
        try msg.appendSlice(a, label);
    }
    try msg.append(a, 0);
    try msg.appendSlice(a, &[_]u8{ 0x00, 0x01, 0x00, 0x01 }); // QTYPE=A, QCLASS=IN
    // Answer 1: CNAME (type 5), name=ptr 0xC00C, TTL 60, rdata = "x." (3 bytes).
    try msg.appendSlice(a, &[_]u8{ 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x03, 0x01, 'x', 0x00 });
    // Answer 2: A (type 1), name=ptr 0xC00C, TTL 60, rdata = 192.168.56.11.
    try msg.appendSlice(a, &[_]u8{ 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 168, 56, 11 });

    const addr = parseFirstA(msg.items, 88) orelse return error.TestExpectedARecord;
    switch (addr) {
        .ip4 => |v| {
            try testing.expectEqual([4]u8{ 192, 168, 56, 11 }, v.bytes);
            try testing.expectEqual(@as(u16, 88), v.port);
        },
        else => return error.TestExpectedIp4,
    }
}

test "parseFirstA: response with no A record yields null" {
    const a = testing.allocator;
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(a);
    // qd=1, an=1, but the only answer is a CNAME (no A record present).
    try msg.appendSlice(a, &[_]u8{ 0x13, 0x37, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 });
    const labels = [_][]const u8{ "dc", "example" };
    for (labels) |label| {
        try msg.append(a, @intCast(label.len));
        try msg.appendSlice(a, label);
    }
    try msg.append(a, 0);
    try msg.appendSlice(a, &[_]u8{ 0x00, 0x01, 0x00, 0x01 });
    try msg.appendSlice(a, &[_]u8{ 0xC0, 0x0C, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x03, 0x01, 'x', 0x00 });
    try testing.expect(parseFirstA(msg.items, 88) == null);
}

test "parseHostsFile finds canonical names and aliases, case-insensitively" {
    const hosts =
        \\# a comment line
        \\127.0.0.1       localhost
        \\::1             localhost ip6-localhost
        \\10.0.0.10   dc01.corp.local dc01 kdc      # the DC
        \\   192.168.1.5  proxy.team.local
        \\bogus-line-without-ip
        \\
    ;
    // Canonical name.
    const dc = parseHostsFile(hosts, "dc01.corp.local", 88).?;
    try testing.expectEqualStrings("10.0.0.10:88", try fmtAddr(&dc));
    // Alias on the same line.
    try testing.expect(parseHostsFile(hosts, "kdc", 88) != null);
    // Case-insensitive, as DNS names are.
    try testing.expect(parseHostsFile(hosts, "DC01.CORP.LOCAL", 88) != null);
    // Leading whitespace and a trailing comment are handled.
    try testing.expect(parseHostsFile(hosts, "proxy.team.local", 1080) != null);
    // Absent names, and a name that only appears as a comment, are not found.
    try testing.expectEqual(@as(?net.IpAddress, null), parseHostsFile(hosts, "nope.corp.local", 88));
    // An IPv6-only entry is skipped rather than returned as a bogus v4 address.
    const lo = parseHostsFile(hosts, "ip6-localhost", 88);
    try testing.expectEqual(@as(?net.IpAddress, null), lo);
}

fn fmtAddr(a: *const net.IpAddress) ![]const u8 {
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    return std.fmt.bufPrint(&S.buf, "{f}", .{a});
}

test "lookupHostsFileAt reads a real file from disk and resolves a hosts-only name" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_hosts_file";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        const f = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer f.close(io);
        var buf: [256]u8 = undefined;
        var w = f.writerStreaming(io, &buf);
        try w.interface.writeAll(
            \\# pinned for the engagement
            \\10.20.30.40   dc01.corp.local dc01
            \\
        );
        try w.interface.flush();
    }

    // A name with no DNS record anywhere still resolves, which is the whole point.
    const got = lookupHostsFileAt(a, io, path, "dc01", 88).?;
    try testing.expectEqualStrings("10.20.30.40:88", try fmtAddr(&got));
    try testing.expect(lookupHostsFileAt(a, io, path, "dc01.corp.local", 88) != null);
    try testing.expectEqual(@as(?net.IpAddress, null), lookupHostsFileAt(a, io, path, "other", 88));
    // A missing hosts file is not an error, just "not found".
    try testing.expectEqual(@as(?net.IpAddress, null), lookupHostsFileAt(a, io, "no_such_hosts_file", "dc01", 88));
}
