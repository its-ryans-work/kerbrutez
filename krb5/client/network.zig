//! KDC networking: send an encoded request and read the reply, mirroring
//! gokrb5's sendToKDC (UDP first when the message fits, with a TCP fallback;
//! TCP framing is a 4-byte big-endian length prefix per RFC 4120 §7.2.2).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const net = std.Io.net;
const Config = @import("../config/config.zig").Config;
const dns = @import("../config/dns.zig");
const krb_error = @import("../messages/krb_error.zig");
const iana = @import("../iana/constants.zig");

pub const Error = error{
    NoKDCs,
    AllKDCsFailed,
    ResponseTooLarge,
} || Allocator.Error;

pub const SocksError = error{
    SocksConnectFailed,
    SocksHandshakeFailed,
    SocksAuthUnsupported,
    SocksHostTooLong,
    SocksBadReply,
    SocksConnectRejected,
};

const timeout_secs = 5;

fn timeout() Io.Timeout {
    return .{ .duration = .{ .raw = Io.Duration.fromSeconds(timeout_secs), .clock = .awake } };
}

/// Send `data` to a KDC for `cfg`'s realm and return the raw reply.
/// OWNERSHIP: caller frees the reply.
pub fn sendToKDC(io: Io, allocator: Allocator, cfg: Config, data: []const u8) Error![]u8 {
    // SOCKS5 proxies TCP only — skip the UDP path entirely.
    if (cfg.socks != null) return sendTCP(io, allocator, cfg, data);
    if (data.len <= cfg.udp_preference_limit) {
        if (sendUDP(io, allocator, cfg, data)) |resp| {
            // If the KDC says the response is too big for UDP, retry over TCP.
            if (krb_error.isKRBError(resp)) {
                if (krb_error.KRBError.unmarshal(resp)) |ke| {
                    if (ke.error_code == iana.error_code.krb_err_response_too_big) {
                        allocator.free(resp);
                        return sendTCP(io, allocator, cfg, data);
                    }
                } else |_| {}
            }
            return resp;
        } else |_| {
            return sendTCP(io, allocator, cfg, data);
        }
    }
    // Large request: TCP first, UDP as a fallback.
    if (sendTCP(io, allocator, cfg, data)) |resp| {
        return resp;
    } else |_| {
        return sendUDP(io, allocator, cfg, data);
    }
}

const HostPort = struct { host: []const u8, port: u16 };

/// Split "host:port" (or "[ipv6]:port"); defaults to port 88.
fn splitHostPort(s: []const u8) HostPort {
    if (s.len > 0 and s[0] == '[') {
        if (std.mem.indexOfScalar(u8, s, ']')) |close| {
            const host = s[1..close];
            if (close + 2 <= s.len and s[close + 1] == ':') {
                const port = std.fmt.parseInt(u16, s[close + 2 ..], 10) catch 88;
                return .{ .host = host, .port = port };
            }
            return .{ .host = host, .port = 88 };
        }
    }
    if (std.mem.lastIndexOfScalar(u8, s, ':')) |idx| {
        // Only treat as host:port if there's a single colon (not bare IPv6).
        if (std.mem.count(u8, s, ":") == 1) {
            const port = std.fmt.parseInt(u16, s[idx + 1 ..], 10) catch 88;
            return .{ .host = s[0..idx], .port = port };
        }
    }
    return .{ .host = s, .port = 88 };
}

/// Resolve a KDC host string to an address. std.Io.net.IpAddress.resolve only
/// parses IP literals (no DNS), so for a hostname (a typed --dc or an SRV
/// target) fall back to a DNS A lookup via the same nameserver SRV discovery uses.
fn resolveAddr(io: Io, allocator: Allocator, cfg: Config, host: []const u8, port: u16) !net.IpAddress {
    if (net.IpAddress.resolve(io, host, port)) |a| return a else |_| {}
    // Hosts file before DNS, as the OS resolver does — an operator who pinned
    // this name in /etc/hosts meant it to win.
    if (dns.lookupHostsFile(allocator, io, host, port)) |a| return a;
    return dns.resolveHost(allocator, io, host, port, cfg.dns_server);
}

fn sendUDP(io: Io, allocator: Allocator, cfg: Config, data: []const u8) Error![]u8 {
    const kdcs = cfg.getKDCs(io, false) catch return Error.NoKDCs;
    defer cfg.freeKDCs(kdcs);
    if (kdcs.len == 0) return Error.NoKDCs;

    for (kdcs) |kdc| {
        const hp = splitHostPort(kdc);
        const addr = resolveAddr(io, allocator, cfg, hp.host, hp.port) catch continue;
        const family_unspec: net.IpAddress = switch (addr) {
            .ip4 => .{ .ip4 = net.Ip4Address.unspecified(0) },
            .ip6 => .{ .ip6 = net.Ip6Address.unspecified(0) },
        };
        var sock = net.IpAddress.bind(&family_unspec, io, .{ .mode = .dgram, .protocol = .udp }) catch continue;
        defer sock.close(io);
        sock.send(io, &addr, data) catch continue;
        // KDC replies can be large (TGT + PAC); use a generous buffer.
        const rbuf = try allocator.alloc(u8, 65535);
        defer allocator.free(rbuf);
        const incoming = sock.receiveTimeout(io, rbuf, timeout()) catch continue;
        if (incoming.data.len == 0) continue;
        return allocator.dupe(u8, incoming.data);
    }
    return Error.AllKDCsFailed;
}

fn sendTCP(io: Io, allocator: Allocator, cfg: Config, data: []const u8) Error![]u8 {
    const kdcs = cfg.getKDCs(io, true) catch return Error.NoKDCs;
    defer cfg.freeKDCs(kdcs);
    if (kdcs.len == 0) return Error.NoKDCs;

    for (kdcs) |kdc| {
        const hp = splitHostPort(kdc);
        // Through a SOCKS5 proxy (OPSEC), or a direct TCP connect.
        var stream = if (cfg.socks) |proxy|
            (socks5Connect(io, allocator, cfg, splitHostPort(proxy), hp.host, hp.port) catch continue)
        else blk: {
            const addr = resolveAddr(io, allocator, cfg, hp.host, hp.port) catch continue;
            // NOTE: Zig 0.16's Threaded Io has not implemented connect-with-timeout
            // (it panics), so we connect without one. Refused/unreachable hosts
            // still fail fast via the OS; the UDP path (which does support a
            // timeout) is tried first for normal-sized requests.
            break :blk net.IpAddress.connect(&addr, io, .{ .mode = .stream, .protocol = .tcp }) catch continue;
        };
        defer stream.close(io);

        // Write 4-byte BE length prefix + data.
        var hdr: [4]u8 = undefined;
        std.mem.writeInt(u32, &hdr, @intCast(data.len), .big);
        var wbuf: [512]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        w.interface.writeAll(&hdr) catch continue;
        w.interface.writeAll(data) catch continue;
        w.interface.flush() catch continue;

        // Read 4-byte length, then that many bytes.
        var rbuf: [4096]u8 = undefined;
        var r = stream.reader(io, &rbuf);
        var lenb: [4]u8 = undefined;
        r.interface.readSliceAll(&lenb) catch continue;
        const resp_len = std.mem.readInt(u32, &lenb, .big);
        if (resp_len == 0) continue;
        if (resp_len > 16 * 1024 * 1024) return Error.ResponseTooLarge;
        const resp = try allocator.alloc(u8, resp_len);
        errdefer allocator.free(resp);
        r.interface.readSliceAll(resp) catch {
            allocator.free(resp);
            continue;
        };
        return resp;
    }
    return Error.AllKDCsFailed;
}

/// Run the SOCKS5 handshake once and hang up, so a proxy misconfiguration is
/// reported ONCE, up front, with the actual reason.
///
/// Without this every proxy failure — proxy down, proxy demands authentication,
/// proxy refused the target — surfaced as the same "NETWORK ERROR - Can't talk
/// to KDC" on every attempt, because `sendTCP` does `catch continue` and drops
/// the specific SocksError. Proxies that require username/password auth are
/// common, and kerbrutez only offers no-auth, so that case in particular needs
/// to say so rather than look like an unreachable DC.
pub fn preflightSocks(io: Io, allocator: Allocator, cfg: Config, target_host: []const u8, target_port: u16) SocksError!void {
    const proxy = cfg.socks orelse return;
    var stream = try socks5Connect(io, allocator, cfg, splitHostPort(proxy), target_host, target_port);
    stream.close(io);
}

/// Open a TCP stream to `target` through a SOCKS5 proxy (no auth), letting the
/// proxy resolve the target (ATYP=domain) so DNS doesn't leak from the operator
/// host. Returns the connected, post-handshake stream.
fn socks5Connect(io: Io, allocator: Allocator, cfg: Config, proxy: HostPort, target_host: []const u8, target_port: u16) !net.Stream {
    if (target_host.len > 255) return SocksError.SocksHostTooLong;
    // Resolve the PROXY through resolveAddr, not net.IpAddress.resolve: the
    // latter only parses IP literals in Zig 0.16, so `--socks proxy.team.local:1080`
    // failed outright. (Same defect previously fixed for the KDC and webhook
    // paths.) The TARGET is still passed to the proxy as a name, so the target's
    // DNS is resolved proxy-side and does not leak from this host.
    const paddr = resolveAddr(io, allocator, cfg, proxy.host, proxy.port) catch return SocksError.SocksConnectFailed;
    var stream = net.IpAddress.connect(&paddr, io, .{ .mode = .stream, .protocol = .tcp }) catch return SocksError.SocksConnectFailed;
    errdefer stream.close(io);

    var wbuf: [320]u8 = undefined;
    var rbuf: [320]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var r = stream.reader(io, &rbuf);

    // Greeting: VER=5, NMETHODS=1, METHODS=[0x00 no-auth].
    w.interface.writeAll(&[_]u8{ 0x05, 0x01, 0x00 }) catch return SocksError.SocksHandshakeFailed;
    w.interface.flush() catch return SocksError.SocksHandshakeFailed;
    var sel: [2]u8 = undefined;
    r.interface.readSliceAll(&sel) catch return SocksError.SocksHandshakeFailed;
    if (sel[0] != 0x05) return SocksError.SocksBadReply;
    if (sel[1] != 0x00) return SocksError.SocksAuthUnsupported;

    // CONNECT: VER=5, CMD=1, RSV=0, ATYP=3(domain), LEN, host, port(2 BE).
    var req: [262]u8 = undefined;
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = @intCast(target_host.len);
    @memcpy(req[5 .. 5 + target_host.len], target_host);
    std.mem.writeInt(u16, req[5 + target_host.len ..][0..2], target_port, .big);
    const req_len = 5 + target_host.len + 2;
    w.interface.writeAll(req[0..req_len]) catch return SocksError.SocksHandshakeFailed;
    w.interface.flush() catch return SocksError.SocksHandshakeFailed;

    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
    var head: [4]u8 = undefined;
    r.interface.readSliceAll(&head) catch return SocksError.SocksHandshakeFailed;
    if (head[0] != 0x05) return SocksError.SocksBadReply;
    if (head[1] != 0x00) return SocksError.SocksConnectRejected;
    const addr_len: usize = switch (head[3]) {
        0x01 => 4, // IPv4
        0x04 => 16, // IPv6
        0x03 => blk: { // domain: 1-byte length prefix
            var l: [1]u8 = undefined;
            r.interface.readSliceAll(&l) catch return SocksError.SocksHandshakeFailed;
            break :blk l[0];
        },
        else => return SocksError.SocksBadReply,
    };
    var skip: [260]u8 = undefined;
    r.interface.readSliceAll(skip[0 .. addr_len + 2]) catch return SocksError.SocksHandshakeFailed; // BND.ADDR + port
    return stream;
}

const testing = std.testing;

test "splitHostPort variants" {
    {
        const hp = splitHostPort("dc01.example.com:88");
        try testing.expectEqualStrings("dc01.example.com", hp.host);
        try testing.expectEqual(@as(u16, 88), hp.port);
    }
    {
        const hp = splitHostPort("10.0.0.1:9999");
        try testing.expectEqualStrings("10.0.0.1", hp.host);
        try testing.expectEqual(@as(u16, 9999), hp.port);
    }
    {
        const hp = splitHostPort("::1"); // bare IPv6, no port
        try testing.expectEqualStrings("::1", hp.host);
        try testing.expectEqual(@as(u16, 88), hp.port);
    }
    {
        const hp = splitHostPort("[fe80::1]:88");
        try testing.expectEqualStrings("fe80::1", hp.host);
        try testing.expectEqual(@as(u16, 88), hp.port);
    }
}
