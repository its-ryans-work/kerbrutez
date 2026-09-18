//! Minimal Kerberos client configuration — the subset kerbrute builds from its
//! krb5.conf template. Either an explicit KDC (the `--dc`) or DNS SRV lookup.

const std = @import("std");
const Allocator = std.mem.Allocator;
const iana = @import("../iana/constants.zig");
const dns = @import("dns.zig");

/// Which encryption types to advertise in the AS-REQ. AES is the default:
/// stealthier on modern AD, where an RC4-only request stands out. RC4 yields a
/// crackable arcfour-hmac AS-REP (`--downgrade`); `all` offers the full gokrb5
/// list (aes256, aes128, des3, rc4) for maximum interoperability.
pub const EtypePref = enum {
    aes,
    rc4,
    all,

    /// Parse the `--etype` flag value. Returns null on an unknown value.
    pub fn parse(s: []const u8) ?EtypePref {
        if (std.ascii.eqlIgnoreCase(s, "aes")) return .aes;
        if (std.ascii.eqlIgnoreCase(s, "rc4") or std.ascii.eqlIgnoreCase(s, "downgrade")) return .rc4;
        if (std.ascii.eqlIgnoreCase(s, "all")) return .all;
        return null;
    }
};

/// AES-only ticket enctypes (default): aes256, aes128.
pub const aes_tkt_etypes = [_]i32{
    iana.etype_id.aes256_cts_hmac_sha1_96,
    iana.etype_id.aes128_cts_hmac_sha1_96,
};

/// gokrb5's full ticket enctype order: aes256, aes128, des3, rc4 (`--etype all`).
pub const all_tkt_etypes = [_]i32{
    iana.etype_id.aes256_cts_hmac_sha1_96,
    iana.etype_id.aes128_cts_hmac_sha1_96,
    iana.etype_id.des3_cbc_sha1_kd,
    iana.etype_id.rc4_hmac,
};

/// Downgraded enctype list (`--etype rc4` / `--downgrade`): RC4 only, for
/// crackable AS-REPs.
pub const downgrade_etypes = [_]i32{iana.etype_id.rc4_hmac};

/// The AS-REQ etype list and preauth etype implied by an `EtypePref`.
/// LOCKOUT SAFETY: the preemptive PA-ENC-TIMESTAMP etype is aes256 because that
/// is what Active Directory advertises in ETYPE-INFO2 for a default account. If
/// we guess a different etype, every wrong password costs TWO badPwdCount
/// increments — one for our guess, one for the corrected retry — which silently
/// halves the account's usable lockout budget. Matching AD up front keeps an
/// attempt to a single increment. (See `advertisesDifferentKey` in client.zig,
/// which suppresses the retry when the KDC advertises what we already used.)
fn etypesFor(pref: EtypePref) struct { tkt: []const i32, preauth: i32 } {
    return switch (pref) {
        .aes => .{ .tkt = &aes_tkt_etypes, .preauth = iana.etype_id.aes256_cts_hmac_sha1_96 },
        .all => .{ .tkt = &all_tkt_etypes, .preauth = iana.etype_id.aes256_cts_hmac_sha1_96 },
        .rc4 => .{ .tkt = &downgrade_etypes, .preauth = iana.etype_id.rc4_hmac },
    };
}

pub const Config = struct {
    allocator: Allocator,
    /// Upper-cased realm. OWNED.
    realm: []const u8,
    /// Explicit KDC as "host:port" (port defaulted to 88). null => DNS lookup.
    /// OWNED when present.
    kdc: ?[]const u8,
    dns_lookup_kdc: bool,
    /// Enctype IDs advertised in the AS-REQ body.
    default_tkt_etype_ids: []const i32,
    /// Etype used for the preemptive PA-ENC-TIMESTAMP. aes256 to match what AD
    /// advertises, so a wrong password costs one badPwdCount, not two (see
    /// `etypesFor`).
    preferred_preauth_etype: i32 = iana.etype_id.aes256_cts_hmac_sha1_96,
    ticket_lifetime_secs: i64 = 24 * 60 * 60,
    clockskew_secs: i64 = 300,
    udp_preference_limit: usize = 1465,
    /// Optional SOCKS5 proxy "host:port" for KDC traffic (TCP-only). BORROW:
    /// set by the caller after `init`; must outlive the config.
    socks: ?[]const u8 = null,
    /// All explicit KDC endpoints ("host:port"), OWNED. Empty => DNS SRV
    /// discovery. More than one entry spreads attempts across DCs.
    kdc_list: []const []const u8 = &.{},
    /// Shared round-robin cursor over `kdc_list` (heap-allocated so copies of
    /// Config rotate together). OWNED; null unless there are 2+ KDCs.
    rotor: ?*std.atomic.Value(usize) = null,
    /// Optional DNS server to use for SRV KDC discovery (overrides resolv.conf).
    /// BORROW: set by the caller after `init`.
    dns_server: ?[]const u8 = null,

    /// Build a config for `domain`. If `domain_controller` is provided it is
    /// used directly (DNS lookup disabled); otherwise KDCs are resolved via
    /// DNS SRV records. `etype_pref` chooses the advertised enctype list
    /// (default `.aes`; `.rc4` downgrades for crackable AS-REPs).
    /// OWNERSHIP: caller calls `deinit`.
    pub fn init(allocator: Allocator, domain: []const u8, domain_controller: ?[]const u8, etype_pref: EtypePref) !Config {
        const realm = try upper(allocator, domain);
        errdefer allocator.free(realm);

        var kdc: ?[]const u8 = null;
        errdefer if (kdc) |k| allocator.free(k);
        var kdc_list: []const []const u8 = &.{};
        errdefer freeList(allocator, kdc_list);
        var dns_lookup = true;
        if (domain_controller) |dc| {
            if (dc.len > 0) {
                kdc_list = try parseKDCList(allocator, dc);
                kdc = try allocator.dupe(u8, kdc_list[0]);
                dns_lookup = false;
            }
        }

        // Only worth a shared cursor when there is something to rotate between.
        var rotor: ?*std.atomic.Value(usize) = null;
        errdefer if (rotor) |r| allocator.destroy(r);
        if (kdc_list.len > 1) {
            rotor = try allocator.create(std.atomic.Value(usize));
            rotor.?.* = std.atomic.Value(usize).init(0);
        }

        const ep = etypesFor(etype_pref);
        return .{
            .allocator = allocator,
            .realm = realm,
            .kdc = kdc,
            .kdc_list = kdc_list,
            .rotor = rotor,
            .dns_lookup_kdc = dns_lookup,
            .default_tkt_etype_ids = ep.tkt,
            .preferred_preauth_etype = ep.preauth,
        };
    }

    pub fn deinit(self: *Config) void {
        self.allocator.free(self.realm);
        if (self.kdc) |k| self.allocator.free(k);
        freeList(self.allocator, self.kdc_list);
        if (self.rotor) |r| self.allocator.destroy(r);
    }

    /// Resolve the KDC endpoints for the realm as a list of "host:port".
    /// `io` is needed only for the DNS SRV path. OWNERSHIP: caller frees the
    /// slice and each string (use `freeKDCs`).
    /// With several `--dc` endpoints the list is rotated one step per call, so
    /// consecutive attempts start at different DCs instead of hammering the
    /// first one; the remaining entries stay in order behind it, preserving
    /// failover. See `--dc dc1,dc2,dc3`.
    pub fn getKDCs(self: Config, io: std.Io, use_tcp: bool) ![][]const u8 {
        if (self.kdc_list.len > 0) {
            const list = try self.allocator.alloc([]const u8, self.kdc_list.len);
            errdefer self.allocator.free(list);
            const start: usize = if (self.rotor) |r| r.fetchAdd(1, .monotonic) else 0;
            for (list, 0..) |*slot, i| {
                slot.* = try self.allocator.dupe(u8, self.kdc_list[(start + i) % self.kdc_list.len]);
            }
            return list;
        }
        return dns.lookupKDCs(self.allocator, io, self.realm, use_tcp, self.dns_server);
    }

    pub fn freeKDCs(self: Config, kdcs: [][]const u8) void {
        for (kdcs) |k| self.allocator.free(k);
        self.allocator.free(kdcs);
    }
};

/// Split a comma-separated `--dc` value into "host:port" endpoints, applying the
/// default Kerberos port to any entry that omits one. Blank entries are ignored;
/// a value with no usable entry yields the original string so the caller still
/// gets a (failing) target rather than silently falling back to DNS.
/// OWNERSHIP: caller frees via `freeList`.
fn parseKDCList(allocator: Allocator, spec: []const u8) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (list.items) |e| allocator.free(e);
        list.deinit(allocator);
    }
    var it = std.mem.splitScalar(u8, spec, ',');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t");
        if (entry.len == 0) continue;
        try list.append(allocator, try withDefaultPort(allocator, entry, 88));
    }
    if (list.items.len == 0) try list.append(allocator, try withDefaultPort(allocator, spec, 88));
    return list.toOwnedSlice(allocator);
}

fn freeList(allocator: Allocator, list: []const []const u8) void {
    for (list) |e| allocator.free(e);
    allocator.free(list);
}

/// ASCII upper-case copy. OWNERSHIP: caller frees.
fn upper(allocator: Allocator, s: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, s.len);
    for (s, 0..) |c, i| out[i] = std.ascii.toUpper(c);
    return out;
}

/// Append ":<default_port>" if `host` has no port. OWNERSHIP: caller frees.
fn withDefaultPort(allocator: Allocator, host: []const u8, default_port: u16) ![]u8 {
    // An IPv6 literal with a port is written "[::1]:88"; bare "::1" has colons
    // but no port. Treat a single trailing :digits as a port.
    if (hasPort(host)) {
        // VALIDATE IT HERE. The consumer parses the port with `catch 88`, so a
        // value that does not fit a u16 was silently replaced by the default —
        // the tool printed "Using KDC(s): 127.0.0.1:99999" and then connected to
        // port 88. Quietly contacting a host:port the operator never asked for
        // is not acceptable in a tool used under a scope agreement.
        const idx = std.mem.lastIndexOfScalar(u8, host, ':').?;
        _ = std.fmt.parseInt(u16, host[idx + 1 ..], 10) catch return error.InvalidPort;
        return allocator.dupe(u8, host);
    }
    return std.fmt.allocPrint(allocator, "{s}:{d}", .{ host, default_port });
}

fn hasPort(host: []const u8) bool {
    if (std.mem.lastIndexOfScalar(u8, host, ':')) |idx| {
        // Everything after the last ':' must be digits to count as a port.
        if (idx + 1 >= host.len) return false;
        for (host[idx + 1 ..]) |c| {
            if (c < '0' or c > '9') return false;
        }
        // Reject bare IPv6 (multiple colons, not bracketed).
        const colons = std.mem.count(u8, host, ":");
        if (colons > 1 and host[0] != '[') return false;
        return true;
    }
    return false;
}

const testing = std.testing;

test "Config explicit DC defaults port to 88, AES default" {
    var c = try Config.init(testing.allocator, "example.com", "dc01.example.com", .aes);
    defer c.deinit();
    try testing.expectEqualStrings("EXAMPLE.COM", c.realm);
    try testing.expect(!c.dns_lookup_kdc);
    try testing.expectEqualStrings("dc01.example.com:88", c.kdc.?);
    try testing.expectEqualSlices(i32, &.{ 18, 17 }, c.default_tkt_etype_ids);
    // aes256: matches AD's advertised ETYPE-INFO2 so no second (badPwdCount-
    // costing) pre-auth round is needed.
    try testing.expectEqual(@as(i32, 18), c.preferred_preauth_etype);
}

test "Config etype all offers the full gokrb5 list" {
    var c = try Config.init(testing.allocator, "example.com", "dc01", .all);
    defer c.deinit();
    try testing.expectEqualSlices(i32, &.{ 18, 17, 16, 23 }, c.default_tkt_etype_ids);
}

test "Config explicit DC keeps provided port" {
    var c = try Config.init(testing.allocator, "example.com", "10.0.0.1:8888", .aes);
    defer c.deinit();
    try testing.expectEqualStrings("10.0.0.1:8888", c.kdc.?);
}

test "Config no DC enables DNS lookup, rc4 downgrades" {
    var c = try Config.init(testing.allocator, "example.com", null, .rc4);
    defer c.deinit();
    try testing.expect(c.dns_lookup_kdc);
    try testing.expectEqual(@as(?[]const u8, null), c.kdc);
    try testing.expectEqualSlices(i32, &.{23}, c.default_tkt_etype_ids); // downgrade
    try testing.expectEqual(@as(i32, 23), c.preferred_preauth_etype);
}

test "EtypePref.parse accepts aliases" {
    try testing.expectEqual(EtypePref.aes, EtypePref.parse("aes").?);
    try testing.expectEqual(EtypePref.rc4, EtypePref.parse("RC4").?);
    try testing.expectEqual(EtypePref.rc4, EtypePref.parse("downgrade").?);
    try testing.expectEqual(EtypePref.all, EtypePref.parse("all").?);
    try testing.expectEqual(@as(?EtypePref, null), EtypePref.parse("bogus"));
}

test "getKDCs returns explicit KDC" {
    var c = try Config.init(testing.allocator, "example.com", "dc01", .aes);
    defer c.deinit();
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const kdcs = try c.getKDCs(threaded.io(), false);
    defer c.freeKDCs(kdcs);
    try testing.expectEqual(@as(usize, 1), kdcs.len);
    try testing.expectEqualStrings("dc01:88", kdcs[0]);
}

test "Config --dc accepts several DCs and rotates between them" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var c = try Config.init(a, "example.com", "dc1, dc2:8888 ,dc3", .aes);
    defer c.deinit();
    try testing.expectEqual(@as(usize, 3), c.kdc_list.len);
    try testing.expectEqualStrings("dc1:88", c.kdc_list[0]); // default port applied
    try testing.expectEqualStrings("dc2:8888", c.kdc_list[1]); // explicit port kept
    try testing.expectEqualStrings("dc3:88", c.kdc_list[2]);
    try testing.expectEqualStrings("dc1:88", c.kdc.?); // first stays the display DC
    try testing.expect(!c.dns_lookup_kdc);

    // Each call starts one step further along, so consecutive attempts spread
    // over the DCs; the rest follow in order, keeping failover intact.
    const expected = [_][3][]const u8{
        .{ "dc1:88", "dc2:8888", "dc3:88" },
        .{ "dc2:8888", "dc3:88", "dc1:88" },
        .{ "dc3:88", "dc1:88", "dc2:8888" },
        .{ "dc1:88", "dc2:8888", "dc3:88" }, // wraps
    };
    for (expected) |round| {
        const kdcs = try c.getKDCs(io, false);
        defer c.freeKDCs(kdcs);
        try testing.expectEqual(@as(usize, 3), kdcs.len);
        for (round, kdcs) |want, got| try testing.expectEqualStrings(want, got);
    }
}

test "Config single --dc keeps the old behaviour (no rotor)" {
    const a = testing.allocator;
    var c = try Config.init(a, "example.com", "dc01", .aes);
    defer c.deinit();
    try testing.expectEqual(@as(usize, 1), c.kdc_list.len);
    try testing.expectEqual(@as(?*std.atomic.Value(usize), null), c.rotor);
}

// REGRESSION TEST. `--dc host:99999` was accepted verbatim and printed back as
// "Using KDC(s): 127.0.0.1:99999", but the consumer parsed the port with
// `catch 88` — so the tool actually connected to port 88. Silently contacting a
// host:port the operator never specified is unacceptable under a scope
// agreement, and it also masks a typo'd non-standard port (labs commonly run a
// KDC on 8088).
test "an out-of-range --dc port is rejected, not silently replaced with 88" {
    const a = testing.allocator;
    try testing.expectError(error.InvalidPort, Config.init(a, "example.com", "127.0.0.1:99999", .aes));
    try testing.expectError(error.InvalidPort, Config.init(a, "example.com", "dc01:70000", .aes));
    // One bad entry in a list fails the whole list rather than half-applying it.
    try testing.expectError(error.InvalidPort, Config.init(a, "example.com", "dc01,dc02:99999", .aes));

    // Valid ports, including non-standard ones, still work untouched.
    {
        var c = try Config.init(a, "example.com", "127.0.0.1:8088", .aes);
        defer c.deinit();
        try testing.expectEqualStrings("127.0.0.1:8088", c.kdc.?);
    }
    {
        var c = try Config.init(a, "example.com", "dc01", .aes);
        defer c.deinit();
        try testing.expectEqualStrings("dc01:88", c.kdc.?); // default applied
    }
}
