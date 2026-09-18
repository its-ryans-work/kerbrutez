//! Offline BloodHound (SharpHound / BloodHound-CE) users ingest.
//!
//! Parses a BloodHound "users" collection into a working user list, flagging
//! disabled / SPN (kerberoastable) / no-preauth (AS-REP-roastable) accounts —
//! the same enrichment as `ldapenum`, but with NO network and NO credentials.
//! It is an offline source: feed it a SharpHound dump and spray/roast the
//! result.
//!
//! Input (`--bloodhound <path>` / `bloodhound <path>`) may be:
//!   * a single `*.json` users file,
//!   * a directory containing one (we locate the `*users.json`), or
//!   * a `.zip` collection (SharpHound output): we locate and inflate ONLY the
//!     users entry — never the whole archive.
//!
//! SAFETY. Untrusted archives are handled defensively:
//!   * Zip bombs — the central directory is capped (`max_entries`) and the
//!     single users entry is inflated through `allocRemaining` with a hard byte
//!     cap (`max_json_bytes`), so the *declared* uncompressed size is never
//!     trusted; a runaway stream is rejected with `error.ZipBombRejected`.
//!   * Path traversal — entry names containing `..`, an absolute root, or a
//!     drive letter are rejected, and nothing is EVER written to disk: we
//!     inflate the one users entry straight into a capped in-memory buffer.
//!   * Oversized plain files are capped the same way (`error.FileTooLarge`).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zip = std.zip;
const flate = std.compress.flate;

/// Resource caps that bound untrusted input. Defaults are generous enough for
/// real domains yet keep a malicious archive from exhausting memory.
pub const Caps = struct {
    /// Max central-directory records scanned before we give up on an archive.
    max_entries: u32 = 16_384,
    /// Hard cap on the users JSON we will hold in memory (inflated or plain).
    max_json_bytes: usize = 256 * 1024 * 1024,
    /// Longest zip entry name we will read (defensive; names are normally short).
    max_name_len: u16 = 1024,
};

/// One enriched user record. OWNERSHIP: `sam` and `description` are owned by the
/// parent `Users` and freed in `Users.deinit`.
pub const User = struct {
    /// sAMAccountName (or the local part of the UPN when sAM is absent). OWNED.
    sam: []const u8,
    enabled: bool,
    dont_require_preauth: bool,
    spn_count: usize,
    has_spn: bool,
    /// AD `description`, when present and non-empty. OWNED, optional.
    description: ?[]const u8 = null,
};

/// The parsed working list. OWNERSHIP: call `deinit` to free `items` and the
/// strings each user owns.
pub const Users = struct {
    allocator: Allocator,
    items: []User,
    /// `meta.count` / `meta.version` from the dump, when present.
    meta_count: ?u64 = null,
    meta_version: ?u64 = null,

    pub fn deinit(self: *Users) void {
        for (self.items) |u| {
            self.allocator.free(u.sam);
            if (u.description) |d| self.allocator.free(d);
        }
        self.allocator.free(self.items);
        self.* = undefined;
    }
};

/// Load a BloodHound users list from a file, directory, or zip with the default
/// caps. OWNERSHIP: caller calls `Users.deinit`.
pub fn load(allocator: Allocator, io: Io, path: []const u8) !Users {
    return loadCaps(allocator, io, path, .{});
}

/// Like `load`, with explicit resource caps.
pub fn loadCaps(allocator: Allocator, io: Io, path: []const u8, caps: Caps) !Users {
    const cwd = Io.Dir.cwd();

    // Directory? (openDir on a regular file returns error.NotDir.)
    if (cwd.openDir(io, path, .{ .iterate = true })) |dir_const| {
        var dir = dir_const;
        defer dir.close(io);
        return loadFromDir(allocator, io, dir, caps);
    } else |err| switch (err) {
        error.NotDir => {}, // a regular file — fall through
        else => return err, // FileNotFound / AccessDenied / ...
    }

    // A file: sniff the magic so a `.zip` without the extension still works.
    if (try looksLikeZip(io, cwd, path)) return loadFromZip(allocator, io, cwd, path, caps);
    return loadJsonFile(allocator, io, cwd, path, caps);
}

/// Peek the first two bytes for the PK zip signature.
fn looksLikeZip(io: Io, cwd: Io.Dir, path: []const u8) !bool {
    var f = try cwd.openFile(io, path, .{});
    defer f.close(io);
    var buf: [16]u8 = undefined;
    var fr = f.reader(io, &buf);
    const hdr = fr.interface.peekArray(2) catch return false;
    return hdr[0] == 'P' and hdr[1] == 'K';
}

// ===========================================================================
// Directory and plain-file sources
// ===========================================================================

fn loadFromDir(allocator: Allocator, io: Io, dir: Io.Dir, caps: Caps) !Users {
    var name_buf: [512]u8 = undefined;
    var chosen_len: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!isUsersFile(entry.name)) continue;
        if (entry.name.len > name_buf.len) continue;
        @memcpy(name_buf[0..entry.name.len], entry.name);
        chosen_len = entry.name.len;
        break;
    }
    if (chosen_len == 0) return error.UsersFileNotFound;

    var f = try dir.openFile(io, name_buf[0..chosen_len], .{});
    defer f.close(io);
    const bytes = try readAllCapped(allocator, io, f, caps.max_json_bytes);
    defer allocator.free(bytes);
    return parseUsersJson(allocator, bytes, caps);
}

fn loadJsonFile(allocator: Allocator, io: Io, cwd: Io.Dir, path: []const u8, caps: Caps) !Users {
    var f = try cwd.openFile(io, path, .{});
    defer f.close(io);
    const bytes = try readAllCapped(allocator, io, f, caps.max_json_bytes);
    defer allocator.free(bytes);
    return parseUsersJson(allocator, bytes, caps);
}

/// Read an entire file into memory, refusing anything past `cap`.
fn readAllCapped(allocator: Allocator, io: Io, f: Io.File, cap: usize) ![]u8 {
    var buf: [64 * 1024]u8 = undefined;
    var fr = f.reader(io, &buf);
    return fr.interface.allocRemaining(allocator, .limited(cap)) catch |err| switch (err) {
        error.StreamTooLong => return error.FileTooLarge,
        else => |e| return e,
    };
}

// ===========================================================================
// Zip source (single-entry, in-memory, hardened)
// ===========================================================================

fn loadFromZip(allocator: Allocator, io: Io, cwd: Io.Dir, path: []const u8, caps: Caps) !Users {
    var f = try cwd.openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [64 * 1024]u8 = undefined;
    var fr = f.reader(io, &rbuf);

    var iter = zip.Iterator.init(&fr) catch return error.BadZip;
    var name_buf: [1024]u8 = undefined;
    var scanned: u32 = 0;
    while (try iter.next()) |entry| {
        scanned += 1;
        if (scanned > caps.max_entries) return error.ZipTooManyEntries;
        if (entry.filename_len == 0 or entry.filename_len > name_buf.len or entry.filename_len > caps.max_name_len) continue;

        // The entry name lives in the central directory; read it there.
        const name = name_buf[0..entry.filename_len];
        try fr.seekTo(entry.header_zip_offset + @sizeOf(zip.CentralDirectoryFileHeader));
        try fr.interface.readSliceAll(name);

        if (!safeEntryName(name)) continue; // path-traversal guard (defence in depth)
        if (!isUsersFile(name)) continue;

        // Found it — inflate ONLY this entry into a capped buffer.
        const bytes = try inflateEntry(allocator, &fr, entry, caps);
        defer allocator.free(bytes);
        return parseUsersJson(allocator, bytes, caps);
    }
    return error.UsersFileNotFound;
}

/// Inflate a single zip entry into an owned, capped in-memory buffer. The
/// declared `uncompressed_size` is never trusted for the deflate path — the
/// byte cap is enforced on the actual output stream.
fn inflateEntry(allocator: Allocator, fr: *Io.File.Reader, entry: zip.Iterator.Entry, caps: Caps) ![]u8 {
    // The compressed data starts after the LOCAL header, whose name/extra
    // lengths can differ from the central directory's — read them here.
    try fr.seekTo(entry.file_offset);
    const local = try fr.interface.takeStruct(zip.LocalFileHeader, .little);
    if (!std.mem.eql(u8, &local.signature, &zip.local_file_header_sig)) return error.ZipBadLocalHeader;
    const data_off = entry.file_offset + @sizeOf(zip.LocalFileHeader) +
        @as(u64, local.filename_len) + @as(u64, local.extra_len);
    try fr.seekTo(data_off);

    switch (entry.compression_method) {
        .store => {
            if (entry.uncompressed_size > caps.max_json_bytes) return error.ZipEntryTooLarge;
            const out = try allocator.alloc(u8, @intCast(entry.uncompressed_size));
            errdefer allocator.free(out);
            try fr.interface.readSliceAll(out);
            return out;
        },
        .deflate => {
            var window: [flate.max_window_len]u8 = undefined;
            var dec = flate.Decompress.init(&fr.interface, .raw, &window);
            return dec.reader.allocRemaining(allocator, .limited(caps.max_json_bytes)) catch |err| switch (err) {
                error.StreamTooLong => return error.ZipBombRejected,
                else => |e| return e,
            };
        },
        else => return error.UnsupportedCompressionMethod,
    }
}

// ===========================================================================
// JSON parsing (BloodHound users schema, v4–v6)
// ===========================================================================

fn parseUsersJson(allocator: Allocator, bytes: []const u8, caps: Caps) !Users {
    _ = caps;
    const Props = struct {
        samaccountname: ?[]const u8 = null,
        serviceprincipalnames: ?[]const []const u8 = null,
        hasspn: ?bool = null,
        dontreqpreauth: ?bool = null,
        enabled: ?bool = null,
        description: ?[]const u8 = null,
        name: ?[]const u8 = null,
    };
    const Node = struct { Properties: ?Props = null };
    const Meta = struct { count: ?u64 = null, version: ?u64 = null };
    const Doc = struct { data: []const Node = &.{}, meta: ?Meta = null };

    var parsed = std.json.parseFromSlice(Doc, allocator, bytes, .{ .ignore_unknown_fields = true }) catch return error.BadJson;
    defer parsed.deinit();
    const doc = parsed.value;

    var list: std.ArrayList(User) = .empty;
    errdefer {
        for (list.items) |u| {
            allocator.free(u.sam);
            if (u.description) |d| allocator.free(d);
        }
        list.deinit(allocator);
    }

    for (doc.data) |node| {
        const props = node.Properties orelse continue;
        const sam_src = props.samaccountname orelse deriveSam(props.name) orelse continue;
        if (sam_src.len == 0) continue;

        const spn_count: usize = if (props.serviceprincipalnames) |s| s.len else 0;
        const has_spn = props.hasspn orelse (spn_count > 0);

        const sam = try allocator.dupe(u8, sam_src);
        errdefer allocator.free(sam);
        var descr: ?[]const u8 = null;
        if (props.description) |d| {
            if (d.len > 0) descr = try allocator.dupe(u8, d);
        }
        try list.append(allocator, .{
            .sam = sam,
            .enabled = props.enabled orelse true,
            .dont_require_preauth = props.dontreqpreauth orelse false,
            .spn_count = spn_count,
            .has_spn = has_spn,
            .description = descr,
        });
    }

    return .{
        .allocator = allocator,
        .items = try list.toOwnedSlice(allocator),
        .meta_count = if (doc.meta) |m| m.count else null,
        .meta_version = if (doc.meta) |m| m.version else null,
    };
}

/// Derive a sAMAccountName from a UPN-style `name` ("USER@DOMAIN" -> "USER").
fn deriveSam(name: ?[]const u8) ?[]const u8 {
    const n = name orelse return null;
    if (std.mem.indexOfScalar(u8, n, '@')) |at| return n[0..at];
    return n;
}

// ===========================================================================
// Name helpers
// ===========================================================================

/// True if the basename (case-insensitive) ends with "users.json" — matches
/// `users.json` and SharpHound's `<timestamp>_users.json`, but NOT
/// `computers.json` (ends "...ters.json").
fn isUsersFile(name: []const u8) bool {
    return endsWithIgnoreCase(basenameOf(name), "users.json");
}

fn basenameOf(name: []const u8) []const u8 {
    if (std.mem.lastIndexOfAny(u8, name, "/\\")) |i| return name[i + 1 ..];
    return name;
}

/// Reject absolute paths, drive letters and `..` traversal components. We never
/// write to disk, but we refuse to even read a suspicious entry.
fn safeEntryName(name: []const u8) bool {
    if (name.len == 0) return false;
    if (name[0] == '/' or name[0] == '\\') return false; // absolute / UNC
    if (name.len >= 2 and name[1] == ':') return false; // drive letter (C:)
    var it = std.mem.splitAny(u8, name, "/\\");
    while (it.next()) |seg| {
        if (std.mem.eql(u8, seg, "..")) return false;
    }
    return true;
}

fn endsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    const tail = haystack[haystack.len - needle.len ..];
    for (tail, needle) |a, b| {
        if (std.ascii.toLower(a) != std.ascii.toLower(b)) return false;
    }
    return true;
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

test "isUsersFile matches users.json but not computers.json" {
    try testing.expect(isUsersFile("20240305110018_users.json"));
    try testing.expect(isUsersFile("users.json"));
    try testing.expect(isUsersFile("/some/dir/USERS.JSON"));
    try testing.expect(!isUsersFile("20240305110018_computers.json"));
    try testing.expect(!isUsersFile("groups.json"));
    try testing.expect(!isUsersFile("users.json.bak"));
}

test "safeEntryName rejects traversal and absolute roots" {
    try testing.expect(safeEntryName("20240305_users.json"));
    try testing.expect(safeEntryName("sub/dir/users.json"));
    try testing.expect(!safeEntryName("../users.json"));
    try testing.expect(!safeEntryName("a/../../etc/passwd"));
    try testing.expect(!safeEntryName("/etc/passwd"));
    try testing.expect(!safeEntryName("C:\\users.json"));
    try testing.expect(!safeEntryName("..\\..\\x"));
}

test "deriveSam strips the UPN domain" {
    try testing.expectEqualStrings("jsnow", deriveSam("jsnow@NORTH.LOCAL").?);
    try testing.expectEqualStrings("plain", deriveSam("plain").?);
    try testing.expect(deriveSam(null) == null);
}

test "parseUsersJson extracts enrichment flags" {
    const a = testing.allocator;
    const json =
        \\{ "meta": { "count": 2, "version": 6, "type": "users" },
        \\  "data": [
        \\    { "ObjectIdentifier": "S-1-5-21-x-500",
        \\      "Properties": { "samaccountname": "Administrator", "enabled": true,
        \\        "hasspn": true, "serviceprincipalnames": ["HTTP/dc","CIFS/dc"],
        \\        "dontreqpreauth": false, "description": "Built-in admin" } },
        \\    { "Properties": { "samaccountname": "krbtgt", "enabled": false,
        \\        "dontreqpreauth": true, "description": null } },
        \\    { "Properties": { "name": "ONLYUPN@NORTH.LOCAL" } }
        \\  ] }
    ;
    var users = try parseUsersJson(a, json, .{});
    defer users.deinit();

    try testing.expectEqual(@as(u64, 6), users.meta_version.?);
    try testing.expectEqual(@as(usize, 3), users.items.len);

    const admin = users.items[0];
    try testing.expectEqualStrings("Administrator", admin.sam);
    try testing.expect(admin.enabled);
    try testing.expect(admin.has_spn);
    try testing.expectEqual(@as(usize, 2), admin.spn_count);
    try testing.expectEqualStrings("Built-in admin", admin.description.?);

    const krbtgt = users.items[1];
    try testing.expectEqualStrings("krbtgt", krbtgt.sam);
    try testing.expect(!krbtgt.enabled);
    try testing.expect(krbtgt.dont_require_preauth);
    try testing.expect(krbtgt.description == null);

    // sAMAccountName absent -> derived from the UPN local part.
    try testing.expectEqualStrings("ONLYUPN", users.items[2].sam);
}

test "parseUsersJson tolerates an empty data array" {
    const a = testing.allocator;
    var users = try parseUsersJson(a, "{\"data\":[],\"meta\":{\"count\":0}}", .{});
    defer users.deinit();
    try testing.expectEqual(@as(usize, 0), users.items.len);
}
