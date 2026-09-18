//! Username and combo-line parsing, mirroring kerbrute's util/username.go.

const std = @import("std");

pub const Error = error{
    BlankUsername,
    TooManyAtSigns,
    MissingColon,
    BlankPassword,
};

/// Reduce a username as written in a wordlist to the bare sAMAccountName the
/// KDC expects. Handles the three forms that show up in real target lists:
///
///   * `user@corp.local`  — UPN; the realm suffix is dropped.
///   * `CORP\user`        — down-level logon name, e.g. from `net user /domain`,
///                          a client-supplied spreadsheet, or a BloodHound
///                          export. The domain prefix is dropped.
///   * `  user  `         — stray whitespace from hand-edited/pasted lists.
///
/// Left unhandled, the last two are worse than they look. The KDC answers a
/// principal like `CORP\user` with PRINCIPAL_UNKNOWN, so the account is never
/// actually tested and the operator reads "no valid credentials" from a spray
/// that silently skipped the target. And because the raw string is also the
/// lockout-budget key, a list mixing `user` with `CORP\user` gives ONE AD
/// account TWO budgets and spends double its bad passwords. `\` is not legal in
/// a sAMAccountName, so stripping the prefix is unambiguous.
///
/// BORROW: the result is a sub-slice of `username`.
pub fn formatUsername(username: []const u8) Error![]const u8 {
    const trimmed = std.mem.trim(u8, username, " \t");
    if (trimmed.len == 0) return Error.BlankUsername;
    // Down-level logon name: keep what follows the last backslash.
    const bare = if (std.mem.lastIndexOfScalar(u8, trimmed, '\\')) |i| trimmed[i + 1 ..] else trimmed;
    var it = std.mem.splitScalar(u8, bare, '@');
    const user = it.first();
    var count: usize = 1;
    while (it.next()) |_| count += 1;
    if (count > 2) return Error.TooManyAtSigns;
    if (user.len == 0) return Error.BlankUsername;
    return user;
}

pub const Combo = struct { username: []const u8, password: []const u8 };

/// Parse a "username:password" line. The username may carry an "@domain" which
/// is stripped. BORROW: results are sub-slices of `combo`.
pub fn formatComboLine(combo: []const u8) Error!Combo {
    const idx = std.mem.indexOfScalar(u8, combo, ':') orelse return Error.MissingColon;
    const user = try formatUsername(combo[0..idx]);
    const pass = combo[idx + 1 ..];
    if (pass.len == 0) return Error.BlankPassword;
    return .{ .username = user, .password = pass };
}

const testing = std.testing;

test "formatUsername strips domain" {
    try testing.expectEqualStrings("alice", try formatUsername("alice"));
    try testing.expectEqualStrings("alice", try formatUsername("alice@example.com"));
    try testing.expectError(Error.BlankUsername, formatUsername(""));
    try testing.expectError(Error.TooManyAtSigns, formatUsername("a@b@c"));
}

test "formatComboLine" {
    const c = try formatComboLine("alice@corp:S3cret:withcolon");
    try testing.expectEqualStrings("alice", c.username);
    try testing.expectEqualStrings("S3cret:withcolon", c.password);
    try testing.expectError(Error.MissingColon, formatComboLine("nocolon"));
    try testing.expectError(Error.BlankPassword, formatComboLine("user:"));
}

// REGRESSION TEST. These three spellings all name ONE AD account. Before this,
// only the UPN form was reduced: `CORP\jon.snow` was sent to the KDC verbatim
// (answered PRINCIPAL_UNKNOWN, so the account was silently never tested) and,
// being a distinct string, it also got its own lockout budget — so a list mixing
// forms spent double the bad passwords on a single account.
test "formatUsername reduces UPN, down-level and padded forms to one account" {
    const forms = [_][]const u8{
        "jon.snow",
        "jon.snow@north.sevenkingdoms.local",
        "NORTH\\jon.snow",
        "north.sevenkingdoms.local\\jon.snow",
        "  jon.snow  ",
        "\tNORTH\\jon.snow\t",
    };
    for (forms) |f| try testing.expectEqualStrings("jon.snow", try formatUsername(f));

    // Degenerate inputs stay errors rather than becoming empty principals.
    try testing.expectError(Error.BlankUsername, formatUsername("   "));
    try testing.expectError(Error.BlankUsername, formatUsername("NORTH\\"));
    try testing.expectError(Error.BlankUsername, formatUsername("@corp.local"));
    try testing.expectError(Error.TooManyAtSigns, formatUsername("a@b@c"));
}

test "formatComboLine reduces the username but never touches the password" {
    // A password may legitimately contain spaces, backslashes and '@'.
    const c = try formatComboLine("NORTH\\jon.snow:  P@ss\\word ");
    try testing.expectEqualStrings("jon.snow", c.username);
    try testing.expectEqualStrings("  P@ss\\word ", c.password);
}
