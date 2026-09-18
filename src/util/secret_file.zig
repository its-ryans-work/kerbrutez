//! Creation permissions for files that hold engagement secrets.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

/// Owner-only (0600) on POSIX.
///
/// kerbrutez writes the client's cracked passwords, crackable AS-REP/TGS hashes,
/// and a log of every password it has TRIED into these files. The default
/// (0o666 & ~umask, usually 0644) leaves all of that readable by every local
/// user — and pentest work routinely runs on shared jump hosts, team boxes and
/// multi-user C2 infrastructure, where "local user" is not just the operator.
///
/// Windows permissions here are an attribute bitfield rather than a POSIX mode
/// (0o600 would set unrelated attribute bits), so Windows keeps the default and
/// relies on the containing directory's ACL.
pub const permissions: Io.File.Permissions = if (builtin.os.tag == .windows)
    .default_file
else
    @enumFromInt(0o600);

/// `createFile` with owner-only permissions, otherwise identical.
///
/// NOTE: like any O_CREAT mode, this applies only when the file is CREATED. A
/// state log written by an older build keeps its original permissions; use
/// `tighten` to fix one that already exists.
pub fn create(io: Io, path: []const u8, opts: Io.Dir.CreateFileOptions) !Io.File {
    var o = opts;
    o.permissions = permissions;
    return Io.Dir.cwd().createFile(io, path, o);
}

/// Best-effort chmod of an already-open secret file to owner-only, for files
/// that outlive a single run (the shared state log). Silently does nothing on
/// Windows or if the platform rejects it — this is defence in depth, not a
/// precondition for the run.
/// Uses the Io-native `setPermissions` rather than a libc `fchmod`, which would
/// force every target to link libc (the Linux cross-builds do not).
pub fn tighten(io: Io, file: Io.File) void {
    if (builtin.os.tag == .windows) return;
    file.setPermissions(io, permissions) catch {};
}

test "secret files are owner-only on POSIX" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), @intFromEnum(permissions));
}

/// Create/open a file holding an EXCLUSIVE advisory lock, blocking until it is
/// acquired. Closing the returned handle releases the lock; the OS also releases
/// it if the process dies, so a crashed run cannot wedge the others.
pub fn createLocked(io: Io, path: []const u8) !Io.File {
    return Io.Dir.cwd().createFile(io, path, .{
        .truncate = false,
        .permissions = permissions,
        .lock = .exclusive,
    });
}
