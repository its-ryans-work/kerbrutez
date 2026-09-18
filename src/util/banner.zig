const std = @import("std");
const version = @import("version.zig");

const banner =
    \\
    \\    __             __               __            
    \\   / /_____  _____/ /_  _______  __/ /____  ____/\ 
    \\  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \/__   /
    \\ / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/  /  /__
    \\/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/  / ____/
    \\                                            \/
;

/// One-line authorized-use notice, shown in the banner and --help.
pub const authorized_use_notice =
    "For AUTHORIZED security testing only. Use against systems you own or have explicit written permission to assess.";

const ansi_yellow = "\x1b[33m";
const ansi_reset = "\x1b[0m";
/// Column at which the stylised "z" flourish begins on each art line. The
/// kerbrute lettering ends at column <= 42; everything from here is the z.
const z_col = 43;

/// Print the kerbrute banner to the given writer, with the stylised "z" flourish
/// (everything from column `z_col` onward on each line) accented in yellow.
/// Print the banner. `colour` gates the yellow "z" flourish: a redirected run
/// (`> run.log`, `| grep`, CI) should not get raw ANSI escapes baked into the
/// file — the banner was the last place still emitting them unconditionally.
pub fn printBanner(w: *std.Io.Writer, colour: bool) !void {
    var it = std.mem.splitScalar(u8, banner, '\n');
    var first = true;
    while (it.next()) |line| {
        if (!first) try w.writeByte('\n');
        first = false;
        if (!colour) {
            try w.writeAll(line);
            continue;
        }
        if (line.len > z_col) {
            try w.writeAll(line[0..z_col]);
            try w.print("{s}{s}{s}", .{ ansi_yellow, line[z_col..], ansi_reset });
        } else {
            try w.writeAll(line);
        }
    }
    try w.print("\nVersion: {s}  (built with Zig {s})  -  {s}\n{s}\n\n", .{
        version.version,
        version.zig_version,
        version.author,
        authorized_use_notice,
    });
}
