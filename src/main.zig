const std = @import("std");
const Io = std.Io;
const banner = @import("util/banner.zig");
const cli = @import("cli.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    // Collect argv into an owned slice for the CLI parser.
    var args: std.ArrayList([]const u8) = .empty;
    defer {
        for (args.items) |a| gpa.free(a);
        args.deinit(gpa);
    }
    var arg_it = try init.minimal.args.iterateAllocator(gpa);
    defer arg_it.deinit();
    while (arg_it.next()) |a| {
        try args.append(gpa, try gpa.dupe(u8, a));
    }

    // Banner to stdout (matches kerbrute's main).
    {
        var buf: [1024]u8 = undefined;
        var w = Io.File.stdout().writerStreaming(io, &buf);
        banner.printBanner(&w.interface, Io.File.stdout().isTty(io) catch false) catch {};
        w.interface.flush() catch {};
    }

    // Home directory (for the persisted "hide this message" preference).
    const home: ?[]const u8 = init.environ_map.array_hash_map.get("HOME");

    const code = cli.run(gpa, io, args.items, home);
    if (code != 0) std.process.exit(code);
}
