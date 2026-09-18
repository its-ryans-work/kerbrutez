//! Aggregates the kerbrute application-layer unit tests.

const std = @import("std");

test {
    _ = @import("util/username.zig");
    _ = @import("util/hash.zig");
    _ = @import("util/log.zig");
    _ = @import("util/spinlock.zig");
    _ = @import("util/secret_file.zig");
    _ = @import("util/banner.zig");
    _ = @import("util/version.zig");
    _ = @import("util/status.zig");
    _ = @import("session/errors.zig");
    _ = @import("session/session.zig");
    _ = @import("state/store.zig");
    _ = @import("state/dedup.zig");
    _ = @import("engine/budget.zig");
    _ = @import("engine/opsec.zig");
    _ = @import("report/report.zig");
    _ = @import("policy/policy.zig");
    _ = @import("workers.zig");
    _ = @import("bloodhound.zig");
    _ = @import("cli.zig");
    _ = @import("test_integration.zig");
    std.testing.refAllDecls(@This());
}
