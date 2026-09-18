const std = @import("std");

/// SEMVERCAL MAJOR — the `MAJOR` in `MAJOR.YYYYMMDD.RUN_NUMBER`.
/// Bump manually on breaking changes. The CI workflow greps this value.
const semvercal_major = 0; // SEMVERCAL_MAJOR — 0.x until the new features land

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Full version string. CI passes the assembled semvercal version via
    // `-Dversion=MAJOR.YYYYMMDD.RUN_NUMBER`; local builds default to "dev".
    const version = b.option([]const u8, "version", "Full semvercal version string (MAJOR.YYYYMMDD.RUN_NUMBER)") orelse "dev";

    // Exposed to the app as the `build_options` module, read at comptime.
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    // The krb5 library module — a standalone, reusable Zig Kerberos
    // implementation (the gokrb5 replacement). Kept distinct from the
    // kerbrute application code so it can be extracted/reused on its own.
    const krb5_mod = b.addModule("krb5", .{
        .root_source_file = b.path("krb5/krb5.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The ldap library module — a standalone, dependency-free LDAP v3 client.
    // Sibling of krb5; kept separate so it can be reused on its own.
    const ldap_mod = b.addModule("ldap", .{
        .root_source_file = b.path("ldap/ldap.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The kerbrute application module, which depends on krb5 + ldap.
    const app_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    app_mod.addImport("krb5", krb5_mod);
    app_mod.addImport("ldap", ldap_mod);
    app_mod.addOptions("build_options", build_options);

    const exe = b.addExecutable(.{
        .name = "kerbrutez",
        .root_module = app_mod,
    });
    b.installArtifact(exe);

    // `zig build run -- <args>`
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run kerbrutez");
    run_step.dependOn(&run_cmd.step);

    // `zig build test` — runs the krb5 library + app unit tests.
    const test_step = b.step("test", "Run unit tests");

    const krb5_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("krb5/krb5.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(krb5_tests).step);

    const ldap_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("ldap/ldap.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(ldap_tests).step);

    // Application-layer tests (depend on the krb5 + ldap modules).
    const app_test_mod = b.createModule(.{
        .root_source_file = b.path("src/test_all.zig"),
        .target = target,
        .optimize = optimize,
    });
    app_test_mod.addImport("krb5", krb5_mod);
    app_test_mod.addImport("ldap", ldap_mod);
    app_test_mod.addOptions("build_options", build_options);
    const app_tests = b.addTest(.{ .root_module = app_test_mod });
    test_step.dependOn(&b.addRunArtifact(app_tests).step);
}
