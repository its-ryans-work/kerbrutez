//! Build/version metadata. All values are comptime — no runtime version logic.
//!
//! The full version uses a "semvercal" scheme `MAJOR.YYYYMMDD.RUN_NUMBER`
//! (e.g. `1.20260604.47`), assembled by CI and injected via `-Dversion=`.
//! Local builds report `dev`.

const builtin = @import("builtin");
const build_options = @import("build_options");

/// Full version string (semvercal), or "dev" for local builds.
pub const version: []const u8 = build_options.version;

/// The Zig compiler version this binary was built with (comptime).
pub const zig_version: []const u8 = builtin.zig_version_string;

pub const author = "Ronnie Flathers @ropnop's kerbrute \nPorted to Zig via Ryan C @ibnbajja in two days. LLMs are crazy!";
