# Compilation

Prebuilt binaries for the most common platforms are on the
[Releases page](../../releases). This document is for building **from source** or
for **a target we don't publish**.

## Requirements

* **Zig 0.16.0** — mandatory. The project uses the 0.16 `Io` std API and will
  **not** compile on 0.13/0.14/0.15. Check with `zig version`.
* No third-party dependencies — only the Zig standard library.

Zig is a single self-contained toolchain (no system C toolchain or linker
needed), so the build is identical on every platform.

## Building

```sh
zig build                          # debug build  -> zig-out/bin/kerbrutez
zig build -Doptimize=ReleaseFast   # optimized build (recommended)
zig build test                     # run the krb5 + ldap + app unit tests
zig build run -- version           # build and run with args
```

The binary is written to `zig-out/bin/kerbrutez` (`.exe` on Windows). To keep
the source tree clean you can redirect the build output and cache:

```sh
zig build -Doptimize=ReleaseFast -p out --cache-dir .cache
```

## Installing Zig 0.16

Distro/Homebrew packages may lag; the official tarballs below guarantee 0.16.0.

**macOS**
```sh
brew install zig            # only if Homebrew currently ships 0.16
# or, version-pinned:
curl -L https://ziglang.org/download/0.16.0/zig-macos-aarch64-0.16.0.tar.xz | tar -xJ
export PATH="$PWD/zig-macos-aarch64-0.16.0:$PATH"   # use -x86_64- on Intel Macs
```

**Linux**
```sh
curl -L https://ziglang.org/download/0.16.0/zig-linux-x86_64-0.16.0.tar.xz | tar -xJ
export PATH="$PWD/zig-linux-x86_64-0.16.0:$PATH"    # use -aarch64- on ARM
git clone <repo> && cd kerbrutez && zig build -Doptimize=ReleaseFast
```

**Windows**
```powershell
# winget install zig.zig   # if it provides 0.16, otherwise download the zip:
# https://ziglang.org/download/0.16.0/zig-windows-x86_64-0.16.0.zip
# unzip, add the folder to PATH, then from the repo:
zig build -Doptimize=ReleaseFast
# binary at zig-out\bin\kerbrutez.exe
```

## Cross-compilation

Zig cross-compiles out of the box — build for any OS/arch from any host with
`-Dtarget`:

```sh
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl     # static Linux x86-64
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-musl    # static Linux ARM64
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-windows-gnu    # Windows x86-64
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-macos         # Apple Silicon
```

## Releases & versioning

Every push to `main` runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which
cross-compiles the binaries above and publishes them as a GitHub Release.

Version strings use a calendar scheme, `MAJOR.YYYYMMDD.RUN_NUMBER`
(e.g. `0.20260605.71`):

* `MAJOR` is `const semvercal_major` in [`build.zig`](build.zig); bump it
  manually on a breaking change.
* `YYYYMMDD` is the build date and `RUN_NUMBER` is the CI run number, assembled
  by the workflow and injected with `zig build -Dversion=…`.
* Local builds (no `-Dversion`) report `dev`.

The version is comptime (`@import("build_options").version`) and shown in the
banner, in `--help`, and via `kerbrutez version` (alongside the Zig compiler
version it was built with).

## A note on tests

* **Unit tests** are inline `test { ... }` blocks in each source file (idiomatic
  Zig — not separate files). They run with `zig build test` and cover private
  functions (DER encoding, RFC 8009 key-derivation vectors, the `$krb5tgs$`
  formatter, etc.).
* **Local/integration testing** — driving the built binary against a live KDC,
  with wordlists (which may contain real credentials), result logs and build
  artifacts — lives in a `testing/` directory that is **git-ignored** and never
  committed.
