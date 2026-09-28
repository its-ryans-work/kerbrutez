//! NDJSON attempt store — the single source of truth for campaign progress.
//! One JSON object per attempt, appended to a file. Replaying the file (see
//! dedup.zig and, later, the windowed budget) reconstructs state across runs.
//!
//! Schema (one line each):
//!   {"realm","dc","user","password","timestamp"(ISO-8601 UTC),"result",
//!    "kdc_error":{"name","code"}}

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const secret_file = @import("../util/secret_file.zig");
const SpinLock = @import("../util/spinlock.zig").SpinLock;
const budget_mod = @import("../engine/budget.zig");

/// Classification of an attempt's outcome (the `result` field).
pub const Result = enum {
    valid,
    invalid,
    user_unknown,
    locked,
    /// Account exists but is unusable for reasons OTHER than a lockout we
    /// caused: disabled, expired, logon-hours/workstation restricted. AD reports
    /// all of these as KDC_ERR_CLIENT_REVOKED, same as a lockout — only the
    /// e-data NTSTATUS tells them apart. Kept distinct from `locked` so these
    /// never consume the --panic-after lockout budget.
    revoked,
    expired, // valid credential, password expired — a win
    skew, // clock skew, but pre-auth succeeded — valid
    network_error,
    decrypt_error,
};

/// One attempt to record. `realm`/`dc`/`timestamp` are filled in by the store.
pub const Attempt = struct {
    user: []const u8,
    /// Empty for username enumeration (no password tried).
    password: []const u8 = "",
    result: Result,
    kdc_error_name: []const u8 = "",
    kdc_error_code: i32 = 0,
};

const KdcErrorJson = struct { name: []const u8, code: i32 };
const RecordJson = struct {
    realm: []const u8,
    dc: []const u8,
    user: []const u8,
    password: []const u8,
    timestamp: []const u8,
    result: []const u8,
    kdc_error: KdcErrorJson,
    /// Which half of an attempt this record is.
    ///
    /// "attempt" is the RESERVATION, published before the KDC is contacted and
    /// while the cross-process lock is held; it is what the lockout budget
    /// counts, exactly one per attempt. "result" is the outcome written
    /// afterwards, which the budget ignores (counting both would halve every
    /// account's budget). Records from older versions carry no phase and are
    /// counted, which is correct — they were written one per attempt.
    phase: []const u8,
    /// Identifies the PROCESS that wrote this record. The lockout budget tails
    /// this log to pick up attempts made by OTHER concurrent kerbrutez runs
    /// (see Budget.refreshFromLog); without a way to recognise its own lines it
    /// would count every attempt twice. Readers that predate this field ignore
    /// it (all parsing uses ignore_unknown_fields).
    run: []const u8,
    /// Record kind. "attempt" = a real password/enumeration attempt (the only
    /// kind older builds ever wrote, hence the default on every reader). "user" =
    /// a ROSTER entry: a username ingested (nxc/BloodHound/LDAP) and persisted so
    /// a later spray can target it without re-supplying a list. EVERY attempt-
    /// replay reader (dedup, lockout budget, locked-set) gates on this and skips
    /// anything that isn't "attempt", so a roster line can never consume a
    /// lockout budget, seed a dedup key, or clear a recorded lockout.
    kind: []const u8,
};

/// The one record kind the budget/dedup/locked-set readers count. Roster
/// records use `roster_kind`; anything else a reader sees is ignored.
pub const attempt_kind = "attempt";
pub const roster_kind = "user";

/// Upper bound on how much of the state log a full replay reads into memory.
/// The log is append-only and can grow across a long/`--retry` campaign; an
/// unbounded read OOMs a memory-constrained Kali VM, and the OOM path used to
/// fail OPEN (empty locked-set => re-spray locked accounts => lockout). 256 MiB
/// is far past any realistic per-realm log; a file larger than this is treated
/// as unreadable and fails CLOSED at the preflight (see cli.zig).
pub const max_state_bytes: usize = 256 * 1024 * 1024;

pub const Store = struct {
    allocator: Allocator,
    io: Io,
    /// BORROW: realm/dc must outlive the store (they come from the config).
    realm: []const u8,
    dc: []const u8,
    file: Io.File,
    /// Path this store appends to; used to derive the sidecar lock file.
    /// BORROW: must outlive the store.
    path: []const u8 = "",
    pos: u64,
    lock: SpinLock = .{},
    /// This process's identity in the shared log. BORROW: set by the caller.
    run_id: []const u8 = "",

    /// Open (creating if needed) the NDJSON log for appending. Existing content
    /// is preserved so a campaign resumes. OWNERSHIP: call `deinit`.
    pub fn open(allocator: Allocator, io: Io, path: []const u8, realm: []const u8, dc: []const u8) !Store {
        // Holds EVERY password this campaign has tried, in cleartext.
        const file = try secret_file.create(io, path, .{ .truncate = false });
        // The state log persists across runs, so one created by an older build
        // keeps its old (world-readable) mode — creation flags don't apply to an
        // existing file. Fix it in place.
        secret_file.tighten(io, file);
        const pos: u64 = if (file.stat(io)) |st| st.size else |_| 0;
        return .{ .allocator = allocator, .io = io, .realm = realm, .dc = dc, .file = file, .path = path, .pos = pos };
    }

    pub fn deinit(self: *Store) void {
        self.file.close(self.io);
    }

    /// Append the OUTCOME of an attempt (phase "result"). Not counted by the
    /// lockout budget — the reservation already was.
    ///
    /// Takes the cross-process sidecar lock (see `appendLocking`): the outcome
    /// write must not clobber a concurrent process's reservation.
    pub fn append(self: *Store, attempt: Attempt) !void {
        return self.appendLocking(attempt, "result", attempt_kind);
    }

    /// Persist a username to the shared roster (record kind "user"). Ingest
    /// commands (nxc/BloodHound/LDAP) call this so `spray @state` can later target
    /// every known user without a fresh list. It is INVISIBLE to the attempt-
    /// replay readers (they gate on kind == "attempt"), so it never touches the
    /// lockout budget, the dedup index, or the locked-account memory.
    pub fn appendUser(self: *Store, user: []const u8) !void {
        return self.appendLocking(.{ .user = user, .result = .invalid }, "roster", roster_kind);
    }

    /// Publish a RESERVATION (phase "attempt") for a slot we are about to spend.
    ///
    /// This is what makes the per-user budget a cross-process guarantee: it is
    /// written while the exclusive lock is held and BEFORE the KDC is contacted,
    /// so any other process that takes the lock next already sees this attempt.
    /// The CALLER (reserveSlot / the one-shot path) already holds the sidecar
    /// lock across refresh->decide->publish, so this does NOT re-take it — doing
    /// so would self-deadlock the same-process flock.
    pub fn appendReservation(self: *Store, user: []const u8, password: []const u8) !void {
        return self.appendRecord(.{ .user = user, .password = password, .result = .invalid }, "attempt", attempt_kind);
    }

    /// Publish an EXTRA reservation for a guess that fired outside the reserved
    /// slot — a corrected-etype/salt retry puts a second PA-ENC-TIMESTAMP on the
    /// wire and AD counts it, but the caller is past the network round-trip and no
    /// longer holds the sidecar lock. Unlike `appendReservation`, this TAKES the
    /// lock so other concurrent processes tail it and count the extra bad
    /// password against the shared per-user budget (in-process it is already
    /// charged via Budget.addHistorical).
    pub fn appendExtraReservation(self: *Store, user: []const u8) !void {
        return self.appendLocking(.{ .user = user, .result = .invalid }, "attempt", attempt_kind);
    }

    /// Open the sidecar lock file with an EXCLUSIVE advisory lock, blocking
    /// until it is ours. Closing the returned handle releases it — and the OS
    /// releases it if the process dies, so a crash cannot wedge other runs.
    /// Returns null if the lock cannot be taken at all; callers then fall back
    /// to the in-process budget rather than refusing to work.
    pub fn lockExclusive(self: *Store, io: Io) ?Io.File {
        var buf: [640]u8 = undefined;
        const lock_path = std.fmt.bufPrint(&buf, "{s}.lock", .{self.path}) catch return null;
        return secret_file.createLocked(io, lock_path) catch null;
    }

    /// Append while holding the exclusive sidecar lock, for writers NOT already
    /// under it (attempt outcomes, predicted-lock records, roster entries).
    ///
    /// WHY: `appendRecord` re-stats the file for the true EOF, but stat+write is
    /// not atomic across processes. Two operators sharing one state log (or a
    /// spray running beside a kerberoast) could each stat the same size and write
    /// at the same offset, so one record — often a RESERVATION the other process
    /// needs to see — is silently overwritten, the cross-process budget
    /// under-counts, and the client's accounts lock. Serialise every unguarded
    /// writer against every other. If the lock can't be taken we still write
    /// (degraded to the old behaviour, never worse). Reservations are excluded:
    /// their caller already holds this lock, and re-taking it would self-deadlock.
    fn appendLocking(self: *Store, attempt: Attempt, phase: []const u8, kind: []const u8) !void {
        const guard = self.lockExclusive(self.io);
        defer if (guard) |g| g.close(self.io);
        return self.appendRecord(attempt, phase, kind);
    }

    /// Append one NDJSON record of the given `kind`. Thread-safe within the
    /// process (spinlock); cross-process safety is the caller's sidecar lock.
    /// BORROW: nothing in `attempt` is retained after this returns.
    fn appendRecord(self: *Store, attempt: Attempt, phase: []const u8, kind: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        var ts_buf: [24]u8 = undefined;
        const ts = isoTimestamp(self.io, &ts_buf);

        const record = RecordJson{
            .realm = self.realm,
            .dc = self.dc,
            .user = attempt.user,
            .password = attempt.password,
            .timestamp = ts,
            .result = @tagName(attempt.result),
            .kdc_error = .{ .name = attempt.kdc_error_name, .code = attempt.kdc_error_code },
            .run = self.run_id,
            .phase = phase,
            .kind = kind,
        };

        const json = try std.json.Stringify.valueAlloc(self.allocator, record, .{});
        defer self.allocator.free(json);

        // Write at the file's CURRENT end, not at an offset cached when we
        // opened it. The state file is shared: another kerbrutez process (a
        // second operator, or a parallel run against the same realm) may have
        // appended since. Trusting our own stale offset overwrites everything
        // they wrote — and lost attempt records make the replayed budget
        // undercount, which is precisely how accounts end up locked.
        // Re-stat is cheap next to the KDC round-trip this record describes.
        const end: u64 = if (self.file.stat(self.io)) |st| @max(st.size, self.pos) else |_| self.pos;

        var buf: [512]u8 = undefined;
        var w = self.file.writer(self.io, &buf);
        w.pos = end;
        try w.interface.writeAll(json);
        try w.interface.writeAll("\n");
        try w.interface.flush();
        self.pos = end + json.len + 1;
    }
};

/// Sentinel for "seen locked, but we could not read WHEN".
///
/// The obvious `orelse 0` is a fail-OPEN: `isBlocked` computes `now - ts`, and
/// with ts=0 that is ~1.8 billion seconds, past any lockout duration — so an
/// unreadable timestamp silently put a locked account back into the spray. The
/// state file persists across runs and is shared between concurrent processes,
/// so a truncated or hand-edited line is not hypothetical. Unknown time means
/// stay blocked; `--retry-locked` is the escape hatch.
pub const unknown_lock_time: i64 = std.math.maxInt(i64);

/// Why an account is out of rotation. `locked` is a TEMPORARY AD lockout that
/// AD releases after lockoutDuration, so the skip must age out (we only learn of
/// recovery by re-testing). `revoked` is PERMANENT-until-admin — disabled,
/// expired, logon-hours/workstation restricted — and must NEVER age out: retrying
/// a disabled account every TTL forever is pure wasted noise, and (worse) letting
/// it back in re-charges a stale non-lockout against --panic-after.
pub const LockReason = enum { locked, revoked };
const LockEntry = struct { ts: i64, reason: LockReason };

/// Accounts seen locked/revoked, each with WHEN and WHY it was last seen that way.
/// Owns its keys. Free with `deinit`.
pub const LockedSet = struct {
    allocator: Allocator,
    map: std.StringHashMapUnmanaged(LockEntry) = .empty,

    pub fn deinit(self: *LockedSet) void {
        var it = self.map.keyIterator();
        while (it.next()) |k| self.allocator.free(k.*);
        self.map.deinit(self.allocator);
    }

    pub fn count(self: *const LockedSet) usize {
        return self.map.count();
    }

    /// Should `user` still be skipped at `now`?
    ///
    /// A REVOKED (disabled/expired/restricted) account is skipped unconditionally
    /// — it does not recover on a timer, so re-testing it every TTL is noise.
    ///
    /// For a temporary LOCKOUT, EXPIRY IS NOT OPTIONAL. AD releases it after the
    /// lockout duration, but we only ever learn an account recovered by trying it.
    /// Skipping locked accounts unconditionally is self-sealing: the account is
    /// skipped, so no new record is written, so it stays skipped FOREVER, silently
    /// eroding coverage. Ageing the skip out puts recovered accounts back in play.
    pub fn isBlocked(self: *const LockedSet, user: []const u8, now: i64, expire_after_secs: i64) bool {
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const e = self.map.get(budget_mod.accountKey(&kbuf, user)) orelse return false;
        if (e.reason == .revoked) return true; // permanent: never age out
        if (e.ts == unknown_lock_time) return true; // fail closed: see the constant
        if (expire_after_secs <= 0) return true; // expiry disabled
        return (now - e.ts) < expire_after_secs;
    }

    /// The reason `user` is out of rotation, or null if not blocked at all
    /// (ignoring TTL — callers that need the reason already know it is listed).
    pub fn reasonFor(self: *const LockedSet, user: []const u8) ?LockReason {
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const e = self.map.get(budget_mod.accountKey(&kbuf, user)) orelse return null;
        return e.reason;
    }
};

/// Replay the NDJSON store and collect every account seen LOCKED or REVOKED
/// (disabled/expired/restricted) in `realm` during an earlier run.
///
/// This is what makes lockouts survive a restart. Without it the locked set is
/// per-process, so a resumed campaign happily sprays accounts it locked five
/// minutes ago — re-confirming the lockout, spending the panic-stop budget on
/// accounts it locked earlier, and reporting them as freshly locked.
///
/// A later successful/invalid attempt for the same user clears them again: that
/// means the account was unlocked (lockout durations expire), so it's back in
/// play. OWNERSHIP: caller calls `deinit`.
pub fn loadLockedFromLog(allocator: Allocator, io: Io, path: []const u8, realm: []const u8) LockedSet {
    var set = LockedSet{ .allocator = allocator };
    var file = Io.Dir.cwd().openFile(io, path, .{}) catch return set; // missing => fresh
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    const content = reader.interface.allocRemaining(allocator, .limited(max_state_bytes)) catch return set;
    defer allocator.free(content);

    const Rec = struct { realm: []const u8, user: []const u8, result: []const u8, timestamp: []const u8, phase: []const u8 = "", kind: []const u8 = attempt_kind };
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const parsed = std.json.parseFromSlice(Rec, allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.realm, realm)) continue;
        // Only real attempts speak to whether an account is locked. A ROSTER
        // record ("user") carries result "invalid" and would otherwise fall into
        // the else-branch below and CLEAR a recorded lockout — re-arming a spray
        // against an account we locked. Skip every non-attempt kind.
        if (!std.mem.eql(u8, parsed.value.kind, attempt_kind)) continue;
        // A RESERVATION carries no outcome yet, so it must not be read as
        // evidence the account is usable again — otherwise publishing the
        // reservation would clear the very lockout we are trying to respect.
        if (std.mem.eql(u8, parsed.value.phase, "attempt")) continue;
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const user = budget_mod.accountKey(&kbuf, parsed.value.user);
        const is_locked = std.mem.eql(u8, parsed.value.result, "locked");
        const is_revoked = std.mem.eql(u8, parsed.value.result, "revoked");
        if (is_locked or is_revoked) {
            const ts = budget_mod.parseIso8601(parsed.value.timestamp) orelse unknown_lock_time;
            const reason: LockReason = if (is_revoked) .revoked else .locked;
            const gop = set.map.getOrPut(allocator, user) catch continue;
            if (!gop.found_existing) {
                gop.key_ptr.* = allocator.dupe(u8, user) catch {
                    _ = set.map.remove(user);
                    continue;
                };
                gop.value_ptr.* = .{ .ts = ts, .reason = reason };
            } else {
                if (ts > gop.value_ptr.ts) gop.value_ptr.ts = ts; // most recent
                // Permanent revocation outranks a temporary lockout: once we have
                // seen the account disabled/expired, keep it out for good.
                if (is_revoked) gop.value_ptr.reason = .revoked;
            }
        } else if (resultProvesUsable(parsed.value.result)) {
            // Clear the lock ONLY on an AUTHORITATIVE KDC verdict that the account
            // answered normally. A network_error (KDC never answered) or a
            // decrypt_error (our own crypto path) proves NOTHING about the
            // account, yet the old unconditional else cleared the lock for every
            // non-locked/revoked result — so a transient blip after a lockout
            // record silently put a locked (or permanently disabled) client
            // account back into the spray. Fail closed: keep it out unless a real
            // verdict says otherwise.
            if (set.map.fetchRemove(user)) |kv| allocator.free(kv.key);
        }
    }
    return set;
}

/// Does this attempt `result` prove the account is usable again (so a prior
/// lockout/revocation record should be cleared)? Only authoritative KDC verdicts
/// count: the account accepted or rejected a credential, or answered with an
/// expired password / clock skew (pre-auth still succeeded). Inconclusive
/// outcomes — network_error, decrypt_error — and the ambiguous user_unknown do
/// NOT clear a recorded lockout.
fn resultProvesUsable(result: []const u8) bool {
    inline for (.{ "valid", "invalid", "expired", "skew" }) |ok| {
        if (std.mem.eql(u8, result, ok)) return true;
    }
    return false;
}

/// Replay the NDJSON store and collect every username persisted to the ROSTER
/// (record kind "user") in `realm`, deduped case-insensitively with the
/// first-seen spelling kept. This is the source for `spray @state`, so an
/// operator who ran an ingest (`ldapenum --nxc` / `--bloodhound` / live LDAP)
/// can spray every known user without re-supplying a list.
///
/// Missing/unreadable file => empty list (not an error): a spray with no roster
/// simply has nothing to do, which the caller reports. OWNERSHIP: caller frees
/// each string AND the returned slice.
pub fn loadRosterFromLog(allocator: Allocator, io: Io, path: []const u8, realm: []const u8) ![][]const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (out.items) |u| allocator.free(u);
        out.deinit(allocator);
    }
    // Case-insensitive dedup key set (owned here, freed before return).
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer {
        var kit = seen.keyIterator();
        while (kit.next()) |k| allocator.free(k.*);
        seen.deinit(allocator);
    }

    var file = Io.Dir.cwd().openFile(io, path, .{}) catch return out.toOwnedSlice(allocator);
    defer file.close(io);
    var rbuf: [4096]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    const content = reader.interface.allocRemaining(allocator, .limited(max_state_bytes)) catch return out.toOwnedSlice(allocator);
    defer allocator.free(content);

    const Rec = struct { realm: []const u8, user: []const u8, kind: []const u8 = attempt_kind };
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const parsed = std.json.parseFromSlice(Rec, allocator, trimmed, .{ .ignore_unknown_fields = true }) catch continue;
        defer parsed.deinit();
        if (!std.mem.eql(u8, parsed.value.kind, roster_kind)) continue;
        if (!std.mem.eql(u8, parsed.value.realm, realm)) continue;
        if (parsed.value.user.len == 0) continue;

        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const key = budget_mod.accountKey(&kbuf, parsed.value.user);
        if (seen.contains(key)) continue;
        const owned_key = allocator.dupe(u8, key) catch continue;
        seen.put(allocator, owned_key, {}) catch {
            allocator.free(owned_key);
            continue;
        };
        const owned_user = try allocator.dupe(u8, parsed.value.user);
        out.append(allocator, owned_user) catch |e| {
            allocator.free(owned_user); // don't leak the dupe if append OOMs
            return e;
        };
    }
    return out.toOwnedSlice(allocator);
}

/// Format the current UTC time as ISO-8601 "YYYY-MM-DDTHH:MM:SSZ".
fn isoTimestamp(io: Io, out: *[24]u8) []const u8 {
    const now = Io.Timestamp.now(io, .real).toSeconds();
    const days = @divFloor(now, 86400);
    var rem = @mod(now, 86400);
    const hour: u32 = @intCast(@divFloor(rem, 3600));
    rem -= @as(i64, hour) * 3600;
    const minute: u32 = @intCast(@divFloor(rem, 60));
    const second: u32 = @intCast(rem - @as(i64, minute) * 60);
    const ymd = civilFromDays(days);
    return std.fmt.bufPrint(out, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u32, @intCast(ymd.year)), ymd.month, ymd.day, hour, minute, second,
    }) catch out[0..0];
}

const YMD = struct { year: i64, month: u32, day: u32 };

fn civilFromDays(days: i64) YMD {
    const z = days + 719468;
    const era = @divFloor(if (z >= 0) z else z - 146096, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    return .{ .year = if (m <= 2) y + 1 else y, .month = @intCast(m), .day = @intCast(d) };
}

const testing = std.testing;

test "store append writes parseable NDJSON and round-trips" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_store.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    {
        var store = try Store.open(a, io, path, "EXAMPLE.COM", "dc01:88");
        defer store.deinit();
        try store.append(.{ .user = "alice", .password = "p\"w\\1", .result = .invalid, .kdc_error_name = "KDC_ERR_PREAUTH_FAILED", .kdc_error_code = 24 });
        try store.append(.{ .user = "bob", .password = "secret", .result = .valid });
    }

    // Read back and verify both lines parse.
    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [256]u8 = undefined;
    var r = f.reader(io, &rbuf);
    const content = try r.interface.allocRemaining(a, .unlimited);
    defer a.free(content);

    var it = std.mem.tokenizeScalar(u8, content, '\n');
    const DedupRec = struct { realm: []const u8, user: []const u8, password: []const u8 };
    const l1 = it.next().?;
    const p1 = try std.json.parseFromSlice(DedupRec, a, l1, .{ .ignore_unknown_fields = true });
    defer p1.deinit();
    try testing.expectEqualStrings("EXAMPLE.COM", p1.value.realm);
    try testing.expectEqualStrings("alice", p1.value.user);
    try testing.expectEqualStrings("p\"w\\1", p1.value.password); // escaping survived
    const l2 = it.next().?;
    const p2 = try std.json.parseFromSlice(DedupRec, a, l2, .{ .ignore_unknown_fields = true });
    defer p2.deinit();
    try testing.expectEqualStrings("bob", p2.value.user);
}

test "loadLockedFromLog remembers locked accounts across runs, and forgets expired ones" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_locked.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "alice", .password = "p1", .result = .invalid });
        try s.append(.{ .user = "alice", .password = "p2", .result = .locked }); // we locked alice
        try s.append(.{ .user = "guest", .password = "p1", .result = .revoked }); // disabled, not ours
        try s.append(.{ .user = "bob", .password = "p1", .result = .locked });
        try s.append(.{ .user = "bob", .password = "p2", .result = .invalid }); // bob's lockout expired
        try s.append(.{ .user = "carol", .password = "p1", .result = .invalid });
    }
    // A different realm's records must not leak in.
    {
        var s2 = try Store.open(a, io, path, "OTHER.COM", "dc:88");
        defer s2.deinit();
        try s2.append(.{ .user = "mallory", .password = "p1", .result = .locked });
    }

    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expect(set.map.contains("alice")); // still locked
    try testing.expect(set.map.contains("guest")); // disabled: don't bother
    try testing.expect(!set.map.contains("bob")); // answered again => unlocked
    try testing.expect(!set.map.contains("carol")); // never locked
    try testing.expect(!set.map.contains("mallory")); // other realm
    try testing.expectEqual(@as(usize, 2), set.count());
}

// REGRESSION TEST for a self-sealing skip list. Skipping locked accounts is
// correct, but we only ever learn an account recovered by TRYING it — so an
// unconditional skip means no new record is ever written for that account and
// it stays skipped forever. Over a multi-day engagement that silently erodes
// coverage to nothing. The skip must age out.
test "locked accounts return to rotation once the lockout duration passes" {
    const a = testing.allocator;
    var set = LockedSet{ .allocator = a };
    defer set.deinit();
    const locked_at: i64 = 1_000_000;
    try set.map.put(a, try a.dupe(u8, "alice"), .{ .ts = locked_at, .reason = .locked });

    const ttl: i64 = 30 * 60;
    try testing.expect(set.isBlocked("alice", locked_at + 60, ttl)); // 1 min later: still out
    try testing.expect(set.isBlocked("alice", locked_at + ttl - 1, ttl)); // just before
    try testing.expect(!set.isBlocked("alice", locked_at + ttl, ttl)); // duration passed: back in play
    try testing.expect(!set.isBlocked("bob", locked_at, ttl)); // never locked

    // Case-insensitive: AD would treat these as the same account.
    try testing.expect(set.isBlocked("Alice", locked_at + 60, ttl));
    try testing.expect(set.isBlocked("ALICE", locked_at + 60, ttl));

    // ttl <= 0 means AD's lockoutDuration is "until an admin unlocks" — the
    // skip must then be permanent, never silently expiring.
    try testing.expect(set.isBlocked("alice", locked_at + 999_999, 0));
}

// REGRESSION TEST for concurrent operators sharing one state file. The store is
// explicitly designed so independent runs see each other's attempts, but each
// process captured the file size ONCE at open and then wrote at its own running
// offset — so a second process's writes land on top of everything the first
// wrote after that moment. Lost attempt records make the replayed budget
// undercount, which is exactly how accounts get locked.
test "a second writer does not clobber records appended since it opened" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_store_concurrent.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Two "processes" hold the same state file at the same time.
    var s1 = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
    defer s1.deinit();
    var s2 = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
    defer s2.deinit();

    try s1.append(.{ .user = "alice", .password = "p1", .result = .invalid });
    try s1.append(.{ .user = "alice", .password = "p2", .result = .invalid });
    // s2 opened when the file was empty; its write must go AFTER s1's records.
    try s2.append(.{ .user = "bob", .password = "p1", .result = .invalid });

    var f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    var rbuf: [512]u8 = undefined;
    var r = f.reader(io, &rbuf);
    const content = try r.interface.allocRemaining(a, .unlimited);
    defer a.free(content);

    var lines: usize = 0;
    var it = std.mem.tokenizeScalar(u8, content, '\n');
    while (it.next()) |_| lines += 1;
    try testing.expectEqual(@as(usize, 3), lines); // nothing overwritten
    try testing.expect(std.mem.indexOf(u8, content, "\"user\":\"alice\",\"password\":\"p1\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"user\":\"alice\",\"password\":\"p2\"") != null);
    try testing.expect(std.mem.indexOf(u8, content, "\"user\":\"bob\"") != null);
}

// REGRESSION TEST for the "permissive sentinel" class landing on the locked-skip
// list. An unreadable timestamp became 0, and `isBlocked` computes `now - ts` —
// so 0 read as "locked ~1.8 billion seconds ago", i.e. long expired, and the
// account went straight back into the spray.
test "a locked record with an unreadable timestamp stays blocked" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_locked_badts.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        const f = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
        defer f.close(io);
        var buf: [512]u8 = undefined;
        var w = f.writerStreaming(io, &buf);
        // Valid JSON, valid realm/result — only the timestamp is unreadable.
        try w.interface.writeAll(
            \\{"realm":"EXAMPLE.COM","dc":"dc:88","user":"alice","password":"p","timestamp":"not-a-time","result":"locked","kdc_error":{"name":"","code":0}}
            \\
        );
        try w.interface.flush();
    }

    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expectEqual(@as(usize, 1), set.count());
    // Blocked regardless of how much later "now" is, and regardless of the TTL.
    try testing.expect(set.isBlocked("alice", 2_000_000_000, 30 * 60));
    try testing.expect(set.isBlocked("alice", 9_000_000_000, 60));
    try testing.expect(!set.isBlocked("bob", 2_000_000_000, 30 * 60));
}

// A RESERVATION is published before the KDC is contacted, so it carries no
// outcome yet. If the locked-set replay treated it as a normal record, that
// record's non-"locked" result would CLEAR a genuine lockout — publishing the
// reservation would erase the very protection it exists to coordinate.
test "a reservation does not clear a locked account" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const path = "test_reservation_locked.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer {
        Io.Dir.cwd().deleteFile(io, path) catch {};
        Io.Dir.cwd().deleteFile(io, path ++ ".lock") catch {};
    }
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.appendReservation("alice", "p1");
        try s.append(.{ .user = "alice", .password = "p1", .result = .locked }); // we locked her
        // A later run reserves another slot against the same account.
        try s.appendReservation("alice", "p2");
    }

    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expect(set.isBlocked("alice", 1_000, 30 * 60));

    // A real outcome record showing she answered normally DOES clear her.
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "alice", .password = "p3", .result = .invalid });
    }
    var set2 = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set2.deinit();
    try testing.expect(!set2.isBlocked("alice", 1_000, 30 * 60));
}

test "a transient network/decrypt error does NOT clear a recorded lockout or revocation" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const path = "test_transient_clear.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        // alice: locked, then a later NETWORK error (KDC never answered).
        try s.append(.{ .user = "alice", .password = "p", .result = .locked });
        try s.append(.{ .user = "alice", .password = "p2", .result = .network_error });
        // bob: revoked (disabled), then a later DECRYPT error (our crypto path).
        try s.append(.{ .user = "bob", .password = "p", .result = .revoked });
        try s.append(.{ .user = "bob", .password = "p2", .result = .decrypt_error });
        // carol: locked, then an AUTHORITATIVE invalid -> genuinely back in play.
        try s.append(.{ .user = "carol", .password = "p", .result = .locked });
        try s.append(.{ .user = "carol", .password = "p2", .result = .invalid });
    }
    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    // Inconclusive outcomes must leave the lock/revocation intact (fail closed).
    try testing.expect(set.isBlocked("alice", 1_000, 30 * 60));
    try testing.expect(set.isBlocked("bob", 4_000_000_000, 30 * 60)); // revoked: never ages
    // An authoritative verdict clears it.
    try testing.expect(!set.isBlocked("carol", 1_000, 30 * 60));
}

test "roster round-trips and dedups case-insensitively, realm-scoped" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const path = "test_roster.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "offline");
        defer s.deinit();
        try s.appendUser("alice.admin");
        try s.appendUser("Alice.Admin"); // dup (case)
        try s.appendUser("bob.jones");
        // A roster entry for a DIFFERENT realm must not leak in.
        var s2 = try Store.open(a, io, path, "OTHER.COM", "offline");
        defer s2.deinit();
        try s2.appendUser("carol.other");
    }
    const roster = try loadRosterFromLog(a, io, path, "EXAMPLE.COM");
    defer {
        for (roster) |u| a.free(u);
        a.free(roster);
    }
    try testing.expectEqual(@as(usize, 2), roster.len);
    var saw_alice = false;
    var saw_carol = false;
    for (roster) |u| {
        if (std.ascii.eqlIgnoreCase(u, "alice.admin")) saw_alice = true;
        if (std.ascii.eqlIgnoreCase(u, "carol.other")) saw_carol = true;
    }
    try testing.expect(saw_alice);
    try testing.expect(!saw_carol); // other realm
}

test "a roster record does NOT clear a recorded lockout" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const path = "test_roster_lockout.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "alice", .password = "p1", .result = .locked }); // locked
        try s.appendUser("alice"); // then re-ingested into the roster
    }
    // The roster line must NOT be read as "answered normally -> back in play".
    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    try testing.expect(set.isBlocked("alice", 1_000, 30 * 60));
}

test "a revoked (disabled) account stays blocked past the lockout TTL; a lockout ages out" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const path = "test_revoked_perm.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "dc:88");
        defer s.deinit();
        try s.append(.{ .user = "disabled_bob", .password = "p", .result = .revoked });
        try s.append(.{ .user = "locked_alice", .password = "p", .result = .locked });
    }
    var set = loadLockedFromLog(a, io, path, "EXAMPLE.COM");
    defer set.deinit();
    const ttl: i64 = 30 * 60;
    // Right after: both blocked.
    try testing.expect(set.isBlocked("disabled_bob", 1_000, ttl));
    try testing.expect(set.isBlocked("locked_alice", 1_000, ttl));
    // Long past the TTL: the temporary lockout ages out (re-test to detect
    // recovery), but the permanent revocation does NOT — never re-spray a
    // disabled account on a timer. (Absolute epoch far AFTER the record's ~2026
    // timestamp, so now-ts >> ttl.)
    const way_later: i64 = 4_000_000_000; // ~year 2096
    try testing.expect(set.isBlocked("disabled_bob", way_later, ttl));
    try testing.expect(!set.isBlocked("locked_alice", way_later, ttl));
    try testing.expectEqual(LockReason.revoked, set.reasonFor("disabled_bob").?);
}

test "roster records are invisible to the dedup index and the lockout budget" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const path = "test_roster_invisible.ndjson";
    Io.Dir.cwd().deleteFile(io, path) catch {};
    defer Io.Dir.cwd().deleteFile(io, path) catch {};
    {
        var s = try Store.open(a, io, path, "EXAMPLE.COM", "offline");
        defer s.deinit();
        try s.appendUser("alice");
        try s.appendUser("bob");
    }
    // Dedup: a roster entry (empty password) must not register as a tried combo.
    const dedup_mod = @import("dedup.zig");
    var d = try dedup_mod.loadFromLog(a, io, path, .realm);
    defer d.deinit();
    try testing.expectEqual(@as(usize, 0), d.count());
    try testing.expect(!d.contains("EXAMPLE.COM", "alice", ""));

    // Budget: a roster entry must not seed a per-user attempt window.
    var b = budget_mod.Budget.init(a, .{});
    defer b.deinit();
    try b.loadFromLog(io, path, "EXAMPLE.COM");
    try testing.expectEqual(@as(usize, 0), b.windowCount("alice", 1_000));
    try testing.expectEqual(@as(usize, 0), b.windowCount("bob", 1_000));
}
