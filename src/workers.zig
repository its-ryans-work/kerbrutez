//! Threaded worker pool. The wordlist is read fully into memory and split into
//! lines up front, so workers can pull the next line via a lock-free atomic
//! index (no mutex/condvar needed). A shared atomic flag cancels the run early
//! — on the first success when requested, or on a fatal error. This preserves
//! kerbrute's behaviour (cancel-on-success / cancel-on-fatal, atomic counters)
//! using only std.Thread + std.atomic, which is what Zig 0.16 still provides
//! for OS threads.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const krb5 = @import("krb5");
const Session = @import("session/session.zig").Session;
const Logger = @import("util/log.zig").Logger;
const username_util = @import("util/username.zig");
const store_mod = @import("state/store.zig");
const Store = store_mod.Store;
const Dedup = @import("state/dedup.zig").Dedup;
const budget_mod = @import("engine/budget.zig");
const Budget = budget_mod.Budget;
const opsec = @import("engine/opsec.zig");
const report_mod = @import("report/report.zig");
const status_mod = @import("util/status.zig");
const SpinLock = @import("util/spinlock.zig").SpinLock;

/// Max per-run "already tried this password, skipping" notices before the rest
/// are counted silently (a big resume would otherwise flood the log).
const dedup_notice_cap: u32 = 25;

/// What each line represents and how to turn it into an attempt.
pub const Mode = union(enum) {
    /// Each line is a username to enumerate.
    enumerate,
    /// Each line is a username; spray with this fixed password.
    spray: []const u8,
    /// Each line is a username; spray using the username as the password.
    spray_user_as_pass,
    /// Each line is a password to try against this fixed username.
    bruteuser: []const u8,
    /// Each line is a "username:password" combo.
    bruteforce,
};

pub const Pool = struct {
    io: Io,
    session: *Session,
    logger: *Logger,
    domain: []const u8,
    lines: []const []const u8,
    mode: Mode,
    delay_ms: u64,
    stop_on_success: bool,

    // OPSEC (M9): per-attempt pacing (jitter + rpm) and canary protection.
    governor: ?*opsec.Governor = null,
    canary: ?*const opsec.CanarySet = null,

    // Reporting (M10): findings aggregator (valid creds/users, locked).
    report: ?*report_mod.Report = null,

    // Live campaign status block (campaign mode on a TTY) + its ticker stop flag.
    status: ?*status_mod.Status = null,
    status_done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    // Campaign state (null for one-shot runs). When set, attempts are logged to
    // the NDJSON store and already-tried combos are skipped via the dedup index.
    store: ?*Store = null,
    dedup: ?*Dedup = null,
    dedup_lock: SpinLock = .{},
    /// Realm used as the dedup key prefix (BORROW: lives for the run).
    realm: []const u8 = "",
    /// Re-attempt (user,password) combos already in the log instead of skipping
    /// them (the dedup default). The KDC ignores a repeat of the exact same bad
    /// password, so re-attempts don't add lockout risk — they just re-verify.
    retry: bool = false,
    /// How many "already-tried, skipping" notices we've emitted; capped so a big
    /// resume doesn't flood the log (the rest are still counted in `skipped`).
    dedup_notices: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    // Lockout budget / cadence. When set, each attempt is recorded against the
    // per-user windowed budget (see engine/budget.zig). Campaigns additionally
    // WAIT for a free slot; one-shot runs don't pace but still record, because
    // the lockout predictor below needs the per-user count either way.
    budget: ?*Budget = null,
    /// Whether to actually wait for a budget slot (campaigns) or just record
    /// the attempt and proceed (one-shot runs).
    pace_budget: bool = true,
    /// AD lockout threshold, or 0 when unknown/disabled. Drives lockout
    /// PREDICTION — see `predictLockout`.
    lockout_threshold: u32 = 0,
    /// Accounts already recorded as locked/revoked in the shared state log by an
    /// EARLIER run. Skipped on sight and never counted against --panic-after:
    /// we didn't lock them, so they must not consume this run's budget.
    /// BORROW: owned by the caller, must outlive the run.
    prior_locked: ?*const store_mod.LockedSet = null,
    /// How long a logged lockout keeps an account out of rotation. Lockouts are
    /// temporary, and we only discover recovery by trying — so this MUST expire
    /// or the skip list grows forever (see LockedSet.isBlocked).
    prior_locked_ttl_secs: i64 = 30 * 60,
    /// The operator-facing lockout cap (--panic-after). Used only for messaging.
    panic_after: u32 = 3,
    /// The actual halt threshold. With T concurrent workers, up to T-1 attempts
    /// may already be on the wire when we decide to stop, so the caller trips us
    /// early — at `panic_after - (T-1)` — so the worst-case total still lands on
    /// `panic_after`. With one worker this equals `panic_after` (an exact cap).
    panic_trip: u32 = 3,
    locked_users: std.StringHashMapUnmanaged(void) = .{},
    locked_lock: SpinLock = .{},
    locked_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    /// Set in `run`; used for the locked-user set (whose keys are OWNED copies).
    allocator: Allocator = undefined,

    next: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    cancelled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    counter: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    successes: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    skipped: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Run the pool with `thread_count` workers; blocks until done/cancelled.
    pub fn run(self: *Pool, allocator: Allocator, thread_count: usize) !void {
        self.allocator = allocator;
        defer self.deinitLocked(allocator);

        // Live status block ticker (redraws ~1/s). Stopped when the run returns.
        var ticker: ?std.Thread = null;
        if (self.status != null) ticker = std.Thread.spawn(.{}, statusTicker, .{self}) catch null;
        defer if (ticker) |t| {
            self.status_done.store(true, .seq_cst);
            t.join();
        };

        const n = @max(thread_count, 1);
        if (n == 1) {
            // Single-threaded path (also used when --delay is set).
            worker(self);
            return;
        }
        const threads = try allocator.alloc(std.Thread, n);
        defer allocator.free(threads);
        var spawned: usize = 0;
        errdefer {
            self.cancelled.store(true, .seq_cst);
            for (threads[0..spawned]) |t| t.join();
        }
        while (spawned < n) : (spawned += 1) {
            threads[spawned] = try std.Thread.spawn(.{}, worker, .{self});
        }
        for (threads) |t| t.join();
    }

    /// Free the locked-account set. Its keys are OWNED (canonicalised copies —
    /// see markLockedInner), so the map's own deinit is not enough.
    pub fn deinitLocked(self: *Pool, allocator: Allocator) void {
        var kit = self.locked_users.keyIterator();
        while (kit.next()) |k| allocator.free(k.*);
        self.locked_users.deinit(allocator);
    }

    fn cancel(self: *Pool) void {
        self.cancelled.store(true, .seq_cst);
    }

    pub fn attempts(self: *Pool) u32 {
        return self.counter.load(.monotonic);
    }
    pub fn validCount(self: *Pool) u32 {
        return self.successes.load(.monotonic);
    }
    pub fn skippedCount(self: *Pool) u32 {
        return self.skipped.load(.monotonic);
    }
    pub fn lockedCount(self: *Pool) u32 {
        return self.locked_count.load(.monotonic);
    }

    fn isLocked(self: *Pool, user: []const u8) bool {
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const key = budget_mod.accountKey(&kbuf, user);
        self.locked_lock.lock();
        defer self.locked_lock.unlock();
        return self.locked_users.contains(key);
    }

    /// Was this account already locked/revoked before this run started?
    fn wasPreviouslyLocked(self: *Pool, user: []const u8) bool {
        const prior = self.prior_locked orelse return false;
        const now = Io.Timestamp.now(self.io, .real).toSeconds();
        return prior.isBlocked(user, now, self.prior_locked_ttl_secs);
    }

    /// Pre-emptively pull an account we have almost certainly just locked.
    ///
    /// WHY PREDICT INSTEAD OF OBSERVE: Windows AD answers the AS-REQ that
    /// actually trips the lockout with KDC_ERR_PREAUTH_FAILED, not
    /// CLIENT_REVOKED — it only reports CLIENT_REVOKED the NEXT time you touch
    /// the account. (Measured on Windows Server AD, threshold 5: attempts 1-5
    /// all returned 24 and attempt 5 was the one that set lockoutTime; only
    /// attempt 6 returned 18.) Waiting to observe a lockout therefore makes the
    /// count lag by one, so --panic-after N halts only after locking N+1.
    ///
    /// We already track every bad password we send per user per window — that's
    /// what the budget is — so when our own count reaches the domain threshold,
    /// the account is locked whether or not the KDC has told us yet.
    fn predictLockout(self: *Pool, user: []const u8) void {
        if (self.lockout_threshold == 0) return;
        const b = self.budget orelse return;
        const now = Io.Timestamp.now(self.io, .real).toSeconds();
        if (b.windowCount(user, now) < self.lockout_threshold) return;
        if (!self.markLockedInner(user, true)) return;
        // PERSIST the deduction. The KDC answered this attempt with "bad
        // password", so its stored record says `.invalid` — replaying the log
        // in a later run would not reveal the lockout, and that run would spray
        // the account again and burn its panic budget re-discovering it.
        if (self.store) |s| {
            s.append(.{ .user = user, .password = "", .result = .locked }) catch |e|
                self.logger.debug("[!] could not record predicted lockout for {s}: {t}", .{ user, e });
        }
    }

    /// Pull a locked-out account from rotation and, once `panic_after` accounts
    /// have locked, halt the whole run (panic-stop; complements --safe).
    fn markLocked(self: *Pool, user: []const u8) void {
        _ = self.markLockedInner(user, false);
    }

    /// Returns true if this call is what newly counted the account as locked
    /// (false for a repeat, or for an account locked before this run).
    fn markLockedInner(self: *Pool, user: []const u8, predicted: bool) bool {
        // An account that was ALREADY locked before this run is not ours to
        // count: charging it to --panic-after would let stale lockouts from a
        // previous run halt this one before it guesses a single password.
        if (self.wasPreviouslyLocked(user)) return false;
        // Canonical (lower-cased) key: AD is case-insensitive, so a list holding
        // both `Administrator` and `administrator` must pull ONE account from
        // rotation, not keep spraying the other spelling of the same account.
        var kbuf: [budget_mod.account_key_max]u8 = undefined;
        const key = budget_mod.accountKey(&kbuf, user);
        self.locked_lock.lock();
        const gop = self.locked_users.getOrPut(self.allocator, key) catch {
            self.locked_lock.unlock();
            return false;
        };
        if (!gop.found_existing) {
            // The key points at a stack buffer; the map must own it.
            gop.key_ptr.* = self.allocator.dupe(u8, key) catch {
                _ = self.locked_users.remove(key);
                self.locked_lock.unlock();
                return false;
            };
        }
        const newly = !gop.found_existing;
        self.locked_lock.unlock();
        if (!newly) return false;
        if (self.report) |r| r.addLocked(user);
        const total = self.locked_count.fetchAdd(1, .monotonic) + 1;
        if (predicted) {
            self.logger.warning("[!] {s}@{s} has taken {d} bad passwords from us (domain threshold) — treating as LOCKED and pulling from rotation", .{ user, self.domain, self.lockout_threshold });
        } else {
            self.logger.warning("[!] {s}@{s} locked out — pulling from rotation", .{ user, self.domain });
        }
        if (total >= self.panic_trip) {
            if (self.panic_trip < self.panic_after) {
                self.logger.err("[!] PANIC-STOP: {d} locked out; halting now so in-flight attempts keep the total within --panic-after {d}", .{ total, self.panic_after });
            } else {
                self.logger.err("[!] PANIC-STOP: {d} account(s) locked out (>= --panic-after {d}); halting", .{ total, self.panic_after });
            }
            self.cancel();
        }
        return true;
    }

    /// Wait (interruptibly) until the per-user lockout budget permits an attempt.
    /// Returns false if the run was cancelled while waiting.
    /// Take a budget slot for `user` atomically ACROSS PROCESSES.
    ///
    /// Everything that makes the per-user cap a guarantee happens inside one
    /// exclusive lock on the state file's sidecar: observe every other run's
    /// attempts, decide, and — if granted — PUBLISH our own attempt before
    /// releasing. Publishing before the KDC call is the point: whichever process
    /// takes the lock next already sees this attempt, so two runs cannot both
    /// believe the same slot is free. Refreshing without the lock (as before)
    /// only narrowed that window to the refresh interval; this closes it.
    ///
    /// The lock is NOT held across the network round-trip, so concurrent runs
    /// still overlap; they serialise only for the few syscalls it takes to
    /// reserve. If the lock cannot be taken at all we proceed on the in-process
    /// budget rather than refusing to work — degraded to the previous behaviour,
    /// never worse.
    const Reservation = union(enum) { granted, wait_secs: i64, failed };

    fn reserveSlot(self: *Pool, user: []const u8, b: *Budget) Reservation {
        const now_ms = Io.Timestamp.now(self.io, .awake).toMilliseconds();
        const guard: ?Io.File = if (self.store) |st| st.lockExclusive(self.io) else null;
        defer if (guard) |g| g.close(self.io);

        // Under the lock, our view of other runs must be current, so bypass the
        // refresh rate limit — the whole point is to see the latest state.
        if (guard != null) b.last_refresh_ms = 0;
        b.refreshFromLog(self.io, now_ms);

        const now = Io.Timestamp.now(self.io, .real).toSeconds();
        const wait_s = b.tryReserve(user, now) catch {
            self.logger.err("[!] {s}: could not reserve a lockout-budget slot — skipping rather than guessing unaccounted.", .{user});
            _ = self.skipped.fetchAdd(1, .monotonic);
            return .failed;
        };
        if (wait_s != 0) return .{ .wait_secs = wait_s };

        // Granted: make it visible to every other process BEFORE we release.
        if (self.store) |st| {
            st.appendReservation(user, "") catch |e|
                self.logger.debug("[!] could not publish the budget reservation for {s}: {t}", .{ user, e });
        }
        return .granted;
    }

    fn waitForBudget(self: *Pool, user: []const u8) bool {
        const b = self.budget orelse return true;
        if (!self.pace_budget) {
            // One-shot run: no cadence, but the attempt is still published under
            // the cross-process lock so other runs count it, and so the lockout
            // predictor sees every bad password this account has taken from us.
            //
            // FAIL CLOSED. If we cannot account for an attempt we must not make
            // it: an unrecorded bad password is one the budget and the predictor
            // never see, so the account silently gets more guesses than the
            // policy allows — the exact outcome this machinery prevents.
            const guard: ?Io.File = if (self.store) |st| st.lockExclusive(self.io) else null;
            defer if (guard) |g| g.close(self.io);
            if (guard != null) b.last_refresh_ms = 0;
            b.refreshFromLog(self.io, Io.Timestamp.now(self.io, .awake).toMilliseconds());
            // ENFORCE THE CAP HERE TOO. A one-shot run does not pace, but it must
            // still not push an account past the per-user limit — and several
            // one-shot runs in parallel otherwise do exactly that, each recording
            // its attempt without ever checking. Measured: six simultaneous runs
            // put six bad passwords on one account against a threshold of five.
            // The predictor cannot save us here, since it only fires once the
            // threshold has already been reached, i.e. after the lockout.
            const now_s = Io.Timestamp.now(self.io, .real).toSeconds();
            const wait_s = b.tryReserve(user, now_s) catch {
                self.logger.err("[!] {s}: could not reserve a lockout-budget slot — skipping rather than guessing unaccounted.", .{user});
                _ = self.skipped.fetchAdd(1, .monotonic);
                return false;
            };
            if (wait_s != 0) {
                _ = self.skipped.fetchAdd(1, .monotonic);
                self.logger.warning("[!] {s}: already at {d} attempt(s) in the last {d} min (counting other runs) — skipping to avoid a lockout. Use spraycampaign to pace across windows instead.", .{ user, b.policy.attempts_per_window, b.policy.window_min });
                return false;
            }
            if (self.store) |st| {
                st.appendReservation(user, "") catch |e|
                    self.logger.debug("[!] could not publish the budget reservation for {s}: {t}", .{ user, e });
            }
            return true;
        }
        var announced = false;
        while (!self.cancelled.load(.seq_cst)) {
            // The lock is taken and released inside reserveSlot — never held
            // across the sleep below, or one paused run would freeze the others.
            const wait_s = switch (self.reserveSlot(user, b)) {
                .granted => {
                    if (self.status) |st| st.clearNext();
                    return true;
                },
                .failed => return false,
                .wait_secs => |w| w,
            };
            if (!announced) {
                self.logger.info("[*] {s}: lockout budget reached ({d}/{d}-min window); pausing ~{d}s", .{ user, b.policy.attempts_per_window, b.policy.window_min, wait_s });
                announced = true;
            }
            if (self.status) |st| st.noteNext(Io.Timestamp.now(self.io, .awake).toMilliseconds() + wait_s * 1000);
            sleepInterruptible(self, @intCast(wait_s));
        }
        return false;
    }

    /// Try a login unless this exact (realm,user,password) was already attempted
    /// (campaign dedup), the account was pulled from rotation, or the per-user
    /// lockout budget says to wait. Records the outcome afterwards.
    fn attemptLogin(self: *Pool, username: []const u8, password: []const u8) void {
        if (self.canary) |c| {
            if (c.contains(username)) {
                _ = self.skipped.fetchAdd(1, .monotonic);
                self.logger.warning("[!] {s}@{s} - CANARY/honeypot account; skipping (never touched)", .{ username, self.domain });
                return;
            }
        }
        if (self.wasPreviouslyLocked(username)) {
            _ = self.skipped.fetchAdd(1, .monotonic);
            self.logger.info("[~] {s}@{s} - skipped (already locked/revoked in the state log from an earlier run; --retry-locked to re-test)", .{ username, self.domain });
            return;
        }
        if (self.isLocked(username)) {
            _ = self.skipped.fetchAdd(1, .monotonic);
            self.logger.info("[~] {s}@{s} - skipped (locked out; pulled from rotation)", .{ username, self.domain });
            return;
        }
        if (self.dedup) |d| {
            if (!self.retry) {
                self.dedup_lock.lock();
                const seen = d.contains(self.realm, username, password);
                self.dedup_lock.unlock();
                if (seen) {
                    _ = self.skipped.fetchAdd(1, .monotonic);
                    // Notify (this exact password was already tried) but cap the
                    // notices so resuming a big campaign doesn't flood the log.
                    const n = self.dedup_notices.fetchAdd(1, .monotonic);
                    if (n < dedup_notice_cap) {
                        self.logger.info("[~] {s}@{s}:{s} - already tried this password; skipping (--retry to re-attempt)", .{ username, self.domain, password });
                    } else if (n == dedup_notice_cap) {
                        self.logger.info("[~] …further already-tried skips counted silently (see the summary; --retry to re-attempt).", .{});
                    }
                    return;
                }
            }
        }
        if (!self.waitForBudget(username)) return; // cancelled while waiting
        self.handleLogin(username, password);
    }

    /// Append the attempt to the NDJSON store and mark the combo as tried.
    /// FALLBACK: a failed log write is reported at debug level and does not
    /// abort the run.
    fn recordAttempt(self: *Pool, username: []const u8, password: []const u8, outcome: anytype) void {
        if (self.store) |s| {
            const err_name = if (outcome.kdc_error_code != 0) krb5.iana.error_code.name(outcome.kdc_error_code) else "";
            s.append(.{
                .user = username,
                .password = password,
                .result = outcome.result,
                .kdc_error_name = err_name,
                .kdc_error_code = outcome.kdc_error_code,
            }) catch |e| self.logger.debug("[!] state log write failed: {t}", .{e});
        }
        if (self.dedup) |d| {
            self.dedup_lock.lock();
            defer self.dedup_lock.unlock();
            // A lost dedup entry only costs a repeat attempt on a later run
            // (the KDC ignores a repeat of the same bad password), but it is
            // still a silent divergence between the log and the index.
            d.add(self.realm, username, password) catch
                self.logger.debug("[!] could not index {s} for dedup; it may be retried on a later run", .{username});
        }
    }

    fn handleLogin(self: *Pool, username: []const u8, password: []const u8) void {
        // A panic-stop / fatal-abort / first-success on another thread may have
        // fired after this attempt cleared the budget gate. Bail before the
        // network call so we don't lock further accounts (panic-stop overshoot)
        // or keep guessing after we've decided to halt. Already-in-flight
        // requests can't be recalled, so a hard cap needs -t 1 / --delay.
        if (self.cancelled.load(.seq_cst)) return;
        _ = self.counter.fetchAdd(1, .monotonic);
        if (self.status) |st| st.noteAttempt(Io.Timestamp.now(self.io, .awake).toMilliseconds());
        const outcome = self.session.testLogin(username, password);
        // TRUTHFUL BUDGET ACCOUNTING: waitForBudget reserved ONE slot, but a
        // corrected-etype retry puts a second password guess on the wire and AD
        // counts both. Charge the difference now, or the budget (and the
        // lockout predictor that reads it) silently undercounts by half —
        // exactly the bug that made every attempt cost two badPwdCounts.
        if (outcome.password_guesses > 1) {
            if (self.budget) |b| {
                const now = Io.Timestamp.now(self.io, .real).toSeconds();
                var extra: u8 = 1;
                // The attempt already happened, so this cannot fail closed —
                // but a silent failure would leave the budget under-counting
                // for the rest of the run. Say so.
                while (extra < outcome.password_guesses) : (extra += 1) b.addHistorical(username, now) catch {
                    self.logger.warning("[!] {s}: lockout budget is now UNDER-counting (couldn't record an extra password guess) — treat the remaining budget as optimistic.", .{username});
                };
            }
        }
        self.recordAttempt(username, password, outcome);
        switch (outcome.result) {
            .locked => self.markLocked(username),
            // A bad password may have been the one that tripped the lockout —
            // AD won't say so until we touch the account again (see
            // predictLockout), so decide from our own attempt count now.
            .invalid => self.predictLockout(username),
            else => {},
        }
        var buf: [4096]u8 = undefined;
        const login = std.fmt.bufPrint(&buf, "{s}@{s}:{s}", .{ username, self.domain, password }) catch "<login>";
        if (outcome.valid) {
            _ = self.successes.fetchAdd(1, .monotonic);
            if (self.report) |r| {
                if (outcome.result == .expired) r.addExpiredWin(username, password) else r.addValidCred(username, password, if (outcome.reason.len > 0) outcome.reason else null);
            }
            if (outcome.reason.len > 0) {
                self.logger.notice("[+] VALID LOGIN WITH ERROR:\t {s}\t ({s})", .{ login, outcome.reason });
            } else {
                self.logger.notice("[+] VALID LOGIN:\t {s}", .{login});
            }
            if (self.stop_on_success) self.cancel();
        } else if (outcome.abort) {
            self.logger.err("[!] {s} - {s}", .{ login, outcome.reason });
            self.cancel();
        } else {
            self.logger.debug("[!] {s} - {s}", .{ login, outcome.reason });
        }
    }

    fn handleEnum(self: *Pool, user: []const u8) void {
        if (self.canary) |c| {
            if (c.contains(user)) {
                _ = self.skipped.fetchAdd(1, .monotonic);
                self.logger.warning("[!] {s}@{s} - CANARY/honeypot account; skipping", .{ user, self.domain });
                return;
            }
        }
        _ = self.counter.fetchAdd(1, .monotonic);
        const outcome = self.session.testUsername(user);
        var buf: [2048]u8 = undefined;
        const full = std.fmt.bufPrint(&buf, "{s}@{s}", .{ user, self.domain }) catch "<user>";
        if (outcome.valid) {
            _ = self.successes.fetchAdd(1, .monotonic);
            if (self.report) |r| r.addValidUser(user);
            self.logger.notice("[+] VALID USERNAME:\t {s}", .{full});
        } else if (outcome.abort) {
            self.logger.err("[!] {s} - {s}", .{ full, outcome.reason });
            self.cancel();
        } else {
            self.logger.debug("[!] {s} - {s}", .{ full, outcome.reason });
        }
    }

    /// Process one input line according to the mode.
    fn processLine(self: *Pool, line: []const u8) void {
        switch (self.mode) {
            .enumerate => {
                const user = username_util.formatUsername(line) catch {
                    self.logger.debug("[!] {s} - invalid username", .{line});
                    return;
                };
                if (user.len == 0) return;
                self.handleEnum(user);
            },
            .spray => |password| {
                const user = username_util.formatUsername(line) catch {
                    self.logger.debug("[!] {s} - invalid username", .{line});
                    return;
                };
                if (user.len == 0) return;
                self.attemptLogin(user, password);
            },
            .spray_user_as_pass => {
                const user = username_util.formatUsername(line) catch {
                    self.logger.debug("[!] {s} - invalid username", .{line});
                    return;
                };
                if (user.len == 0) return;
                self.attemptLogin(user, user);
            },
            .bruteuser => |user| {
                self.attemptLogin(user, line);
            },
            .bruteforce => {
                if (line.len == 0) return;
                const combo = username_util.formatComboLine(line) catch {
                    self.logger.debug("[!] Skipping: {s}", .{line});
                    return;
                };
                self.attemptLogin(combo.username, combo.password);
            },
        }
    }
};

fn worker(pool: *Pool) void {
    while (!pool.cancelled.load(.seq_cst)) {
        const idx = pool.next.fetchAdd(1, .monotonic);
        if (idx >= pool.lines.len) break;
        pace(pool);
        // Pacing can sleep across a cancel (panic-stop / abort / first success);
        // re-check before spending the pulled slot on another attempt.
        if (pool.cancelled.load(.seq_cst)) break;
        pool.processLine(pool.lines[idx]);
    }
}

/// Apply OPSEC pacing (rpm gate + jitter) before an attempt, falling back to the
/// legacy fixed --delay. The rpm wait is cancellation-aware.
fn pace(pool: *Pool) void {
    if (pool.governor) |g| {
        const now_ms = Io.Timestamp.now(pool.io, .awake).toMilliseconds();
        const ms = g.reserve(now_ms);
        if (ms > 0) sleepMsInterruptible(pool, ms);
    } else if (pool.delay_ms != 0) {
        sleep(pool.io, pool.delay_ms);
    }
}

/// Sleep `ms` milliseconds in short chunks, waking early if the run is cancelled.
fn sleepMsInterruptible(pool: *Pool, ms: u64) void {
    var remaining: i64 = @intCast(ms);
    while (remaining > 0 and !pool.cancelled.load(.seq_cst)) {
        const chunk: u64 = @intCast(@min(remaining, 500));
        sleep(pool.io, chunk);
        remaining -= @intCast(chunk);
    }
}

/// Redraw the live status block roughly once a second until the run finishes.
fn statusTicker(pool: *Pool) void {
    pool.logger.refreshStatus(); // initial draw
    while (!pool.status_done.load(.seq_cst) and !pool.cancelled.load(.seq_cst)) {
        sleep(pool.io, 1000);
        pool.logger.refreshStatus();
    }
}

fn sleep(io: Io, ms: u64) void {
    const t: Io.Timeout = .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(@intCast(ms)), .clock = .awake } };
    t.sleep(io) catch {};
}

/// Sleep up to `seconds`, waking early (within ~2s) if the run is cancelled.
fn sleepInterruptible(pool: *Pool, seconds: i64) void {
    var remaining = seconds;
    while (remaining > 0 and !pool.cancelled.load(.seq_cst)) {
        const chunk: u64 = @intCast(@min(remaining, 2));
        sleep(pool.io, chunk * 1000);
        remaining -= @intCast(chunk);
    }
}

const testing = std.testing;

// A bare Pool for unit tests. io/session/logger are caller-supplied; the rest
// take their struct defaults. Paths under test short-circuit before touching
// `session`, so an `undefined` session is a deliberate tripwire: if a guard
// regresses and lets an attempt through, the test crashes instead of passing.
fn testPool(io: Io, logger: *Logger) Pool {
    return .{
        .io = io,
        .session = undefined,
        .logger = logger,
        .domain = "EXAMPLE",
        .lines = &.{},
        .mode = .enumerate,
        .delay_ms = 0,
        .stop_on_success = false,
    };
}

test "handleLogin bails before the network call once cancelled (panic-stop overshoot fix)" {
    // No io/logger needed: the cancelled check is the first statement, so a
    // cancelled pool must return before counting or calling session.testLogin.
    var pool = testPool(undefined, undefined);
    pool.cancelled.store(true, .seq_cst);
    pool.handleLogin("u", "p");
    try testing.expectEqual(@as(u32, 0), pool.counter.load(.monotonic));
}

test "attemptLogin skips, counts, and never touches the session for a locked user (skip-visibility fix)" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var logger = try Logger.init(io, false, null);
    defer logger.deinit();
    // Redirect log output to a scratch file. The default `Logger` writes to the
    // real stdout, and under `zig build test` that stream carries the test
    // runner's result protocol — logging into it deadlocks the build runner.
    const sink = try Io.Dir.cwd().createFile(io, "zz_workers_skip.log", .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, "zz_workers_skip.log") catch {};
    }

    var pool = testPool(io, &logger);
    pool.allocator = a;
    defer pool.deinitLocked(a);
    try pool.locked_users.put(a, try a.dupe(u8, "bob"), {});

    pool.attemptLogin("bob", "pw"); // session is undefined: must short-circuit
    try testing.expectEqual(@as(u32, 1), pool.skippedCount()); // now counted
    try testing.expectEqual(@as(u32, 0), pool.counter.load(.monotonic)); // no attempt
}

test "markLocked counts distinct accounts and fires panic-stop at panic_trip" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var logger = try Logger.init(io, false, null);
    defer logger.deinit();
    // See note above: keep log output off the test runner's stdout protocol.
    const sink = try Io.Dir.cwd().createFile(io, "zz_workers_panic.log", .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, "zz_workers_panic.log") catch {};
    }

    var pool = testPool(io, &logger);
    pool.allocator = a;
    pool.panic_after = 2; // operator cap
    pool.panic_trip = 2; // single-thread case: trip == cap (exact)
    defer pool.deinitLocked(a);

    pool.markLocked("alice"); // 1st distinct lock: below the trip
    try testing.expectEqual(@as(u32, 1), pool.lockedCount());
    try testing.expect(!pool.cancelled.load(.seq_cst));

    pool.markLocked("alice"); // same account: not recounted, no panic
    try testing.expectEqual(@as(u32, 1), pool.lockedCount());
    try testing.expect(!pool.cancelled.load(.seq_cst));

    pool.markLocked("bob"); // 2nd distinct lock == panic_trip: halt now (not 3)
    try testing.expectEqual(@as(u32, 2), pool.lockedCount());
    try testing.expect(pool.cancelled.load(.seq_cst));
}

test "previously locked accounts are skipped and never charged to --panic-after" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var logger = try Logger.init(io, false, null);
    defer logger.deinit();
    const sink = try Io.Dir.cwd().createFile(io, "zz_workers_prior.log", .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, "zz_workers_prior.log") catch {};
    }

    // "alice" was locked by an EARLIER run (replayed from the state log).
    // Stored under the canonical key; the list below spells her "Alice".
    var prior = store_mod.LockedSet{ .allocator = a };
    defer prior.deinit();
    try prior.map.put(a, try a.dupe(u8, "alice"), 1_000_000);

    var pool = testPool(io, &logger);
    pool.allocator = a;
    pool.prior_locked = &prior;
    pool.prior_locked_ttl_secs = 0; // expiry disabled for this assertion
    pool.panic_after = 1;
    pool.panic_trip = 1;
    defer pool.deinitLocked(a);

    // Skipped without touching the session (which is `undefined` on purpose).
    // Different case on purpose: AD would treat this as the same account.
    pool.attemptLogin("Alice", "pw");
    try testing.expectEqual(@as(u32, 1), pool.skippedCount());
    try testing.expectEqual(@as(u32, 0), pool.counter.load(.monotonic));

    // And a stale lockout must not consume the panic budget: with panic_trip=1
    // this would otherwise halt the run before a single password was guessed.
    pool.markLocked("Alice");
    try testing.expectEqual(@as(u32, 0), pool.lockedCount());
    try testing.expect(!pool.cancelled.load(.seq_cst));
}

// REGRESSION TEST for the "--panic-after N stops at N+1" report. Windows AD
// answers the AS-REQ that actually trips the lockout with PREAUTH_FAILED and
// only reports CLIENT_REVOKED on the NEXT touch (verified live), so observing
// lockouts always lags by one. predictLockout closes that gap using the bad
// passwords we know we sent.
test "predictLockout pulls an account at the threshold without waiting for CLIENT_REVOKED" {
    const a = testing.allocator;
    var threaded: std.Io.Threaded = .init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var logger = try Logger.init(io, false, null);
    defer logger.deinit();
    const sink = try Io.Dir.cwd().createFile(io, "zz_workers_predict.log", .{ .truncate = true });
    logger.stdout = sink;
    defer {
        sink.close(io);
        Io.Dir.cwd().deleteFile(io, "zz_workers_predict.log") catch {};
    }

    var budget = Budget.init(a, .{ .threshold = 3, .window_min = 60, .attempts_per_window = 99, .margin_min = 0 });
    defer budget.deinit();

    var pool = testPool(io, &logger);
    pool.allocator = a;
    pool.budget = &budget;
    pool.lockout_threshold = 3;
    pool.panic_after = 1;
    pool.panic_trip = 1;
    defer pool.deinitLocked(a);

    const now = Io.Timestamp.now(io, .real).toSeconds();
    try budget.addHistorical("bob", now);
    try budget.addHistorical("bob", now);
    pool.predictLockout("bob"); // 2 bad passwords < threshold 3: not yet
    try testing.expectEqual(@as(u32, 0), pool.lockedCount());
    try testing.expect(!pool.cancelled.load(.seq_cst));

    try budget.addHistorical("bob", now);
    pool.predictLockout("bob"); // 3rd bad password == threshold: locked NOW
    try testing.expectEqual(@as(u32, 1), pool.lockedCount());
    try testing.expect(pool.cancelled.load(.seq_cst)); // panic-stop fired on time

    // Idempotent: the same account can't be counted twice.
    pool.predictLockout("bob");
    try testing.expectEqual(@as(u32, 1), pool.lockedCount());
}

test "predictLockout is inert when the lockout threshold is unknown" {
    var pool = testPool(undefined, undefined);
    pool.lockout_threshold = 0; // e.g. --lockout-threshold 0 / no policy
    pool.predictLockout("bob"); // must not touch budget/logger (both undefined)
    try testing.expectEqual(@as(u32, 0), pool.lockedCount());
}
