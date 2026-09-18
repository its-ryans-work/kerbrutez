//! Maps KDC error codes to kerbrute's continue/abort decisions and messages.
//! Mirrors kerbrute's session/errors.go (HandleKerbError + TestLoginError) but
//! switches on error codes rather than matching error strings.

const std = @import("std");
const krb5 = @import("krb5");
const ec = krb5.iana.error_code;
const Result = @import("../state/store.zig").Result;

/// The interpreted result of an attempt.
pub const Outcome = struct {
    /// Whether this counts as a valid login / username.
    valid: bool,
    /// Whether the whole run should be aborted (fatal error).
    abort: bool,
    /// Human-readable reason/note (a static string).
    reason: []const u8 = "",
    /// Classification for the NDJSON attempt store.
    result: Result = .invalid,
    /// The raw KDC error code (0 if none / not a KDC error).
    kdc_error_code: i32 = 0,
    /// How many password guesses this attempt actually put on the wire. AD
    /// increments badPwdCount once per guess, so the lockout budget must be
    /// charged this much — not a hardcoded 1. See Client.loginCounted.
    password_guesses: u8 = 1,
};

/// Classify a KDC_ERR_CLIENT_REVOKED using the NTSTATUS Windows puts in the
/// KRB-ERROR e-data.
///
/// AD returns error 18 for a locked-out account, a disabled account, an expired
/// account and logon-hour/workstation restrictions alike. Treating all of them
/// as lockouts is wrong in a way that actively breaks the tool: a single
/// disabled account in a user list (every domain has some — `Guest`, `krbtgt`)
/// would consume the --panic-after budget and halt the whole run, and would be
/// reported as "locked out during this run" when nobody locked anything.
///
/// A KDC that sends no NTSTATUS (MIT/Samba/Heimdal) falls back to `.locked`,
/// which is the conservative choice: it can stop early, never spray on.
fn classifyRevoked(nt: ?u32, safe: bool, code: i32) Outcome {
    const ns = krb5.krb_error.nt_status;
    const status = nt orelse return lockedOutcome(safe, code);
    return switch (status) {
        ns.account_locked_out => lockedOutcome(safe, code),
        ns.account_disabled => .{ .valid = false, .abort = false, .reason = "Account DISABLED (not sprayable)", .result = .revoked, .kdc_error_code = code },
        ns.account_expired => .{ .valid = false, .abort = false, .reason = "Account EXPIRED (not sprayable)", .result = .revoked, .kdc_error_code = code },
        ns.invalid_logon_hours => .{ .valid = false, .abort = false, .reason = "Logon-hours restriction (not sprayable right now)", .result = .revoked, .kdc_error_code = code },
        ns.invalid_workstation => .{ .valid = false, .abort = false, .reason = "Workstation restriction (not sprayable from here)", .result = .revoked, .kdc_error_code = code },
        ns.account_restriction => .{ .valid = false, .abort = false, .reason = "Account restriction (not sprayable)", .result = .revoked, .kdc_error_code = code },
        // Both of these mean the PASSWORD WAS RIGHT — the account just can't get
        // a TGT until it changes. That's a win, not a revocation.
        ns.password_expired, ns.password_must_change => .{ .valid = true, .abort = false, .reason = "Password correct but must be changed", .result = .expired, .kdc_error_code = code },
        else => lockedOutcome(safe, code),
    };
}

fn lockedOutcome(safe: bool, code: i32) Outcome {
    return if (safe)
        .{ .valid = false, .abort = true, .reason = "USER LOCKED OUT and safe mode on! Aborting...", .result = .locked, .kdc_error_code = code }
    else
        .{ .valid = false, .abort = false, .reason = "USER LOCKED OUT", .result = .locked, .kdc_error_code = code };
}

/// Interpret a `login` KRB-ERROR code. `safe` is the --safe lockout-abort flag.
/// `nt` is the NTSTATUS from the KRB-ERROR e-data when the KDC supplied one.
pub fn mapLoginError(code: i32, safe: bool, nt: ?u32) Outcome {
    // RFC 6113 multi-step pre-auth (FAST/SPAKE): the account exists and the KDC
    // wants another round we don't perform. Non-fatal, not a confirmed login.
    if (ec.isMorePreauthRequired(code)) {
        return .{ .valid = false, .abort = false, .reason = "KDC requires additional pre-auth (FAST/PKINIT/SPAKE) — can't validate via PA-ENC-TIMESTAMP", .result = .invalid, .kdc_error_code = code };
    }
    // PKINIT certificate failures: the account needs smartcard/cert auth.
    if (ec.isPkinitError(code)) {
        return .{ .valid = false, .abort = false, .reason = "PKINIT/certificate auth required — not password-sprayable", .result = .invalid, .kdc_error_code = code };
    }
    return switch (code) {
        // Valid credentials despite an error (TestLoginError in kerbrute).
        ec.kdc_err_key_expired => .{ .valid = true, .abort = false, .reason = "User's password has expired", .result = .expired, .kdc_error_code = code },
        ec.krb_ap_err_skew => .{ .valid = true, .abort = false, .reason = "Clock skew is too great", .result = .skew, .kdc_error_code = code },
        // Non-fatal negatives.
        ec.kdc_err_preauth_failed => .{ .valid = false, .abort = false, .reason = "Invalid password", .result = .invalid, .kdc_error_code = code },
        ec.kdc_err_c_principal_unknown => .{ .valid = false, .abort = false, .reason = "User does not exist", .result = .user_unknown, .kdc_error_code = code },
        ec.kdc_err_client_revoked => classifyRevoked(nt, safe, code),
        // Fatal.
        ec.kdc_err_wrong_realm => .{ .valid = false, .abort = true, .reason = "KDC ERROR - Wrong Realm. Try adjusting the domain? Aborting...", .result = .invalid, .kdc_error_code = code },
        else => .{ .valid = false, .abort = true, .reason = ec.lookup(code) orelse "Unhandled KRB error", .result = .invalid, .kdc_error_code = code },
    };
}

/// Interpret a `testUsername` KRB-ERROR code.
pub fn mapUsernameError(code: i32, safe: bool, nt: ?u32) Outcome {
    // Multi-step pre-auth required ⇒ the principal exists (valid username).
    if (ec.isMorePreauthRequired(code)) {
        return .{ .valid = true, .abort = false, .reason = "Valid user; KDC wants multi-step pre-auth (FAST/PKINIT/SPAKE)", .result = .valid, .kdc_error_code = code };
    }
    return switch (code) {
        ec.kdc_err_preauth_required => .{ .valid = true, .abort = false, .reason = "", .result = .valid, .kdc_error_code = code },
        ec.kdc_err_c_principal_unknown => .{ .valid = false, .abort = false, .reason = "User does not exist", .result = .user_unknown, .kdc_error_code = code },
        // Same 18-means-four-things problem as the login path (see
        // classifyRevoked); enumeration only needs the right `result` for the
        // state log, so reuse it and keep the existing not-a-hit semantics.
        ec.kdc_err_client_revoked => blk: {
            var o = classifyRevoked(nt, safe, code);
            o.valid = false;
            break :blk o;
        },
        ec.kdc_err_wrong_realm => .{ .valid = false, .abort = true, .reason = "KDC ERROR - Wrong Realm. Try adjusting the domain? Aborting...", .result = .invalid, .kdc_error_code = code },
        else => .{ .valid = false, .abort = true, .reason = ec.lookup(code) orelse "Unhandled KRB error", .result = .invalid, .kdc_error_code = code },
    };
}

const testing = std.testing;

test "login error mapping" {
    try testing.expect(mapLoginError(ec.kdc_err_key_expired, false, null).valid);
    try testing.expect(!mapLoginError(ec.kdc_err_preauth_failed, false, null).valid);
    try testing.expect(!mapLoginError(ec.kdc_err_preauth_failed, false, null).abort);
    try testing.expect(mapLoginError(ec.kdc_err_client_revoked, true, null).abort);
    try testing.expect(!mapLoginError(ec.kdc_err_client_revoked, false, null).abort);
    try testing.expect(mapLoginError(ec.kdc_err_wrong_realm, false, null).abort);
}

test "username error mapping" {
    try testing.expect(mapUsernameError(ec.kdc_err_preauth_required, false, null).valid);
    try testing.expect(!mapUsernameError(ec.kdc_err_c_principal_unknown, false, null).valid);
    try testing.expect(!mapUsernameError(ec.kdc_err_c_principal_unknown, false, null).abort);
}

test "M7: error 91 (more pre-auth) is valid user on enum, non-fatal on login" {
    // userenum: a valid principal — KDC just wants more pre-auth.
    const u = mapUsernameError(ec.kdc_err_more_preauth_data_required, false, null);
    try testing.expect(u.valid and !u.abort);
    try testing.expectEqual(@as(i32, 91), u.kdc_error_code);
    // login: not a confirmed credential, but must NOT abort the run.
    const l = mapLoginError(ec.kdc_err_more_preauth_data_required, false, null);
    try testing.expect(!l.valid and !l.abort);
}

test "M7: PKINIT cert errors are non-fatal on login (not sprayable)" {
    const l = mapLoginError(ec.kdc_error_client_not_trusted, false, null);
    try testing.expect(!l.valid and !l.abort);
    try testing.expect(mapLoginError(ec.kdc_err_certificate_mismatch, false, null).abort == false);
}

test "M7: full error map resolves the new codes" {
    try std.testing.expect(ec.lookup(91) != null);
    try std.testing.expect(ec.lookup(76) != null);
    try std.testing.expectEqualStrings("KDC_ERR_MORE_PREAUTH_DATA_REQUIRED", ec.name(91));
    try std.testing.expect(ec.isMorePreauthRequired(91));
    try std.testing.expect(ec.isPkinitError(62));
}

// REGRESSION TEST for a bug found live against Windows AD: `Guest` (a DISABLED
// account) came back as KDC_ERR_CLIENT_REVOKED, was reported as "locked out —
// pulling from rotation", counted against --panic-after and HALTED the whole
// run. Nothing had been locked. Every domain ships disabled accounts, so any
// user list containing one would stop a spray dead.
test "CLIENT_REVOKED: only a real lockout counts as locked" {
    const ns = krb5.krb_error.nt_status;
    const code = ec.kdc_err_client_revoked;

    // Genuinely locked out -> .locked (consumes the panic-stop budget).
    const locked = mapLoginError(code, false, ns.account_locked_out);
    try testing.expectEqual(Result.locked, locked.result);
    try testing.expect(!locked.valid and !locked.abort);

    // Disabled / expired / restricted -> .revoked: skip it, don't call it a
    // lockout, don't spend the budget.
    for ([_]u32{
        ns.account_disabled,
        ns.account_expired,
        ns.invalid_logon_hours,
        ns.invalid_workstation,
        ns.account_restriction,
    }) |status| {
        const o = mapLoginError(code, false, status);
        try testing.expectEqual(Result.revoked, o.result);
        try testing.expect(!o.valid and !o.abort);
    }

    // "Password must change" means the password we sent was CORRECT.
    const must_change = mapLoginError(code, false, ns.password_must_change);
    try testing.expect(must_change.valid);
    try testing.expectEqual(Result.expired, must_change.result);

    // --safe still aborts on a real lockout, but NOT on a disabled account.
    try testing.expect(mapLoginError(code, true, ns.account_locked_out).abort);
    try testing.expect(!mapLoginError(code, true, ns.account_disabled).abort);

    // No NTSTATUS (MIT/Samba/Heimdal): fall back to the conservative reading.
    try testing.expectEqual(Result.locked, mapLoginError(code, false, null).result);
}
