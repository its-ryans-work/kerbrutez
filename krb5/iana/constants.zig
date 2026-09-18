//! IANA-assigned Kerberos 5 numbers (RFC 4120 and related).
//!
//! Ported from gokrb5's iana/* packages. Values are grouped into namespaced
//! structs so call sites read like `iana.etype_id.aes256_cts_hmac_sha1_96`.

const std = @import("std");

/// Protocol Version Number (RFC 4120).
pub const pvno: i32 = 5;

/// Encryption type assigned numbers (RFC 3961 / registry).
pub const etype_id = struct {
    pub const des_cbc_crc: i32 = 1;
    pub const des_cbc_md4: i32 = 2;
    pub const des_cbc_md5: i32 = 3;
    pub const des3_cbc_sha1_kd: i32 = 16;
    pub const aes128_cts_hmac_sha1_96: i32 = 17;
    pub const aes256_cts_hmac_sha1_96: i32 = 18;
    pub const aes128_cts_hmac_sha256_128: i32 = 19;
    pub const aes256_cts_hmac_sha384_192: i32 = 20;
    pub const rc4_hmac: i32 = 23;
    pub const rc4_hmac_exp: i32 = 24;
    pub const camellia128_cts_cmac: i32 = 25;
    pub const camellia256_cts_cmac: i32 = 26;

    /// Resolve an enctype name (krb5.conf style) to its ID, or 0 if unknown
    /// or unsupported by this library. Mirrors gokrb5's etypeID.EtypeSupported.
    pub fn supported(name: []const u8) i32 {
        const Pair = struct { name: []const u8, id: i32 };
        const table = [_]Pair{
            .{ .name = "aes128-cts-hmac-sha1-96", .id = aes128_cts_hmac_sha1_96 },
            .{ .name = "aes256-cts-hmac-sha1-96", .id = aes256_cts_hmac_sha1_96 },
            .{ .name = "aes128-cts-hmac-sha256-128", .id = aes128_cts_hmac_sha256_128 },
            .{ .name = "aes256-cts-hmac-sha384-192", .id = aes256_cts_hmac_sha384_192 },
            .{ .name = "des3-cbc-sha1", .id = des3_cbc_sha1_kd },
            .{ .name = "des3-cbc-sha1-kd", .id = des3_cbc_sha1_kd },
            .{ .name = "des3-hmac-sha1", .id = des3_cbc_sha1_kd },
            .{ .name = "arcfour-hmac-md5", .id = rc4_hmac },
            .{ .name = "rc4-hmac", .id = rc4_hmac },
            .{ .name = "arcfour-hmac", .id = rc4_hmac },
        };
        for (table) |p| {
            if (std.mem.eql(u8, p.name, name)) return p.id;
        }
        return 0;
    }
};

/// Checksum type assigned numbers.
pub const chksum_type = struct {
    pub const hmac_sha1_des3_kd: i32 = 12;
    pub const hmac_sha1_96_aes128: i32 = 15;
    pub const hmac_sha1_96_aes256: i32 = 16;
    pub const hmac_sha256_128_aes128: i32 = 19;
    pub const hmac_sha384_192_aes256: i32 = 20;
    /// KERB_CHECKSUM_HMAC_MD5 — documented as -138.
    pub const kerb_checksum_hmac_md5: i32 = -138;
};

/// Key usage numbers (RFC 4120 §7.5.1).
pub const key_usage = struct {
    pub const as_req_pa_enc_timestamp: u32 = 1;
    pub const kdc_rep_ticket: u32 = 2;
    pub const as_rep_encpart: u32 = 3;
    pub const tgs_req_kdc_req_body_authdata_session_key: u32 = 4;
    pub const tgs_req_kdc_req_body_authdata_sub_key: u32 = 5;
    pub const tgs_req_pa_tgs_req_ap_req_authenticator_chksum: u32 = 6;
    pub const tgs_req_pa_tgs_req_ap_req_authenticator: u32 = 7;
    pub const tgs_rep_encpart_session_key: u32 = 8;
    pub const tgs_rep_encpart_authenticator_sub_key: u32 = 9;
    pub const ap_req_authenticator_chksum: u32 = 10;
    pub const ap_req_authenticator: u32 = 11;
    pub const ap_rep_encpart: u32 = 12;
    pub const key_usage_as_req: u32 = 56;
};

/// Pre-authentication data type numbers.
pub const pa_type = struct {
    pub const pa_tgs_req: i32 = 1;
    pub const pa_enc_timestamp: i32 = 2;
    pub const pa_pw_salt: i32 = 3;
    pub const pa_pk_as_req_old: i32 = 14;
    pub const pa_pk_as_rep: i32 = 15;
    pub const pa_pk_as_req: i32 = 16;
    pub const pa_etype_info: i32 = 11;
    pub const pa_etype_info2: i32 = 19;
    pub const pa_pac_request: i32 = 128;
    pub const pa_fx_cookie: i32 = 133;
    pub const pa_fx_fast: i32 = 136;
    pub const pa_fx_error: i32 = 137;
    pub const pa_encrypted_challenge: i32 = 138;
    pub const pa_req_enc_pa_rep: i32 = 149;
};

/// Principal name type numbers (RFC 4120 §6.2).
pub const name_type = struct {
    pub const krb_nt_unknown: i32 = 0;
    pub const krb_nt_principal: i32 = 1;
    pub const krb_nt_srv_inst: i32 = 2;
    pub const krb_nt_srv_hst: i32 = 3;
    pub const krb_nt_enterprise: i32 = 10;
};

/// Message type numbers.
pub const msg_type = struct {
    pub const krb_as_req: i32 = 10;
    pub const krb_as_rep: i32 = 11;
    pub const krb_tgs_req: i32 = 12;
    pub const krb_tgs_rep: i32 = 13;
    pub const krb_ap_req: i32 = 14;
    pub const krb_ap_rep: i32 = 15;
    pub const krb_error: i32 = 30;
};

/// ASN.1 application tag numbers used to wrap Kerberos messages.
pub const asn_app_tag = struct {
    pub const ticket: u8 = 1;
    pub const authenticator: u8 = 2;
    pub const enc_ticket_part: u8 = 3;
    pub const as_req: u8 = 10;
    pub const as_rep: u8 = 11;
    pub const tgs_req: u8 = 12;
    pub const tgs_rep: u8 = 13;
    pub const ap_req: u8 = 14;
    pub const ap_rep: u8 = 15;
    pub const enc_as_rep_part: u8 = 25;
    pub const enc_tgs_rep_part: u8 = 26;
    pub const krb_error: u8 = 30;
};

/// KDCOptions / ticket flag bit positions (RFC 4120 §5.4.1).
pub const flags = struct {
    pub const forwardable: usize = 1;
    pub const forwarded: usize = 2;
    pub const proxiable: usize = 3;
    pub const proxy: usize = 4;
    pub const allow_postdate: usize = 5;
    pub const postdated: usize = 6;
    pub const renewable: usize = 8;
    pub const initial: usize = 9;
    pub const pre_authent: usize = 10;
    pub const hw_authent: usize = 11;
    pub const canonicalize: usize = 15;
    pub const enc_pa_rep: usize = 15;
    pub const renewable_ok: usize = 27;
    pub const enc_tkt_in_skey: usize = 28;
    pub const renew: usize = 30;
    pub const validate: usize = 31;
};

/// Kerberos error codes (RFC 4120 §7.5.9).
pub const error_code = struct {
    pub const kdc_err_none: i32 = 0;
    pub const kdc_err_name_exp: i32 = 1;
    pub const kdc_err_service_exp: i32 = 2;
    pub const kdc_err_bad_pvno: i32 = 3;
    pub const kdc_err_c_old_mast_kvno: i32 = 4;
    pub const kdc_err_s_old_mast_kvno: i32 = 5;
    pub const kdc_err_c_principal_unknown: i32 = 6;
    pub const kdc_err_s_principal_unknown: i32 = 7;
    pub const kdc_err_principal_not_unique: i32 = 8;
    pub const kdc_err_null_key: i32 = 9;
    pub const kdc_err_cannot_postdate: i32 = 10;
    pub const kdc_err_never_valid: i32 = 11;
    pub const kdc_err_policy: i32 = 12;
    pub const kdc_err_badoption: i32 = 13;
    pub const kdc_err_etype_nosupp: i32 = 14;
    pub const kdc_err_sumtype_nosupp: i32 = 15;
    pub const kdc_err_padata_type_nosupp: i32 = 16;
    pub const kdc_err_trtype_nosupp: i32 = 17;
    pub const kdc_err_client_revoked: i32 = 18;
    pub const kdc_err_service_revoked: i32 = 19;
    pub const kdc_err_tgt_revoked: i32 = 20;
    pub const kdc_err_client_notyet: i32 = 21;
    pub const kdc_err_service_notyet: i32 = 22;
    pub const kdc_err_key_expired: i32 = 23;
    pub const kdc_err_preauth_failed: i32 = 24;
    pub const kdc_err_preauth_required: i32 = 25;
    pub const kdc_err_server_nomatch: i32 = 26;
    pub const kdc_err_must_use_user2user: i32 = 27;
    pub const kdc_err_path_not_accepted: i32 = 28;
    pub const kdc_err_svc_unavailable: i32 = 29;
    pub const krb_ap_err_bad_integrity: i32 = 31;
    pub const krb_ap_err_tkt_expired: i32 = 32;
    pub const krb_ap_err_tkt_nyv: i32 = 33;
    pub const krb_ap_err_repeat: i32 = 34;
    pub const krb_ap_err_not_us: i32 = 35;
    pub const krb_ap_err_badmatch: i32 = 36;
    pub const krb_ap_err_skew: i32 = 37;
    pub const krb_ap_err_badaddr: i32 = 38;
    pub const krb_ap_err_badversion: i32 = 39;
    pub const krb_ap_err_msg_type: i32 = 40;
    pub const krb_ap_err_modified: i32 = 41;
    pub const krb_ap_err_badorder: i32 = 42;
    pub const krb_ap_err_badkeyver: i32 = 44;
    pub const krb_ap_err_nokey: i32 = 45;
    pub const krb_ap_err_mut_fail: i32 = 46;
    pub const krb_ap_err_baddirection: i32 = 47;
    pub const krb_ap_err_method: i32 = 48;
    pub const krb_ap_err_badseq: i32 = 49;
    pub const krb_ap_err_inapp_cksum: i32 = 50;
    pub const krb_ap_path_not_accepted: i32 = 51;
    pub const krb_err_response_too_big: i32 = 52;
    pub const krb_err_generic: i32 = 60;
    pub const krb_err_field_toolong: i32 = 61;
    pub const kdc_error_client_not_trusted: i32 = 62;
    pub const kdc_error_kdc_not_trusted: i32 = 63;
    pub const kdc_error_invalid_sig: i32 = 64;
    pub const kdc_err_key_too_weak: i32 = 65;
    pub const kdc_err_certificate_mismatch: i32 = 66;
    pub const krb_ap_err_no_tgt: i32 = 67;
    pub const kdc_err_wrong_realm: i32 = 68;
    pub const krb_ap_err_user_to_user_required: i32 = 69;
    pub const kdc_err_cant_verify_certificate: i32 = 70;
    pub const kdc_err_invalid_certificate: i32 = 71;
    pub const kdc_err_revoked_certificate: i32 = 72;
    pub const kdc_err_revocation_status_unknown: i32 = 73;
    pub const kdc_err_revocation_status_unavailable: i32 = 74;
    pub const kdc_err_client_name_mismatch: i32 = 75;
    pub const kdc_err_kdc_name_mismatch: i32 = 76;
    // RFC 6113 (FAST / multi-step pre-auth).
    pub const kdc_err_preauth_expired: i32 = 90;
    pub const kdc_err_more_preauth_data_required: i32 = 91;
    pub const kdc_err_preauth_bad_authentication_set: i32 = 92;
    pub const kdc_err_unknown_critical_fast_options: i32 = 93;

    /// Returns the short symbolic name for an error code (e.g.
    /// "KDC_ERR_PREAUTH_FAILED"), or "KRB_ERR_UNKNOWN" if unrecognised.
    pub fn name(code: i32) []const u8 {
        return switch (code) {
            kdc_err_none => "KDC_ERR_NONE",
            kdc_err_name_exp => "KDC_ERR_NAME_EXP",
            kdc_err_c_principal_unknown => "KDC_ERR_C_PRINCIPAL_UNKNOWN",
            kdc_err_s_principal_unknown => "KDC_ERR_S_PRINCIPAL_UNKNOWN",
            kdc_err_policy => "KDC_ERR_POLICY",
            kdc_err_etype_nosupp => "KDC_ERR_ETYPE_NOSUPP",
            kdc_err_client_revoked => "KDC_ERR_CLIENT_REVOKED",
            kdc_err_key_expired => "KDC_ERR_KEY_EXPIRED",
            kdc_err_preauth_failed => "KDC_ERR_PREAUTH_FAILED",
            kdc_err_preauth_required => "KDC_ERR_PREAUTH_REQUIRED",
            kdc_err_padata_type_nosupp => "KDC_ERR_PADATA_TYPE_NOSUPP",
            kdc_err_svc_unavailable => "KDC_ERR_SVC_UNAVAILABLE",
            krb_ap_err_skew => "KRB_AP_ERR_SKEW",
            krb_ap_err_modified => "KRB_AP_ERR_MODIFIED",
            krb_err_response_too_big => "KRB_ERR_RESPONSE_TOO_BIG",
            krb_err_generic => "KRB_ERR_GENERIC",
            kdc_error_client_not_trusted => "KDC_ERR_CLIENT_NOT_TRUSTED",
            kdc_err_certificate_mismatch => "KDC_ERR_CERTIFICATE_MISMATCH",
            kdc_err_wrong_realm => "KDC_ERR_WRONG_REALM",
            kdc_err_cant_verify_certificate => "KDC_ERR_CANT_VERIFY_CERTIFICATE",
            kdc_err_invalid_certificate => "KDC_ERR_INVALID_CERTIFICATE",
            kdc_err_preauth_expired => "KDC_ERR_PREAUTH_EXPIRED",
            kdc_err_more_preauth_data_required => "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED",
            kdc_err_preauth_bad_authentication_set => "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET",
            kdc_err_unknown_critical_fast_options => "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS",
            else => "KRB_ERR_UNKNOWN",
        };
    }

    /// True for the RFC 6113 multi-step pre-auth codes (FAST/SPAKE/PKINIT
    /// negotiation): the principal exists but the KDC wants another round we
    /// don't implement — treat as non-fatal, not a confirmed credential.
    pub fn isMorePreauthRequired(code: i32) bool {
        return code == kdc_err_more_preauth_data_required or
            code == kdc_err_preauth_expired or
            code == kdc_err_preauth_bad_authentication_set or
            code == kdc_err_unknown_critical_fast_options;
    }

    /// True for the PKINIT certificate-related failures (the account likely
    /// requires smartcard/cert auth and is not password-sprayable).
    pub fn isPkinitError(code: i32) bool {
        return code == kdc_error_client_not_trusted or
            code == kdc_err_certificate_mismatch or
            code == kdc_err_cant_verify_certificate or
            code == kdc_err_invalid_certificate or
            code == kdc_err_revoked_certificate or
            code == kdc_err_client_name_mismatch;
    }

    /// Returns a human-readable "(N) NAME description" string for an error
    /// code. Mirrors gokrb5 errorcode.Lookup. Returns null for unknown codes.
    pub fn lookup(code: i32) ?[]const u8 {
        return switch (code) {
            kdc_err_none => "(0) KDC_ERR_NONE No error",
            kdc_err_name_exp => "(1) KDC_ERR_NAME_EXP Client's entry in database has expired",
            kdc_err_service_exp => "(2) KDC_ERR_SERVICE_EXP Server's entry in database has expired",
            kdc_err_bad_pvno => "(3) KDC_ERR_BAD_PVNO Requested protocol version number not supported",
            kdc_err_c_principal_unknown => "(6) KDC_ERR_C_PRINCIPAL_UNKNOWN Client not found in Kerberos database",
            kdc_err_s_principal_unknown => "(7) KDC_ERR_S_PRINCIPAL_UNKNOWN Server not found in Kerberos database",
            kdc_err_principal_not_unique => "(8) KDC_ERR_PRINCIPAL_NOT_UNIQUE Multiple principal entries in database",
            kdc_err_null_key => "(9) KDC_ERR_NULL_KEY The client or server has a null key",
            kdc_err_cannot_postdate => "(10) KDC_ERR_CANNOT_POSTDATE Ticket not eligible for postdating",
            kdc_err_never_valid => "(11) KDC_ERR_NEVER_VALID Requested starttime is later than end time",
            kdc_err_policy => "(12) KDC_ERR_POLICY KDC policy rejects request",
            kdc_err_badoption => "(13) KDC_ERR_BADOPTION KDC cannot accommodate requested option",
            kdc_err_etype_nosupp => "(14) KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type",
            kdc_err_sumtype_nosupp => "(15) KDC_ERR_SUMTYPE_NOSUPP KDC has no support for checksum type",
            kdc_err_padata_type_nosupp => "(16) KDC_ERR_PADATA_TYPE_NOSUPP KDC has no support for padata type",
            kdc_err_trtype_nosupp => "(17) KDC_ERR_TRTYPE_NOSUPP KDC has no support for transited type",
            kdc_err_client_revoked => "(18) KDC_ERR_CLIENT_REVOKED Clients credentials have been revoked",
            kdc_err_service_revoked => "(19) KDC_ERR_SERVICE_REVOKED Credentials for server have been revoked",
            kdc_err_tgt_revoked => "(20) KDC_ERR_TGT_REVOKED TGT has been revoked",
            kdc_err_client_notyet => "(21) KDC_ERR_CLIENT_NOTYET Client not yet valid; try again later",
            kdc_err_service_notyet => "(22) KDC_ERR_SERVICE_NOTYET Server not yet valid; try again later",
            kdc_err_key_expired => "(23) KDC_ERR_KEY_EXPIRED Password has expired; change password to reset",
            kdc_err_preauth_failed => "(24) KDC_ERR_PREAUTH_FAILED Pre-authentication information was invalid",
            kdc_err_preauth_required => "(25) KDC_ERR_PREAUTH_REQUIRED Additional pre-authentication required",
            kdc_err_server_nomatch => "(26) KDC_ERR_SERVER_NOMATCH Requested server and ticket don't match",
            kdc_err_must_use_user2user => "(27) KDC_ERR_MUST_USE_USER2USER Server principal valid for user2user only",
            kdc_err_path_not_accepted => "(28) KDC_ERR_PATH_NOT_ACCEPTED KDC policy rejects transited path",
            kdc_err_svc_unavailable => "(29) KDC_ERR_SVC_UNAVAILABLE A service is not available",
            krb_ap_err_bad_integrity => "(31) KRB_AP_ERR_BAD_INTEGRITY Integrity check on decrypted field failed",
            krb_ap_err_tkt_expired => "(32) KRB_AP_ERR_TKT_EXPIRED Ticket expired",
            krb_ap_err_tkt_nyv => "(33) KRB_AP_ERR_TKT_NYV Ticket not yet valid",
            krb_ap_err_repeat => "(34) KRB_AP_ERR_REPEAT Request is a replay",
            krb_ap_err_not_us => "(35) KRB_AP_ERR_NOT_US The ticket isn't for us",
            krb_ap_err_badmatch => "(36) KRB_AP_ERR_BADMATCH Ticket and authenticator don't match",
            krb_ap_err_skew => "(37) KRB_AP_ERR_SKEW Clock skew too great",
            krb_ap_err_badaddr => "(38) KRB_AP_ERR_BADADDR Incorrect net address",
            krb_ap_err_badversion => "(39) KRB_AP_ERR_BADVERSION Protocol version mismatch",
            krb_ap_err_msg_type => "(40) KRB_AP_ERR_MSG_TYPE Invalid msg type",
            krb_ap_err_modified => "(41) KRB_AP_ERR_MODIFIED Message stream modified",
            krb_ap_err_badorder => "(42) KRB_AP_ERR_BADORDER Message out of order",
            krb_ap_err_badkeyver => "(44) KRB_AP_ERR_BADKEYVER Specified version of key is not available",
            krb_ap_err_nokey => "(45) KRB_AP_ERR_NOKEY Service key not available",
            krb_ap_err_mut_fail => "(46) KRB_AP_ERR_MUT_FAIL Mutual authentication failed",
            krb_ap_err_baddirection => "(47) KRB_AP_ERR_BADDIRECTION Incorrect message direction",
            krb_ap_err_method => "(48) KRB_AP_ERR_METHOD Alternative authentication method required",
            krb_ap_err_badseq => "(49) KRB_AP_ERR_BADSEQ Incorrect sequence number in message",
            krb_ap_err_inapp_cksum => "(50) KRB_AP_ERR_INAPP_CKSUM Inappropriate type of checksum in message",
            krb_ap_path_not_accepted => "(51) KRB_AP_PATH_NOT_ACCEPTED Policy rejects transited path",
            krb_err_response_too_big => "(52) KRB_ERR_RESPONSE_TOO_BIG Response too big for UDP; retry with TCP",
            krb_err_generic => "(60) KRB_ERR_GENERIC Generic error (description in e-text)",
            krb_err_field_toolong => "(61) KRB_ERR_FIELD_TOOLONG Field is too long for this implementation",
            kdc_error_client_not_trusted => "(62) KDC_ERR_CLIENT_NOT_TRUSTED Reserved for PKINIT — client cert not trusted",
            kdc_error_kdc_not_trusted => "(63) KDC_ERR_KDC_NOT_TRUSTED Reserved for PKINIT — KDC cert not trusted",
            kdc_error_invalid_sig => "(64) KDC_ERR_INVALID_SIG Reserved for PKINIT — invalid signature",
            kdc_err_key_too_weak => "(65) KDC_ERR_KEY_TOO_WEAK Reserved for PKINIT — DH key too weak",
            kdc_err_certificate_mismatch => "(66) KDC_ERR_CERTIFICATE_MISMATCH Reserved for PKINIT — certificate mismatch",
            krb_ap_err_no_tgt => "(67) KRB_AP_ERR_NO_TGT No TGT available to validate USER-TO-USER",
            kdc_err_wrong_realm => "(68) KDC_ERR_WRONG_REALM Wrong realm (referral)",
            krb_ap_err_user_to_user_required => "(69) KRB_AP_ERR_USER_TO_USER_REQUIRED Ticket must be for USER-TO-USER",
            kdc_err_cant_verify_certificate => "(70) KDC_ERR_CANT_VERIFY_CERTIFICATE Reserved for PKINIT — can't verify certificate",
            kdc_err_invalid_certificate => "(71) KDC_ERR_INVALID_CERTIFICATE Reserved for PKINIT — invalid certificate",
            kdc_err_revoked_certificate => "(72) KDC_ERR_REVOKED_CERTIFICATE Reserved for PKINIT — revoked certificate",
            kdc_err_revocation_status_unknown => "(73) KDC_ERR_REVOCATION_STATUS_UNKNOWN Reserved for PKINIT — revocation status unknown",
            kdc_err_revocation_status_unavailable => "(74) KDC_ERR_REVOCATION_STATUS_UNAVAILABLE Reserved for PKINIT — revocation status unavailable",
            kdc_err_client_name_mismatch => "(75) KDC_ERR_CLIENT_NAME_MISMATCH Reserved for PKINIT — client name mismatch",
            kdc_err_kdc_name_mismatch => "(76) KDC_ERR_KDC_NAME_MISMATCH Reserved for PKINIT — KDC name mismatch",
            kdc_err_preauth_expired => "(90) KDC_ERR_PREAUTH_EXPIRED Pre-authentication has expired",
            kdc_err_more_preauth_data_required => "(91) KDC_ERR_MORE_PREAUTH_DATA_REQUIRED KDC requires more pre-auth data (FAST/SPAKE/PKINIT multi-step)",
            kdc_err_preauth_bad_authentication_set => "(92) KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET Unsupported pre-auth authentication set",
            kdc_err_unknown_critical_fast_options => "(93) KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS Unknown critical FAST options",
            else => null,
        };
    }
};
