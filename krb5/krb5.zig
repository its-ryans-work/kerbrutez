//! krb5 — a standalone, dependency-free Kerberos 5 implementation in Zig.
//!
//! This module is the gokrb5 replacement for kerbrutez, but is intentionally
//! kept self-contained so it can be reused as a general Kerberos library.
//! It implements (a subset of RFC 4120 / 3961 / 3962 / 4757 / 8009) the pieces
//! required to perform AS exchanges against a KDC: ASN.1 DER, the Kerberos
//! message types, the encryption-type crypto stack, and KDC networking.

const std = @import("std");

pub const iana = @import("iana/constants.zig");
pub const der = @import("asn1/der.zig");

pub const md4 = @import("crypto/md4.zig");
pub const rc4 = @import("crypto/rc4.zig");
pub const nfold = @import("crypto/nfold.zig");
pub const cts = @import("crypto/cts.zig");
pub const des = @import("crypto/des.zig");
pub const etype = @import("crypto/etype.zig");
pub const rng = @import("crypto/rng.zig");

pub const principal_name = @import("types/principal_name.zig");
pub const encrypted_data = @import("types/encrypted_data.zig");
pub const pa_data = @import("types/pa_data.zig");
pub const kerberos_flags = @import("types/kerberos_flags.zig");

pub const keys = @import("crypto/keys.zig");

pub const kdc_req = @import("messages/kdc_req.zig");
pub const kdc_rep = @import("messages/kdc_rep.zig");
pub const krb_error = @import("messages/krb_error.zig");
pub const ticket = @import("messages/ticket.zig");
pub const tgs = @import("messages/tgs.zig");

pub const config = @import("config/config.zig");
pub const dns = @import("config/dns.zig");

pub const network = @import("client/network.zig");
pub const client = @import("client/client.zig");

test {
    std.testing.refAllDecls(@This());
    _ = iana;
    _ = der;
    _ = md4;
    _ = rc4;
    _ = nfold;
    _ = cts;
    _ = des;
    _ = etype;
    _ = rng;
    _ = principal_name;
    _ = encrypted_data;
    _ = pa_data;
    _ = kerberos_flags;
    _ = keys;
    _ = kdc_req;
    _ = kdc_rep;
    _ = krb_error;
    _ = ticket;
    _ = tgs;
    _ = config;
    _ = dns;
    _ = network;
    _ = client;
}
