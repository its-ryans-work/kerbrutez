# kerbrutez

```
    __             __               __
   / /_____  _____/ /_  _______  __/ /____  ____/\
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \/__   /
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/  /  /__
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/  / ____/
                                            \/
```

A from-scratch **Zig** port of
[ropnop/kerbrute](https://github.com/ropnop/kerbrute) — the same fast Kerberos
username enumeration and password spraying, as one static, dependency-free
binary — with a set of quality-of-life features layered on top.

## ⚡ New features ⚡

* **Timed password-spraying campaigns** — the headline feature: spray on a
  cadence that stays *under* the account-lockout policy. The per-user attempt
  budget is derived from the tool's own log (no AD reads), paces itself across
  observation windows, auto-resumes, dedups, coordinates across concurrent
  runs, and panic-stops if anything locks.
* **Kerberoasting, three ways** — standard (LDAP-sourced SPNs), credential-less
  (through a no-pre-auth account), and DACL abuse (write a temp SPN onto a
  GenericWrite victim, roast, then restore).
* **AS-REP roasting** — dump crackable `$krb5asrep$` hashes for accounts that
  don't require pre-auth.
* **LDAP & password-policy recon** — enumerate users (flagging
  disabled / SPN / no-pre-auth) and read the real lockout policy, fine-grained
  PSOs included.
* **User ingest** — build your target user list from an offline source instead
  of retyping it: **BloodHound** (a SharpHound `users.json`, directory, or
  `.zip`) or **nxc / NetExec** (a `--users-export` file, or a tee'd/piped
  `--users` / `--active-users` console capture). Ingested users are saved to the
  per-realm state file, so a later spray can target them all with `@state` — no
  list argument needed.
* **OPSEC controls** — jitter, a global rate cap, order randomization,
  canary/honeypot avoidance, business-hours windows, and SOCKS5 routing.
* **Structured reporting** — JSON / greppable / raw / hashcat-ready output
  files, an optional webhook, and an end-of-run findings summary.
* **Interactive wizard** — `kerbrutez wizard` walks you through any operation.

> **Status — beta.** kerbrutez is largely AI-written ("vibe-coded") and
> human-reviewed, with every offensive primitive exercised by hand against a
> live lab (see [Tested & validated](#tested--validated)). It is **not**
> warranty-backed or independently audited. **Use it at your own risk.**

> ⚠️ **For authorized security testing only.** Failed Kerberos pre-auth counts
> as a failed logon and *will lock out* accounts under a lockout policy. Use
> only against systems you own or have explicit written permission to assess.

## Why kerbrutez?

* **An experiment to learn more about Zig and Kerberos.**
* **One static binary, zero dependencies, any platform.** Zig cross-compiles a
  single self-contained executable for Linux / Windows / macOS (x86-64 and
  ARM64) — no runtime, no DLLs, no `python`/`go` on the target.
* **Its own Kerberos stack.** Because there's no `gokrb5` for Zig, kerbrutez
  ships a small, dependency-free Kerberos 5 library in [`krb5/`](krb5/) (ASN.1
  DER, the RFC 3961/3962/4757/8009 crypto, the AS/TGS message types and KDC
  networking) plus a focused LDAP v3 client in [`ldap/`](ldap/). Both are
  reusable on their own and can be ported to other projects (GNU GPLv3). 
* **Lockout-aware by design.** The spray/brute engine derives a per-user
  attempt budget purely from its own NDJSON log (no AD reads required), paces
  itself to stay *under* the policy, auto-resumes, and panic-stops on lockouts.

## Features

Run `kerbrutez --help` for the full flag reference, or `kerbrutez wizard` to be
walked through any of this interactively.

### Username enumeration & AS-REP roasting
Probe Kerberos pre-auth to find valid usernames; dump crackable hashes for
accounts that don't require pre-auth.
```sh
kerbrutez userenum -d corp.local --dc 10.0.0.10 users.txt
kerbrutez userenum -d corp.local --dc 10.0.0.10 --asrep -o run users.txt   # dump $krb5asrep$
kerbrutez userenum -d corp.local --dc 10.0.0.10 --etype-probe users.txt    # per-user etype matrix
```

### Kerberoasting — three ways
```sh
# C1  standard: enumerate every SPN account over LDAP and roast them
kerbrutez kerberoast -d corp.local --dc 10.0.0.10 --ldap-user joe --ldap-pass P -o roast
# C1  single target
kerbrutez kerberoast -d corp.local --dc 10.0.0.10 --ldap-user joe --ldap-pass P --userspn MSSQLSvc/db.corp.local:1433
# C2  credential-less: roast a service via a DONT_REQUIRE_PREAUTH account, no password
kerbrutez kerberoast -d corp.local --dc 10.0.0.10 --nopreauth-user svc_norpre --userspn MSSQLSvc/db.corp.local:1433
# C3  DACL abuse: write a temp SPN onto a GenericWrite victim, roast, then restore
kerbrutez kerberoast -d corp.local --dc 10.0.0.10 --ldap-user abuser --ldap-pass P --target-user victim
```
Output hashes are byte-for-byte impacket-format and land in
`<base>.cred.hc<mode>` files, ready for `hashcat -m 19700|13100`.

### Password spraying & bruteforce — lockout-safe campaigns
```sh
kerbrutez passwordspray -d corp.local --dc 10.0.0.10 users.txt 'Spring2026!'
# spraycampaign: <users> x <passwords>, each a file OR a single value (any mix),
# resumable + deduped + lockout-paced (password-major order):
kerbrutez spraycampaign -d corp.local --dc 10.0.0.10 --policy-fetch \
          --ldap-user joe --ldap-pass P users.txt passwords.txt
```
The budget is computed from the tool's own attempt log (resumable, deduped per
realm). `--policy-fetch` reads the real AD lockout policy (and any fine-grained
PSOs) over LDAP; `--check-badpwdcount` shrinks the first window. One-shot runs
that would exceed the budget **auto-promote to a campaign** with an ETA, and the
run **panic-stops** after `--panic-after` lockouts.

### LDAP recon & user ingest
```sh
kerbrutez ldapenum -d corp.local --dc 10.0.0.10 --ldap-user joe --ldap-pass P     # live LDAP: flags DISABLED / SPN / NO-PREAUTH
kerbrutez ldapenum -d corp.local --bloodhound ./sharphound.zip -o working.txt     # offline: SharpHound users.json / dir / .zip
```
Ingest a user list you already collected with **nxc / NetExec** — either the
clean `--users-export` file, or a tee'd/piped capture of the `--users` /
`--active-users` console output (kerbrutez strips the `PROTO IP PORT HOST`
prefix, drops banner/credential/header lines, and de-duplicates):
```sh
# clean export file (one sAMAccountName per line)
nxc smb  10.0.0.10 -u u -p p --users-export users.txt
kerbrutez ldapenum -d corp.local --nxc users.txt

# tee'd console (the ONLY way to get an active-only list: --active-users prints
# active users to the console, but --users-export always writes ALL of them)
nxc ldap 10.0.0.10 -u u -p p --active-users | tee active.txt
kerbrutez ldapenum -d corp.local --nxc active.txt

# or pipe the console straight in with '-'
nxc smb 10.0.0.10 -u u -p p --users | kerbrutez ldapenum -d corp.local --nxc -
```
With `-d`, an ingest also saves the users to the per-realm state file, so you can
spray them all later without a list argument:
```sh
kerbrutez spraycampaign -d corp.local --dc 10.0.0.10 @state 'Spring2026!'         # spray every ingested user
```

### OPSEC controls
`--noise 1|2|3` (stealthy→loud) sets sane defaults you can override:
`--jitter`, `--rpm` (global rate cap), `--randomize` (shuffle order),
`--canary-file` (never touch known honeypot accounts, + a bait-name heuristic),
`--business-hours`, and `--socks host:port` (route KDC traffic through a SOCKS5
proxy — the proxy resolves the DC, so no DNS leak). **OPSEC never relaxes the
lockout budget.**

### Reporting
`--json`, `-o <base>` (writes `.json` / `.grep.txt` / `.raw.txt` /
`.cred.hc<mode>`), an always-on auto-saved JSON under
`~/.local/share/kerbrutez/logs/`, `--webhook` (POST on a cred/lockout), an
end-of-run findings summary, and a Windows event-log footprint note
(4768 / 4769 / 4771).

### Detection & discovery
A full RFC 4120 / 6113 KDC error map; classification of **PKINIT-required**
(not sprayable) and **FAST-armored** accounts; graceful handling of multi-step
pre-auth (KDC_ERR 91). KDCs are found via DNS SRV when `--dc` is omitted
(`--dns` overrides the resolver), and hostname `--dc` values are resolved
automatically.

## Tested & validated

kerbrutez is validated **live** against:

* a local **Samba 4.x Active Directory DC**, and
* **[GOAD](https://github.com/Orange-Cyberdefense/GOAD)** (Game of Active
  Directory) — Orange Cyberdefense's real Windows Server AD lab, on **Windows
  Server 2019 / 2016** domain controllers.

Every offensive primitive was end-to-end verified there — including cracking the
captured AS-REP / TGS hashes with **[hashcat](https://hashcat.net/)** (modes
18200 / 19700 / 13100) back to the known lab passwords. Test artifacts may be found
in the repo. These are not leaks, but intentional to prevent regression during
iterative development. 

**Byte-for-byte cross-checks & shout-outs** — kerbrutez's wire format and hash
output were validated against the reference implementations:

* **[ropnop/kerbrute](https://github.com/ropnop/kerbrute)** by Ronnie Flathers
  (@ropnop) — the original tool this ports; behavior parity baseline.
* **[gokrb5](https://github.com/jcmturner/gokrb5)** by @jcmturner — the Go
  Kerberos library kerbrute uses. The AS-REQ encoding and AS-REP decryption are
  byte-identical to gokrb5's, verified against its test vectors.
* **[impacket](https://github.com/fortra/impacket)** (Fortra) — the
  `$krb5asrep$` and `$krb5tgs$` hash formats match impacket's `GetNPUsers` /
  `GetUserSPNs` exactly (the format was taken straight from impacket's source).

## The libraries

* [`krb5/`](krb5/) — a dependency-free Kerberos 5 implementation: DER, the
  encryption-type crypto stack, the AS/TGS/AP message types, Ticket parsing, and
  UDP/TCP/SOCKS5 KDC networking with DNS SRV discovery.
* [`ldap/`](ldap/) — a focused LDAP v3 client (BER codec, bind/search/modify)
  used for user sourcing, lockout-policy reads and the C3 SPN write/restore.

## Compilation — for new targets

Prebuilt binaries for the most common platforms are on the
**[Releases page](../../releases)** — download the one for your OS/arch and run
it; nothing else is needed.

Building from source, or for a target we don't publish? Zig cross-compiles
anything from anywhere — see **[compilation.md](compilation.md)** for Zig 0.16
install steps, build commands and `-Dtarget` cross-compilation examples.

## Credits

A Zig port of the original **kerbrute** by Ronnie Flathers (**@ropnop**). The
Kerberos protocol implementation follows the design of **@jcmturner**'s
**gokrb5**, and the roast hash formats match **impacket**. Validated against
**Samba** and **GOAD**, cracked with **hashcat**. Thank you to all of the above.
