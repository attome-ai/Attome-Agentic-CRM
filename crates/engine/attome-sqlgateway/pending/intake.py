"""Adds the SQL gateway's new crates to docs/dependencies/intake.json (Y3-T1)."""
import json

p = "docs/dependencies/intake.json"
d = json.load(open(p, encoding="utf-8"))
why = "Y3-T1: the SQL gateway (attome-sqlgateway)"
entries = [
    ("pgwire", "MIT OR Apache-2.0", f"{why} speaks the PostgreSQL wire protocol (startup, cleartext password, simple and extended query) through this library; ring features only, never the aws-lc-rs default.", "Active; frequent releases (0.42.1, 2026-10), widely used by Rust databases that speak the Postgres protocol."),
    ("postgres-types", "MIT OR Apache-2.0", f"{why}: pgwire's type and wire-encoding definitions.", "Part of rust-postgres, maintained with tokio-postgres."),
    ("postgres-protocol", "MIT OR Apache-2.0", f"{why}: the message codec under postgres-types.", "Part of rust-postgres, maintained with tokio-postgres."),
    ("pg_interval", "MIT", f"{why}: pgwire's PostgreSQL interval type.", "Small, stable; released 2026-06."),
    ("derive-new", "MIT", f"{why}: a derive macro pgwire uses for its constructors (build time only).", "Stable, widely used."),
    ("lazy-regex", "MIT", f"{why}: pgwire's compiled-once regular expressions.", "Active; released 2026-10."),
    ("lazy-regex-proc_macros", "MIT", f"{why}: the macros of lazy-regex (build time only).", "Released in lock-step with lazy-regex."),
    ("md5", "Apache-2.0 OR MIT", f"{why}: pgwire's MD5 password mechanism, which the gateway does not offer (it asks for the cleartext password and checks it against the stored API key hash).", "Stable; released 2026-07."),
    ("smol_str", "MIT OR Apache-2.0", f"{why}: small-string type used inside pgwire.", "Maintained by the rust-analyzer team; released 2026-10."),
    ("array-init", "MIT OR Apache-2.0", f"{why}: array construction helper inside postgres-protocol.", "Small and stable."),
    ("x509-certificate", "MPL-2.0", f"{why}: certificate parsing pgwire compiles in with its ring TLS features; the gateway runs without TLS (behind a proxy) and does not use it.", "Maintained (released 2025-08); MPL-2.0 is file-level copyleft and allowed by deny.toml."),
    ("bcder", "BSD-3-Clause", f"{why}: BER/DER encoding under x509-certificate.", "Maintained by NLnet Labs; released 2026-06."),
]
have = {(e.get("ecosystem"), e.get("name")) for e in d["dependencies"]}
for name, licence, reason, maintenance in entries:
    if ("cargo", name) in have:
        continue
    d["dependencies"].append({
        "ecosystem": "cargo",
        "name": name,
        "reason": reason,
        "licence": licence,
        "maintenance": maintenance,
        "windows_native": True,
    })
with open(p, "w", encoding="utf-8", newline="\n") as f:
    json.dump(d, f, ensure_ascii=False, indent=2)
    f.write("\n")
print("intake entries:", len(d["dependencies"]))
