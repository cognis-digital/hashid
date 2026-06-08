# Demo 01 — Basic hash triage

A SOC analyst exports a set of suspicious credential artifacts (recovered
from a leaked config, an LDAP dump, and a legacy DB) and needs to know,
for each one: **what kind of hash is this, and how hard is it to crack?**

`hashes.txt` contains one artifact per line:

- A 32-char hex digest (likely MD5).
- A 40-char hex digest (likely SHA-1).
- A bcrypt `$2b$` string (a real KDF with a work factor).
- A `$6$` crypt(3) SHA-512 entry from `/etc/shadow`.
- An LDAP `{SSHA}` salted SHA-1 entry.
- A CRC32 checksum (NOT a security primitive).

## Run

Identify only:

```
python -m hashid identify -f demos/01-basic/hashes.txt
```

Identify + crack-feasibility estimate, JSON for piping into a SIEM:

```
python -m hashid --format json estimate -f demos/01-basic/hashes.txt
```

## Expected reading

- The MD5/SHA-1/CRC32 entries report **trivial/weak** feasibility and are
  flagged as broken/legacy — migrate them.
- The bcrypt and `$6$` entries report **strong/infeasible** brute-force
  feasibility because their throughput class is intentionally tiny.
- Exit code is **1** because at least one hash type was identified
  (a finding worth acting on). An unidentifiable blob yields exit **0**.
