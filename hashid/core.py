"""Real hash-identification + crack-feasibility engine (stdlib only).

Two stages:
  1. identify(value) -> ranked list of HashCandidate, using structural
     signatures (prefixes like $2b$, $argon2id$), length+charset for raw
     digests, and modifier rules (e.g. trailing salt).
  2. estimate_crack(candidate) -> CrackEstimate, modelling brute-force
     keyspace exhaustion against a reference attacker throughput per
     algorithm class (fast raw digests vs. deliberately slow KDFs).

Everything is heuristic and transparent — no claims of certainty, no
attack execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Optional


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class HashCandidate:
    name: str
    hashcat_mode: Optional[int]
    confidence: float          # 0..1
    category: str              # raw | salted | kdf | checksum | encoding
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CrackEstimate:
    algorithm: str
    category: str
    # reference single-attacker guesses/second for this class
    ref_guesses_per_sec: float
    # keyspace assumptions used for the brute-force model
    assumed_charset_size: int
    assumed_password_len: int
    keyspace: float
    seconds_avg: float         # average (half the keyspace)
    human_time: str
    feasibility: str           # trivial | weak | moderate | strong | infeasible
    notes: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Identification
# --------------------------------------------------------------------------
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64ISH = re.compile(r"^[0-9a-zA-Z+/.=_-]+$")

# Raw hex digests keyed by nibble length.
_RAW_HEX = {
    32: [("MD5", 0, "raw"), ("MD4", 900, "raw"), ("NTLM", 1000, "raw"),
         ("LM", 3000, "raw")],
    40: [("SHA-1", 100, "raw"), ("RIPEMD-160", 6000, "raw")],
    56: [("SHA-224", 1300, "raw"), ("SHA3-224", 17300, "raw")],
    64: [("SHA-256", 1400, "raw"), ("SHA3-256", 17400, "raw"),
         ("BLAKE2s-256", 600, "raw")],
    96: [("SHA-384", 10800, "raw"), ("SHA3-384", 17500, "raw")],
    128: [("SHA-512", 1700, "raw"), ("SHA3-512", 17600, "raw"),
          ("Whirlpool", 6100, "raw"), ("BLAKE2b-512", 600, "raw")],
    8: [("CRC32", None, "checksum"), ("Adler-32", None, "checksum")],
    16: [("MySQL323", 200, "raw"), ("CRC64", None, "checksum")],
}

# Prefixed / structured formats. (regex, name, mode, category, reason)
_PREFIXED = [
    (re.compile(r"^\$2[abxy]\$\d{2}\$[./0-9A-Za-z]{53}$"),
     "bcrypt", 3200, "kdf", "bcrypt $2*$ signature with cost factor"),
    (re.compile(r"^\$argon2(id|i|d)\$"),
     "Argon2", None, "kdf", "Argon2 PHC string"),
    (re.compile(r"^\$scrypt\$"),
     "scrypt", 8900, "kdf", "scrypt PHC string"),
    (re.compile(r"^\$pbkdf2(-sha(1|256|512))?\$"),
     "PBKDF2", 10900, "kdf", "PBKDF2 PHC string"),
    (re.compile(r"^\$6\$"),
     "sha512crypt", 1800, "kdf", "$6$ crypt(3) SHA-512"),
    (re.compile(r"^\$5\$"),
     "sha256crypt", 7400, "kdf", "$5$ crypt(3) SHA-256"),
    (re.compile(r"^\$1\$"),
     "md5crypt", 500, "kdf", "$1$ crypt(3) MD5"),
    (re.compile(r"^\$apr1\$"),
     "Apache md5apr1", 1600, "kdf", "$apr1$ Apache MD5"),
    (re.compile(r"^\{SSHA\}[A-Za-z0-9+/=]+$"),
     "LDAP SSHA", 111, "salted", "{SSHA} salted SHA-1 (LDAP)"),
    (re.compile(r"^\{SHA\}[A-Za-z0-9+/=]+$"),
     "LDAP SHA", 101, "raw", "{SHA} base64 SHA-1 (LDAP)"),
    (re.compile(r"^\*[0-9A-F]{40}$"),
     "MySQL 4.1+ (SHA1(SHA1))", 300, "raw", "MySQL *HEX 41-char form"),
    (re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{1,}$"),
     "md5($pass.$salt)", 10, "salted", "32-hex digest with appended salt"),
    (re.compile(r"^[0-9a-fA-F]{40}:.+$"),
     "sha1($pass.$salt)", 110, "salted", "40-hex digest with appended salt"),
    (re.compile(r"^sha256\$[0-9a-fA-F]+\$[0-9a-fA-F]{64}$"),
     "Django SHA-256", None, "kdf", "Django formatted sha256$salt$hash"),
    (re.compile(r"^pbkdf2_sha256\$\d+\$"),
     "Django PBKDF2-SHA256", 10000, "kdf", "Django PBKDF2 string"),
]


def _looks_hex(value: str) -> bool:
    return bool(_HEX.match(value))


def identify(value: str) -> list[HashCandidate]:
    """Return ranked candidate hash types for *value* (best first)."""
    value = value.strip()
    out: list[HashCandidate] = []
    if not value:
        return out

    # 1) structured / prefixed formats win when they match.
    for rx, name, mode, cat, reason in _PREFIXED:
        if rx.match(value):
            out.append(HashCandidate(name, mode, 0.95, cat, reason))

    # 2) raw hex digests by length.
    if _looks_hex(value):
        n = len(value)
        for name, mode, cat in _RAW_HEX.get(n, []):
            # MD5 is far more common than MD4/NTLM at len 32 — weight it.
            conf = 0.6
            if name in ("MD5", "SHA-1", "SHA-256", "SHA-512"):
                conf = 0.7
            out.append(HashCandidate(
                name, mode, conf, cat,
                f"{n}-char hex matches {name} digest width"))

    # 3) base64-ish blob of plausible digest length.
    if not out and _B64ISH.match(value) and len(value) >= 16:
        approx_bytes = (len(value.rstrip("=")) * 3) // 4
        out.append(HashCandidate(
            "base64-encoded digest/data", None, 0.3, "encoding",
            f"base64-like, ~{approx_bytes} decoded bytes; "
            f"could be SHA digest, token, or ciphertext"))

    if not out:
        out.append(HashCandidate(
            "unknown", None, 0.0, "unknown",
            "no structural or length signature matched"))

    # rank: confidence desc, then more-specific (mode known) first.
    out.sort(key=lambda c: (c.confidence, c.hashcat_mode is not None),
             reverse=True)
    return out


# --------------------------------------------------------------------------
# Crack-feasibility estimate
# --------------------------------------------------------------------------
# Reference throughput (guesses/sec) for a single capable GPU rig, by class.
# These are order-of-magnitude planning numbers, not benchmarks.
_THROUGHPUT = {
    "md5_class": 2.0e10,     # MD5/MD4/NTLM/LM/CRC — extremely fast
    "sha1_class": 8.0e9,
    "sha2_class": 3.0e9,
    "sha3_class": 1.0e9,
    "salted_fast": 2.0e9,    # fast hash + salt (no work factor)
    "kdf_slow": 2.0e4,       # bcrypt/argon2/pbkdf2/*crypt — by design slow
    "checksum": 1.0e12,      # not a security primitive
    "unknown": 1.0e9,
}

_CLASS_BY_NAME = {
    "MD5": "md5_class", "MD4": "md5_class", "NTLM": "md5_class",
    "LM": "md5_class", "MySQL323": "md5_class", "CRC32": "checksum",
    "CRC64": "checksum", "Adler-32": "checksum",
    "SHA-1": "sha1_class", "RIPEMD-160": "sha1_class",
    "MySQL 4.1+ (SHA1(SHA1))": "sha1_class", "LDAP SHA": "sha1_class",
    "SHA-224": "sha2_class", "SHA-256": "sha2_class",
    "SHA-384": "sha2_class", "SHA-512": "sha2_class",
    "Whirlpool": "sha2_class", "BLAKE2s-256": "sha2_class",
    "BLAKE2b-512": "sha2_class",
    "SHA3-224": "sha3_class", "SHA3-256": "sha3_class",
    "SHA3-384": "sha3_class", "SHA3-512": "sha3_class",
}


def _class_for(candidate: HashCandidate) -> str:
    if candidate.category == "kdf":
        return "kdf_slow"
    if candidate.category == "salted":
        return "salted_fast"
    if candidate.category == "checksum":
        return "checksum"
    return _CLASS_BY_NAME.get(candidate.name, "unknown")


def _human_time(seconds: float) -> str:
    if seconds < 1:
        return "< 1 second"
    units = [
        ("year", 365 * 24 * 3600),
        ("day", 24 * 3600),
        ("hour", 3600),
        ("minute", 60),
        ("second", 1),
    ]
    for name, size in units:
        if seconds >= size:
            val = seconds / size
            if name == "year" and val > 1e6:
                return f"{val:.2e} years (effectively infeasible)"
            return f"{val:.1f} {name}{'s' if val >= 2 else ''}"
    return f"{seconds:.1f} seconds"


def _feasibility(seconds: float, category: str) -> str:
    if category == "checksum":
        return "trivial"
    if seconds < 60:
        return "trivial"
    if seconds < 24 * 3600:
        return "weak"
    if seconds < 365 * 24 * 3600:
        return "moderate"
    if seconds < 1000 * 365 * 24 * 3600:
        return "strong"
    return "infeasible"


def estimate_crack(candidate: HashCandidate,
                   charset_size: int = 95,
                   password_len: int = 8) -> CrackEstimate:
    """Brute-force feasibility model for the given candidate.

    Defaults model an 8-char password over the printable-ASCII set (95).
    The estimate is the *average* time (half the keyspace) for a single
    reference attacker against the algorithm's throughput class.
    """
    cls = _class_for(candidate)
    rate = _THROUGHPUT[cls]
    keyspace = float(charset_size) ** password_len
    seconds_avg = (keyspace / 2.0) / rate

    notes: list[str] = []
    if candidate.category == "kdf":
        notes.append("KDF/work-factor hash: throughput is intentionally low; "
                     "raise cost/iterations to slow attackers further.")
    if candidate.category == "salted":
        notes.append("Salt defeats precomputed rainbow tables but not "
                     "per-target brute force shown here.")
    if candidate.category == "checksum":
        notes.append("Checksum, not a password hash — provides no "
                     "cryptographic protection.")
    if candidate.name in ("MD5", "SHA-1", "MD4", "NTLM", "LM"):
        notes.append("Algorithm is broken/legacy for password storage; "
                     "migrate to bcrypt/argon2id.")
    notes.append("Dictionary/rule attacks against weak passwords are far "
                 "faster than the brute-force figure above.")

    return CrackEstimate(
        algorithm=candidate.name,
        category=candidate.category,
        ref_guesses_per_sec=rate,
        assumed_charset_size=charset_size,
        assumed_password_len=password_len,
        keyspace=keyspace,
        seconds_avg=seconds_avg,
        human_time=_human_time(seconds_avg),
        feasibility=_feasibility(seconds_avg, candidate.category),
        notes=notes,
    )


def analyze(value: str, charset_size: int = 95,
            password_len: int = 8) -> dict:
    """Full pipeline: identify + estimate for the top candidate."""
    candidates = identify(value)
    top = candidates[0]
    est = (estimate_crack(top, charset_size, password_len)
           if top.name != "unknown" else None)
    return {
        "input_length": len(value.strip()),
        "candidates": [c.to_dict() for c in candidates],
        "best_guess": top.to_dict(),
        "crack_estimate": est.to_dict() if est else None,
    }
