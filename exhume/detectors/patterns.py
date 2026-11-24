"""Catalog of secret and PII detectors.

Each :class:`Detector` wraps a regex, its severity, whether it needs an entropy
check, the key of its active verifier (if any), fast-path literal anchors, and
an optional validator that confirms the match is real (IPs, URLs, cards).
Patterns favor provider-specific prefixes to minimize false positives
(Gitleaks/TruffleHog-style strategy).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Severity


@dataclass(frozen=True)
class Detector:
    name: str
    regex: re.Pattern
    severity: Severity
    needs_entropy: bool = False
    verifier: str | None = None
    # Literal lowercase keywords for fast prefiltering. If set, the detector is
    # only evaluated on lines that contain at least one of them.
    anchors: tuple[str, ...] = ()
    # Name of a validator (in VALIDATORS) that confirms the match is real.
    validator: str | None = None


def _d(name, pattern, sev, *, flags=0, entropy=False, verifier=None, anchors=(), validator=None):
    return Detector(name, re.compile(pattern, flags), sev, entropy, verifier, tuple(anchors), validator)


C, H, M = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM

DETECTORS: list[Detector] = [
    # --- Private keys / certificates ---
    _d("Private key (PEM)", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", C,
       anchors=("private key",)),
    _d("PuTTY private key (.ppk)", r"PuTTY-User-Key-File-\d", C, anchors=("putty-user-key",)),
    _d("GCP service account (JSON)", r'"type"\s*:\s*"service_account"', C, anchors=("service_account",)),

    # --- Cloud / SaaS with provider-specific formats ---
    _d("AWS Access Key ID", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b", C,
       verifier="aws", anchors=("akia", "asia", "agpa", "aida", "aroa", "aipa", "anpa", "anva")),
    _d("AWS Secret Access Key", r"(?i)aws(.{0,20})?(?:secret|access).{0,5}['\"=:\s]+([A-Za-z0-9/+=]{40})", C,
       anchors=("aws",)),
    _d("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", C, anchors=("aiza",)),
    _d("Google OAuth token", r"\bya29\.[0-9A-Za-z\-_]+", C, anchors=("ya29.",)),
    _d("GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,}\b", C, verifier="github",
       anchors=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    _d("GitHub fine-grained PAT", r"\bgithub_pat_[0-9A-Za-z_]{40,}\b", C, verifier="github",
       anchors=("github_pat_",)),
    _d("GitLab token", r"\bglpat-[0-9A-Za-z\-_]{20,}\b", C, verifier="gitlab", anchors=("glpat-",)),
    _d("Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", C, verifier="slack",
       anchors=("xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-")),
    _d("Slack app token", r"\bxapp-\d-[A-Za-z0-9-]+\b", C, anchors=("xapp-",)),
    _d("Slack webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", H, anchors=("hooks.slack.com",)),
    _d("Stripe secret key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,}\b", C, verifier="stripe",
       anchors=("sk_live", "sk_test", "rk_live", "rk_test")),
    _d("Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", H, anchors=("sk",)),
    _d("Twilio Account SID", r"\bAC[0-9a-fA-F]{32}\b", H, anchors=("ac",)),
    _d("SendGrid key", r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", C, verifier="sendgrid",
       anchors=("sg.",)),
    _d("Mailgun key", r"\bkey-[0-9a-f]{32}\b", H, anchors=("key-",)),
    _d("Mailchimp key", r"\b[0-9a-f]{32}-us\d{1,2}\b", H, anchors=("-us",)),
    _d("npm token", r"\bnpm_[0-9A-Za-z]{36}\b", H, verifier="npm", anchors=("npm_",)),
    _d("PyPI token", r"\bpypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,}", C, anchors=("pypi-",)),
    _d("OpenAI project key", r"\bsk-proj-[A-Za-z0-9\-_]{20,}\b", C, anchors=("sk-proj-",)),
    _d("Anthropic API key", r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b", C, anchors=("sk-ant-",)),
    _d("Generic sk- key", r"\bsk-[A-Za-z0-9]{20,}\b", H, anchors=("sk-",)),
    _d("Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}\b", H, anchors=("hf_",)),
    _d("Heroku API key",
       r"(?i)heroku.{0,20}['\"=:\s]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", H,
       anchors=("heroku",)),
    _d("Firebase Cloud Messaging key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}", H, anchors=("aaaa",)),
    _d("Azure Storage key", r"(?i)(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{40,}", C,
       anchors=("accountkey", "sharedaccesskey")),
    _d("Azure AD client secret", r"\b[A-Za-z0-9~._\-]{3}\dQ~[A-Za-z0-9~._\-]{31,34}\b", C, anchors=("q~",)),
    _d("DigitalOcean token", r"\bdop_v1_[0-9a-f]{64}\b", C, verifier="digitalocean", anchors=("dop_v1_",)),
    _d("DigitalOcean OAuth token", r"\bdoo_v1_[0-9a-f]{64}\b", C, anchors=("doo_v1_",)),
    _d("Shopify token", r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b", C,
       anchors=("shpat_", "shpca_", "shppa_", "shpss_")),
    _d("Square access token", r"\b(?:sq0atp|sq0csp|EAAA)[0-9A-Za-z\-_]{22,}\b", C,
       anchors=("sq0atp", "sq0csp", "eaaa")),
    _d("New Relic key", r"\bNRAK-[0-9A-Z]{27}\b", H, anchors=("nrak-",)),
    _d("New Relic license key", r"\b[0-9a-f]{40}NRAL\b", H, anchors=("nral",)),
    _d("Postman API key", r"\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b", H, verifier="postman", anchors=("pmak-",)),
    _d("Databricks token", r"\bdapi[0-9a-f]{32}(?:-\d)?\b", C, anchors=("dapi",)),
    _d("HashiCorp Vault token", r"\bhv[sb]\.[A-Za-z0-9]{20,}\b", C, anchors=("hvs.", "hvb.")),
    _d("Telegram bot token", r"\b\d{6,12}:AA[0-9A-Za-z_\-]{30,}\b", H, verifier="telegram", anchors=(":aa",)),
    _d("Discord bot token", r"\b[MNO][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}\b", H, verifier="discord"),
    _d("Discord webhook", r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", H, anchors=("discord",)),
    _d("Linear API key", r"\blin_api_[0-9A-Za-z]{40}\b", H, anchors=("lin_api_",)),
    _d("Dropbox token", r"\bsl\.[A-Za-z0-9_-]{130,}\b", C, anchors=("sl.",)),
    _d("Facebook access token", r"\bEAACEdEose0cBA[0-9A-Za-z]+\b", H, anchors=("eaacedeose0cba",)),
    _d("Mapbox secret token", r"\bsk\.eyJ[0-9A-Za-z\-_]{50,}\.[0-9A-Za-z\-_]{20,}\b", H, anchors=("sk.eyj",)),
    _d("Algolia admin key", r"(?i)algolia.{0,20}['\"=:\s]([0-9a-f]{32})", H, anchors=("algolia",)),
    _d("Atlassian/Jira token", r"\bATATT3[A-Za-z0-9_\-=]{20,}\b", C, anchors=("atatt3",)),
    _d("JWT", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", H, anchors=("eyj",)),

    # --- Connection strings / embedded credentials ---
    _d("Connection URI with credentials",
       r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|ftps|sftp|ssh|ldap|jdbc:[a-z]+)"
       r"://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+", C, anchors=("://",)),
    _d("MSSQL/ODBC connection string",
       r"(?i)(?:Server|Data Source)=[^;]+;(?:[^;]*;)?Password=[^;]{3,}", C, anchors=("password=",)),
    # Keyword may be a whole token or an underscore-joined suffix (DB_PASSWORD, MYSQL_PASS),
    # but not glued inside another word (bypass=, compass=). Broad keyword set so
    # non-default variable names are still caught.
    _d("Credential assignment",
       r"(?i)(?:^|[^A-Za-z0-9_])(?:[a-z0-9]+_)*"
       r"(?:password|passwd|passphrase|pwd|pass|secret[_-]?key|secretkey|secret|"
       r"api[_-]?key|apikey|access[_-]?key|accesskey|access[_-]?token|auth[_-]?token|"
       r"refresh[_-]?token|id[_-]?token|bearer|client[_-]?secret|private[_-]?key|privkey|"
       r"priv[_-]?key|encryption[_-]?key|signing[_-]?key|master[_-]?key|db[_-]?pass|"
       r"credential|creds?|token|sas[_-]?token|connection[_-]?string|connectionstring|dsn)"
       r"\s*[:=]\s*['\"]?([^\s'\"#;]{4,})", H, entropy=True),
    _d("Credential in XML/property",
       r"(?i)<(?:password|secret|token|apikey|api-key|credential)>\s*([^<\s]{4,})\s*</", H, entropy=True),
    _d("GPP cpassword (Windows)", r"(?i)cpassword\s*=\s*[\"']?([A-Za-z0-9+/=]{10,})", C, anchors=("cpassword",)),
    _d("/etc/shadow hash", r"\$(?:1|2[aby]?|5|6|y)\$[./A-Za-z0-9]{3,}\$[./A-Za-z0-9]{10,}", H, anchors=("$",)),
    _d("NTLM hash", r"\b[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}\b", H),
    _d("Authorization header",
       r"(?i)authorization\s*[:=]\s*['\"]?(?:bearer|basic)\s+([A-Za-z0-9+/=._\-]{10,})", H,
       anchors=("authorization",)),
    _d("Basic auth in URL", r"https?://[^\s:@/]+:[^\s:@/]+@[^\s/'\"]+", H, anchors=("://",)),

    # --- PII ---
    _d("Email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", M, anchors=("@",)),
    _d("IBAN", r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b", H),
    _d("Credit card", r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ -]?\d{4}[ -]?\d{4}[ -]?\d{3,4}\b",
       H, validator="luhn"),
    _d("Spanish DNI/NIF", r"\b\d{8}[ -]?[A-HJ-NP-TV-Z]\b", M),
    _d("Spanish NIE", r"\b[XYZ][ -]?\d{7}[ -]?[A-HJ-NP-TV-Z]\b", M),
    _d("US SSN", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", M, anchors=("-",)),

    # --- Network surface (validated: REAL addresses/links, not bare numbers) ---
    _d("Internal/private URL",
       r"\bhttps?://(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
       r"192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
       r"[^\s/'\"]*\.(?:local|internal|intranet|corp|lan))[^\s'\"]*", M, anchors=("http",)),
    _d("URL", r"https?://[^\s'\"<>()\[\]]+", M, anchors=("http",), validator="url_public"),
    _d("Private IP (RFC1918)", r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])", M, validator="ipv4_private"),
    _d("Public IPv4", r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])", M, validator="ipv4_public"),
    _d("IPv6 address",
       r"(?<![:\w.])(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9]{0,4}(?![:\w.])", M, validator="ipv6"),
]

# Generic high-entropy secret (single pass per line)
GENERIC_SECRET = re.compile(r"['\"=:\s]([A-Za-z0-9+/\-_]{24,})['\"\s;,]")
ENTROPY_DENY = re.compile(
    r"(?i)(sha256|sha1|md5|integrity=|data:image|base64,|[0-9a-f]{40,}\s|^[0-9a-f]{64}$|license|lorem ipsum)"
)
# Used to pair AWS secrets (AKIA + secret verification)
AWS_SECRET_RE = re.compile(r"\b[A-Za-z0-9/+]{40}\b")

_PLACEHOLDER = re.compile(
    r"(?i)^(true|false|null|none|example|changeme|password|yourpassword|xxx+|\.{3,}|<[^>]+>|\$\{[^}]+\})$"
)


def is_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.fullmatch(value.strip()))
