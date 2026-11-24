"""File classification by extension and by magic bytes."""
from __future__ import annotations

import os
import re

EXT_DB = {".db", ".sqlite", ".sqlite3", ".db3", ".mdb", ".accdb", ".sql", ".dump", ".bak",
          ".sqlitedb", ".frm", ".myd", ".ibd", ".dbf", ".ndf", ".mdf", ".ldf"}
EXT_EXEC = {".exe", ".dll", ".so", ".bin", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".com",
            ".scr", ".apk", ".jar", ".app", ".deb", ".rpm", ".elf", ".o", ".dylib"}
EXT_KEY = {".pem", ".key", ".pfx", ".p12", ".crt", ".cer", ".keystore", ".jks", ".ppk",
           ".pub", ".asc", ".gpg", ".kdbx", ".ovpn"}
EXT_CONFIG = {".env", ".ini", ".cfg", ".conf", ".config", ".yaml", ".yml", ".toml",
              ".properties", ".json", ".xml", ".plist", ".tfvars", ".tfstate"}
ARCH_ZIP = {".zip", ".jar", ".war", ".ear", ".apk", ".odt", ".ods", ".odp", ".xpi",
            ".whl", ".egg", ".nupkg"}
ARCH_TAR = {".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tbz2", ".txz"}
ARCH_SINGLE = {".gz", ".bz2", ".xz"}
ARCH_7Z = {".7z"}
ARCH_RAR = {".rar"}
ARCHIVE_ALL = ARCH_ZIP | ARCH_TAR | ARCH_SINGLE | ARCH_7Z | ARCH_RAR
BINARY_SKIP = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp", ".ico",
               ".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".mp4", ".avi", ".mov",
               ".mkv", ".webm", ".wmv", ".flv", ".ttf", ".otf", ".woff", ".woff2", ".eot",
               ".psd", ".pyc", ".class", ".wasm", ".pdb", ".lib", ".a", ".iso", ".img",
               ".vmdk", ".dmg", ".heic"}
IMAGE_EXT = {".jpg", ".jpeg", ".png", ".bmp", ".tiff", ".tif", ".webp", ".gif"}
DOC_EXTRACT = {".pdf", ".docx", ".xlsx", ".xlsm", ".pptx", ".eml", ".msg"}

# Asset tags (English, used in reports and logic).
TAG_DATABASE = "database"
TAG_EXECUTABLE = "executable"
TAG_KEY_MATERIAL = "key_material"
TAG_ARCHIVE = "archive"
TAG_CONFIG = "config"
TAG_SENSITIVE_NAME = "sensitive_name"
TAG_GIT_HISTORY = "git_history"

JUICY_NAMES = re.compile(
    r"(?i)^(\.env.*|\.?npmrc|\.?pypirc|\.?netrc|\.?pgpass|\.?my\.cnf|"
    r"id_rsa.*|id_dsa.*|id_ecdsa.*|id_ed25519.*|known_hosts|authorized_keys|"
    r"config\.php|wp-config\.php|settings\.py|local_settings\.py|secrets?.*|"
    r"credentials?.*|shadow|passwd|htpasswd|\.htpasswd|\.git-credentials|"
    r"docker-compose\.ya?ml|\.?dockercfg|\.?aws|\.?ssh|backup.*|dump.*|"
    r"unattend.*|sysprep.*|web\.config|\.?kube.*|.*\.ovpn|.*\.kdbx|"
    r".*password.*|.*secret.*|.*confidential.*|.*payroll.*)$")

DEFAULT_SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "venv", "env", ".idea",
                     ".vscode", "dist", "build", ".next", ".cache", "vendor",
                     "site-packages", ".terraform", ".gradle", ".mypy_cache",
                     ".pytest_cache"}

_MAGIC = [
    (b"MZ", "executable"), (b"\x7fELF", "executable"),
    (b"SQLite format 3\x00", "database"),
    (b"-----BEGIN", "key_material"), (b"PuTTY-User-Key", "key_material"),
    (b"%PDF", "pdf_document"), (b"PK\x03\x04", "zip"),
    (b"Rar!\x1a\x07", "rar"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"), (b"\xfd7zXZ", "xz"),
]


def ext_of(name: str) -> str:
    """Lowercase extension, recognizing compound ones like .tar.gz."""
    low = name.lower()
    for comp in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if low.endswith(comp):
            return comp
    return os.path.splitext(low)[1]


def sniff_magic(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return None
    for sig, kind in _MAGIC:
        if head.startswith(sig):
            return kind
    return None


def classify(name: str, ext: str, magic_kind: str | None) -> list[str]:
    tags: list[str] = []
    if ext in EXT_DB or magic_kind == "database":
        tags.append(TAG_DATABASE)
    if ext in EXT_EXEC or magic_kind == "executable":
        tags.append(TAG_EXECUTABLE)
    if ext in EXT_KEY or magic_kind == "key_material":
        tags.append(TAG_KEY_MATERIAL)
    if ext not in DOC_EXTRACT and (ext in ARCHIVE_ALL or magic_kind in ("zip", "rar", "7z", "gzip", "bzip2", "xz")):
        tags.append(TAG_ARCHIVE)
    if ext in EXT_CONFIG:
        tags.append(TAG_CONFIG)
    if JUICY_NAMES.match(name):
        tags.append(TAG_SENSITIVE_NAME)
    return tags
