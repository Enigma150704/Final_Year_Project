from pathlib import Path, PurePosixPath
import zipfile
import hashlib
import re
from typing import Dict, Any, Tuple

MAX_UPLOAD_BYTES = 40 * 1024 * 1024
MAX_FILES = 12000
MAX_UNCOMPRESSED_BYTES = 250 * 1024 * 1024
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024

ALLOWED_SOURCE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".php",
    ".rb", ".cs", ".cpp", ".c", ".h", ".hpp", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".xml", ".html", ".sql", ".sh",
    ".dockerfile", ".md", ".txt"
}

IGNORED_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "target", ".next", ".idea"
}

SECRET_PATTERNS = [
    re.compile(r'(?i)(api[_-]?key|secret|password|token|bearer|auth|private[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-./+=]{8,})["\']'),
    re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----')
]

def compute_sha256(data: bytes) -> str:
    """Calculate the cryptographic SHA-256 hash of byte content."""
    return hashlib.sha256(data).hexdigest()

def redact_secret_text(text: str) -> str:
    """Safely redact credential-like strings and tokens in evidence and logs."""
    if not text:
        return ""
    result = text
    # Redact private key blocks
    result = re.sub(r'-----BEGIN [A-Z ]+KEY-----[\s\S]*?-----END [A-Z ]+KEY-----', '[REDACTED_PRIVATE_KEY]', result)
    # Redact assignment patterns
    result = re.sub(
        r'(?i)\b(api[_-]?key|secret|password|token|access[_-]?token|auth)\b(\s*[:=]\s*["\'])[A-Za-z0-9_\-./+=]{8,}(["\'])',
        r'\1\2[REDACTED]\3',
        result
    )
    # Redact standard JWTs
    result = re.sub(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', '[REDACTED_JWT]', result)
    return result

def safe_extract_zip(data: bytes, destination: Path) -> int:
    """Extract zip archive safely; returns extracted file count."""
    count, _, _ = safe_extract_zip_with_metadata(data, destination)
    return count

def safe_extract_zip_with_metadata(data: bytes, destination: Path) -> Tuple[int, int, str]:
    """
    Safely validate and extract a ZIP archive.
    Enforces:
    - Max upload size
    - Max file count
    - Max uncompressed total and per-file size
    - Prevention of path traversal (Zip Slip, .., drive letters, absolute paths)
    - Rejection of symlinks, hardlinks, FIFOs and device files.
    Returns: (file_count, total_bytes, content_hash)
    """
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB limit.")
    
    content_hash = compute_sha256(data)
    destination.mkdir(parents=True, exist_ok=True)
    count = 0
    total_size = 0

    try:
        with zipfile.ZipFile(__import__("io").BytesIO(data)) as zf:
            members = zf.infolist()
            if len(members) > MAX_FILES:
                raise ValueError(f"Archive contains too many entries (max {MAX_FILES}).")
            
            for info in members:
                # Normalize slashes (handle Windows zip creations)
                name = info.filename.replace("\\", "/")
                # Strip leading slashes
                name = name.lstrip("/")
                pp = PurePosixPath(name)
                
                # Check for traversal indicators
                if pp.is_absolute() or ".." in pp.parts or (len(pp.parts) > 0 and ":" in pp.parts[0]):
                    raise ValueError(f"Unsafe archive path rejected: {info.filename}")
                
                # Verify Unix mode for symlinks / special files
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and (mode & 0o170000) not in (0, 0o100000, 0o040000):
                    raise ValueError(f"Unsupported or unsafe archive entry (symlink/device): {info.filename}")
                
                if info.file_size > MAX_SINGLE_FILE_BYTES:
                    raise ValueError(f"Archive file {name} exceeds per-file limit ({MAX_SINGLE_FILE_BYTES // (1024*1024)} MB).")
                
                total_size += info.file_size
                if total_size > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError(f"Archive expands beyond the {MAX_UNCOMPRESSED_BYTES // (1024*1024)} MB limit.")
                
                if info.is_dir() or name.endswith("/"):
                    continue
                
                target = (destination / Path(*pp.parts)).resolve()
                dest_resolved = destination.resolve()
                if dest_resolved not in target.parents and target != dest_resolved:
                    raise ValueError(f"Unsafe archive path rejected: {info.filename}")
                
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    bytes_written = 0
                    while True:
                        chunk = src.read(65536)
                        if not chunk:
                            break
                        bytes_written += len(chunk)
                        if bytes_written > MAX_SINGLE_FILE_BYTES:
                            raise ValueError(f"Archive entry {name} inflated beyond per-file limit.")
                        dst.write(chunk)
                count += 1

    except zipfile.BadZipFile as exc:
        raise ValueError("The uploaded file is not a valid ZIP archive.") from exc

    return count, total_size, content_hash

def should_ignore(path: Path) -> bool:
    """Ignore VCS, package caches, build outputs, and virtualenvs."""
    return any(part in IGNORED_DIRS for part in path.parts)

def is_source_file(path: Path) -> bool:
    """Check if file matches allowed source extensions and is not ignored."""
    return path.is_file() and path.suffix.lower() in ALLOWED_SOURCE_SUFFIXES and not should_ignore(path)
