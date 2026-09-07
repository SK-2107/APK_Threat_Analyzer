"""File hashing utilities.

SHA-256 identifies a particular APK file without executing it. A hash changes
when the file changes, so it is useful for comparing and storing analyses.
"""

from pathlib import Path
import hashlib


def calculate_sha256(file_path: Path, chunk_size: int = 65_536) -> str:
    """Return the SHA-256 hexadecimal digest for *file_path*.

    The file is read in chunks to avoid loading an entire APK into memory.
    """
    sha256 = hashlib.sha256()
    with file_path.open("rb") as file_handle:
        while chunk := file_handle.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()
