"""Basic, non-executing validation for APK files."""

from dataclasses import dataclass
from pathlib import Path
import zipfile


class APKValidationError(ValueError):
    """Raised when a selected file does not pass basic APK checks."""


@dataclass(frozen=True)
class APKFileInfo:
    """Safe file details collected during the initial validation step."""

    path: Path
    name: str
    size_bytes: int


def validate_apk_file(file_path: Path | None) -> APKFileInfo:
    """Check that a file looks like an APK without installing or running it.

    An APK is a ZIP archive and normally contains ``AndroidManifest.xml``.
    Successful validation does not mean the APK is safe or fully parseable.
    """
    if file_path is None:
        raise APKValidationError("Please choose an APK file first.")
    if not file_path.is_file():
        raise APKValidationError("The selected file no longer exists or is not a file.")
    if file_path.suffix.lower() != ".apk":
        raise APKValidationError("Please select a file with the .apk extension.")

    try:
        file_size = file_path.stat().st_size
    except OSError as error:
        raise APKValidationError("The selected file could not be accessed.") from error

    if file_size == 0:
        raise APKValidationError("The selected APK file is empty.")
    if not zipfile.is_zipfile(file_path):
        raise APKValidationError("The file is not a valid ZIP-based APK archive.")

    try:
        with zipfile.ZipFile(file_path) as apk_archive:
            archive_names = apk_archive.namelist()
    except (OSError, zipfile.BadZipFile) as error:
        raise APKValidationError("The APK archive appears to be corrupted.") from error

    if "AndroidManifest.xml" not in archive_names:
        raise APKValidationError("The archive does not contain AndroidManifest.xml.")

    return APKFileInfo(path=file_path, name=file_path.name, size_bytes=file_size)
