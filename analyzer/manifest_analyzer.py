"""Helpers for extracting Android manifest details from a parsed APK."""

from dataclasses import dataclass

from androguard.core.apk import APK


@dataclass(frozen=True)
class ManifestDetails:
    """Permissions and Android components declared by the APK manifest."""

    permissions: list[str]
    activities: list[str]
    services: list[str]
    receivers: list[str]
    providers: list[str]


def extract_manifest_details(apk: APK) -> ManifestDetails:
    """Return manifest lists, replacing missing values with empty lists."""
    return ManifestDetails(
        permissions=list(apk.get_permissions() or []),
        activities=list(apk.get_activities() or []),
        services=list(apk.get_services() or []),
        receivers=list(apk.get_receivers() or []),
        providers=list(apk.get_providers() or []),
    )
