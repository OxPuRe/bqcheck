"""Security utilities for license management."""


def mask_key(key: str) -> str:
    """
    Mask master license key for safe display.

    Shows only first 2 segments, masks the rest with ***.

    Examples:
        ABC-XYZ-123-DEF-456 → ABC-XYZ-***
        SHORT → ***

    Args:
        key: Master license key to mask

    Returns:
        str: Masked key showing only first 2 segments

    Security:
        - FR61: Master keys never appear in full in logs/output
        - Only first 2 segments visible
    """
    parts = key.split("-")
    if len(parts) < 3:
        return "***"
    return f"{parts[0]}-{parts[1]}-***"
