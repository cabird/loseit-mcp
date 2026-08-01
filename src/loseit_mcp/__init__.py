"""MCP server for the Lose It! food diary."""

from __future__ import annotations

import os

__version__ = "0.5.1"


def build_info() -> dict[str, str]:
    """Identify the running build.

    ``LOSEIT_BUILD_*`` are stamped in at image build time. They are absent for a
    source checkout, which is itself useful information -- it distinguishes
    "running from source" from "running a built image".
    """
    return {
        "version": __version__,
        "commit": os.environ.get("LOSEIT_BUILD_COMMIT", "unknown"),
        "built_at": os.environ.get("LOSEIT_BUILD_TIME", "unknown"),
        "image_tag": os.environ.get("LOSEIT_BUILD_TAG", "source"),
    }


__all__ = ["__version__", "build_info"]


