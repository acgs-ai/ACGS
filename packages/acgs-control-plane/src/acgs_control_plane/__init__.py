"""ACGS Enterprise Governance Control Plane.

Multi-tenant management API over the gove-zone governed runtime.
Invariant: no valid Decision Receipt, no side effect — including for the
control plane's own mutations.
"""

from acgs_control_plane.app import create_app
from acgs_control_plane.config import Settings

__version__ = "0.1.0"

__all__ = ["Settings", "__version__", "create_app"]
