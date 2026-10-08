"""Allow ``python -m systemd_hardening_kit``."""

import sys

from .cli import main

sys.exit(main())
