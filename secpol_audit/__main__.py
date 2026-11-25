"""Module entrypoint for `python3 -m secpol_audit`."""

import sys

from secpol_audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
