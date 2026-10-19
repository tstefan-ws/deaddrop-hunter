"""Entry point for the deaddrop-hunter OpenCTI connector."""

import sys
import traceback

from connector import DeaddropHunterConnector

if __name__ == "__main__":
    try:
        DeaddropHunterConnector().run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
