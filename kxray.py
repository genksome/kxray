#!/usr/bin/env python3
import sys
from kxray.cli import run

if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print()
        sys.exit(0)