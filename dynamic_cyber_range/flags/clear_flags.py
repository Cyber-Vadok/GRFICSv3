#!/usr/bin/env python3
"""Remove planted flag tokens from the GRFICSv3 containers (thin wrapper)."""
import sys
import plant_flags

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--clear", *sys.argv[1:]]
    plant_flags.main()
