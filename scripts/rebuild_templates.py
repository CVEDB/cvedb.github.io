#!/usr/bin/env python3
"""
Quick template rebuild script - regenerates HTML pages without reprocessing data
Refactored to use quick_build.py logic
"""

import sys
from pathlib import Path

# Add scripts to path to import CVEQuickBuilder
SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

try:
    from quick_build import CVEQuickBuilder
except ImportError:
    print("❌ Error: Could not import CVEQuickBuilder from quick_build.py")
    sys.exit(1)

def main():
    """Run the quick builder"""
    builder = CVEQuickBuilder()
    builder.build()

if __name__ == "__main__":
    main()
