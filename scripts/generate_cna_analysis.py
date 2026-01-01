#!/usr/bin/env python3
"""
Comprehensive CNA Analysis Generator (Wrapper)
Migrated to use the cvedb package.
"""

import sys
from pathlib import Path

# Add src to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

try:
    from cvedb.cna.v5_processor import CVEV5Processor
except ImportError:
    print("❌ Error: Could not import cvedb.cna.v5_processor")
    sys.exit(1)

def main():
    """Main entry point"""
    cache_dir = PROJECT_ROOT / 'data' / 'raw'
    data_output_dir = PROJECT_ROOT / 'dist' / 'data'
    
    # Ensure output exists
    data_output_dir.mkdir(parents=True, exist_ok=True)
    
    print("🏢 Generating comprehensive CNA analysis...")
    v5_processor = CVEV5Processor(PROJECT_ROOT, cache_dir, data_output_dir)
    
    try:
        # This generates both comprehensive and current year analysis
        v5_processor.generate_comprehensive_cna_analysis()
        v5_processor.generate_current_year_analysis()
        print("✅ CNA analysis complete.")
        return 0
    except Exception as e:
        print(f"❌ Error during CNA analysis: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
