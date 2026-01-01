#!/usr/bin/env python3
"""
CNA Analysis Rebuild Script
Quick rebuild script for CNA analysis only - much faster than full site rebuild
"""

import sys
import os
from pathlib import Path

# Add src to path if not installed
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

try:
    from cvedb.cna.v5_processor import CVEV5Processor
except ImportError:
    print("❌ Error: Could not import cvedb.cna.v5_processor")
    print("Please run 'make install' or ensuring src/ is in PYTHONPATH")
    sys.exit(1)

def main():
    """Rebuild CNA analysis only"""
    print("🏢 CNA Analysis Quick Rebuild")
    print("=" * 40)
    
    # Set up paths
    cache_dir = PROJECT_ROOT / 'data' / 'raw'
    data_output_dir = PROJECT_ROOT / 'dist' / 'data'
    
    # Ensure output exists
    data_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Initialize CVE V5 processor
    v5_processor = CVEV5Processor(PROJECT_ROOT, cache_dir, data_output_dir)
    
    try:
        # Generate comprehensive CNA analysis using CVE V5 data
        print("\n🔄 Generating comprehensive CNA analysis (CVE V5 authoritative)...")
        cna_analysis = v5_processor.generate_comprehensive_cna_analysis()
        
        # Generate current year CNA analysis
        print(f"\n🗓️  Generating current year CNA analysis...")
        current_cna_analysis = v5_processor.generate_current_year_analysis()
        
        print("\n" + "=" * 40)
        print("✅ CNA analysis rebuild completed!")
        print(f"📁 Files updated in: {data_output_dir}")
        return True
        
    except Exception as e:
        print(f"\n❌ CNA analysis rebuild failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
