#!/usr/bin/env python3
"""
CNA Mapping Restart Script
Maps every CVE to either an official or unofficial CNA using:
1. UUID/official CNA mapping (cna_name_map.json)
2. Reporting email/domain mapping (cna_list.json contact emails)
3. Fallback to edge-case/unknown (creates 'Unofficial CNA' if needed)

Refactored to use the new project structure.
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict

# Add src to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / 'src'))

def normalize_name(name):
    """Normalize CNA names for fuzzy matching"""
    if not name:
        return ''
    return (
        name.lower()
        .replace(',', '')
        .replace('.', '')
        .replace('incorporated', 'inc')
        .replace('corporation', 'corp')
        .replace('limited', 'ltd')
        .replace('llc', '')
        .replace('inc', '')
        .replace('corp', '')
        .replace('ltd', '')
        .replace('the ', '')
        .replace('&', 'and')
        .replace('  ', ' ')
        .strip()
    )

def extract_designation_year(cna_id):
    """Extract designation year from CNA ID (e.g., CNA-2005-0001)"""
    match = re.match(r"CNA-(\d{4})-", cna_id or "")
    return int(match.group(1)) if match else None

def main():
    cache_dir = PROJECT_ROOT / 'data' / 'raw'
    data_output_dir = PROJECT_ROOT / 'dist' / 'data'
    
    nvd_file = cache_dir / 'nvd.json'
    if not nvd_file.exists():
        print(f"❌ Error: {nvd_file} not found. Run full build first.")
        return 1
        
    print("🔄 Restarting CNA mapping...")
    
    # Load support files
    try:
        with open(cache_dir / 'cna_name_map.json', 'r') as f:
            uuid_map = json.load(f)
        with open(cache_dir / 'cna_list.json', 'r') as f:
            cna_list_raw = json.load(f)
            cna_list = cna_list_raw['data'] if isinstance(cna_list_raw, dict) and 'data' in cna_list_raw else cna_list_raw
    except FileNotFoundError as e:
        print(f"❌ Error: Required support file missing: {e}")
        return 1

    # Build official CNA lookup by UUID and normalized name
    uuid_to_name = {uuid: name for uuid, name in uuid_map.items()}
    official_names = {normalize_name(name): uuid for uuid, name in uuid_map.items()}
    
    # Build contact email and domain lookup from cna_list.json
    email_to_cna = {}
    domain_to_cna = {}
    cnaid_to_year = {}
    
    for cna in cna_list:
        org_name = cna.get('organizationName', '')
        cna_id = cna.get('cnaID', '')
        if cna_id:
            cnaid_to_year[org_name] = extract_designation_year(cna_id)
        
        # Contact emails
        for contact in cna.get('contact', []):
            for email in contact.get('email', []):
                email_addr = email.get('emailAddr', '').lower()
                if email_addr:
                    email_to_cna[email_addr] = org_name
                    domain = email_addr.split('@')[-1]
                    if domain:
                        domain_to_cna[domain] = org_name

    # Main mapping pass
    print("📊 Processing NVD data...")
    cna_stats = defaultdict(lambda: {
        'count': 0, 
        'first_cve_year': None, 
        'last_cve_year': None, 
        'designation_year': None, 
        'official': False, 
        'source': set()
    })
    
    with open(nvd_file, 'r') as f:
        # Check if it's a JSON array or line-delimited
        content = f.read(1)
        f.seek(0)
        if content == '[':
            cve_data = json.load(f)
        else:
            cve_data = [json.loads(line) for line in f if line.strip()]

    for cve_entry in cve_data:
        cve = cve_entry.get('cve', {}) if 'cve' in cve_entry else cve_entry
        
        # 1. Try UUID/official CNA mapping
        source_id = cve.get('sourceIdentifier', '')
        cna_name = uuid_to_name.get(source_id, '')
        
        if cna_name:
            mapped_name = cna_name
            official = True
            designation_year = cnaid_to_year.get(cna_name)
            source = 'uuid'
        else:
            # 2. Try reporting email(s)
            emails = set()
            assigner = cve.get('assigner', '')
            if assigner and '@' in assigner:
                emails.add(assigner.lower())
                
            for ref in cve.get('references', []):
                url = ref.get('url', '')
                if '@' in url:
                    emails.add(url.lower())
            
            mapped_name = ''
            official = False
            designation_year = None
            source = ''
            
            for email in emails:
                if email in email_to_cna:
                    mapped_name = email_to_cna[email]
                    official = normalize_name(mapped_name) in official_names
                    designation_year = cnaid_to_year.get(mapped_name)
                    source = 'email'
                    break
                
                domain = email.split('@')[-1]
                if domain in domain_to_cna:
                    mapped_name = domain_to_cna[domain]
                    official = normalize_name(mapped_name) in official_names
                    designation_year = cnaid_to_year.get(mapped_name)
                    source = 'domain'
                    break
            
            # 3. Fallback: fuzzy match on assigner
            if not mapped_name and assigner:
                normalized = normalize_name(assigner)
                if normalized in official_names:
                    mapped_name = uuid_to_name[official_names[normalized]]
                    official = True
                    designation_year = cnaid_to_year.get(mapped_name)
                    source = 'fuzzy-assigner'
            
            # 4. Edge: fallback to email
            if not mapped_name and emails:
                mapped_name = sorted(emails)[0]
                official = False
                source = 'unofficial-email'
                
            if not mapped_name:
                mapped_name = 'Unknown CNA'
                official = False
                source = 'unknown'

        # Update stats
        cna_stats[mapped_name]['count'] += 1
        pub_date = cve.get('published', '')
        year = int(pub_date[:4]) if pub_date and pub_date[:4].isdigit() else None
        
        if year:
            if not cna_stats[mapped_name]['first_cve_year'] or year < cna_stats[mapped_name]['first_cve_year']:
                cna_stats[mapped_name]['first_cve_year'] = year
            if not cna_stats[mapped_name]['last_cve_year'] or year > cna_stats[mapped_name]['last_cve_year']:
                cna_stats[mapped_name]['last_cve_year'] = year
        
        if designation_year:
            cna_stats[mapped_name]['designation_year'] = designation_year
        cna_stats[mapped_name]['official'] = official
        cna_stats[mapped_name]['source'].add(source)

    # Output summary
    summary = []
    current_year = 2026 # As per local time
    for name, stats in cna_stats.items():
        years_active = None
        if stats['designation_year']:
            years_active = current_year - stats['designation_year']
        
        summary.append({
            'name': name,
            'count': stats['count'],
            'official': stats['official'],
            'years_active': years_active,
            'first_cve_year': stats['first_cve_year'],
            'last_cve_year': stats['last_cve_year'],
            'sources': sorted(list(stats['source'])),
        })
    
    summary.sort(key=lambda x: x['count'], reverse=True)
    
    output_file = data_output_dir / 'cna_analysis_restart.json'
    with open(output_file, 'w') as f:
        json.dump(summary, f, indent=2)
        
    print(f"✅ CNA mapping complete. {len(summary)} CNAs found.")
    print(f"📁 Output: {output_file}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
