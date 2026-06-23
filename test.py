#!/usr/bin/env python3
"""
DNS Zone Records Extractor
Retrieves all DNS records for a given domain using multiple DNS record types
"""

import dns.resolver
import dns.zone
import dns.query
import sys
from typing import Dict, List, Optional

# Common DNS record types to query
RECORD_TYPES = [
    'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 
    'SRV', 'PTR', 'CAA', 'DS', 'DNSKEY', 'RRSIG', 'NSEC'
]

class DNSZoneExtractor:
    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        # Use Google DNS or system default
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        self.results = {}

    def get_records(self, record_type: str) -> Optional[List[str]]:
        """Get DNS records of a specific type for the domain"""
        try:
            answers = self.resolver.resolve(self.domain, record_type)
            records = []
            for answer in answers:
                records.append(str(answer))
            return records
        except dns.resolver.NXDOMAIN:
            print(f"Domain {self.domain} does not exist")
            return None
        except dns.resolver.NoAnswer:
            return []  # No records of this type
        except dns.resolver.Timeout:
            print(f"Timeout while querying {record_type} records")
            return None
        except Exception as e:
            print(f"Error querying {record_type}: {str(e)}")
            return None

    def get_zone_transfer(self) -> Optional[Dict]:
        """Attempt a zone transfer (AXFR)"""
        try:
            # First get NS records to find authoritative nameservers
            ns_records = self.get_records('NS')
            if not ns_records:
                return None
            
            # Try zone transfer with each nameserver
            for ns in ns_records:
                try:
                    # Remove trailing dot if present
                    ns = ns.rstrip('.')
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain))
                    records = {}
                    for name, node in zone.nodes.items():
                        name_str = str(name)
                        if name_str == '@':
                            name_str = self.domain
                        elif not name_str.endswith(self.domain):
                            name_str = f"{name_str}.{self.domain}"
                        
                        for rdtype in zone.get_rdtypes(name, 'A'):
                            records.setdefault(name_str, {})
                            records[name_str]['A'] = [str(r) for r in zone.get_rrset(name, 'A')]
                        for rdtype in zone.get_rdtypes(name, 'MX'):
                            records.setdefault(name_str, {})
                            records[name_str]['MX'] = [str(r) for r in zone.get_rrset(name, 'MX')]
                        for rdtype in zone.get_rdtypes(name, 'CNAME'):
                            records.setdefault(name_str, {})
                            records[name_str]['CNAME'] = [str(r) for r in zone.get_rrset(name, 'CNAME')]
                        # Add more types as needed
                    
                    if records:
                        return records
                except Exception:
                    continue
            return None
        except Exception as e:
            print(f"Zone transfer failed: {str(e)}")
            return None

    def extract_all_records(self, use_zone_transfer: bool = True) -> Dict:
        """Extract all DNS records for the domain"""
        print(f"\n{'='*60}")
        print(f"DNS Records for: {self.domain}")
        print(f"{'='*60}\n")

        # Try zone transfer first if requested
        if use_zone_transfer:
            print("Attempting zone transfer (AXFR)...")
            zone_data = self.get_zone_transfer()
            if zone_data:
                print("✓ Zone transfer successful!\n")
                return zone_data
            else:
                print("✗ Zone transfer failed or not allowed\n")
                print("Falling back to individual record queries...\n")

        # Fallback: Query each record type individually
        results = {}
        for record_type in RECORD_TYPES:
            records = self.get_records(record_type)
            if records is not None:
                if records:  # Only add if there are records
                    results[record_type] = records
                    print(f"{record_type} records found: {len(records)}")
                    for record in records:
                        print(f"  → {record}")
                else:
                    print(f"{record_type}: No records found")
        
        return results

    def print_results(self, results: Dict):
        """Pretty print the DNS records"""
        if not results:
            print("\nNo DNS records found!")
            return

        print(f"\n{'='*60}")
        print(f"SUMMARY: DNS Records for {self.domain}")
        print(f"{'='*60}")

        # Check if results are from zone transfer (nested structure)
        if any(isinstance(v, dict) for v in results.values()):
            for name, record_types in results.items():
                print(f"\n📌 {name}")
                for rtype, records in record_types.items():
                    print(f"  {rtype}:")
                    for record in records:
                        print(f"    → {record}")
        else:
            # Regular query results
            for record_type, records in results.items():
                print(f"\n📌 {record_type} Records:")
                for record in records:
                    print(f"  → {record}")

    def save_to_file(self, filename: str = None):
        """Save results to a file"""
        if not filename:
            filename = f"{self.domain}_dns_records.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"DNS Records for {self.domain}\n")
                f.write("="*60 + "\n\n")
                
                for record_type, records in self.results.items():
                    f.write(f"{record_type} Records:\n")
                    for record in records:
                        f.write(f"  {record}\n")
                    f.write("\n")
            
            print(f"\n✓ Results saved to: {filename}")
        except Exception as e:
            print(f"✗ Error saving to file: {str(e)}")

def main():
    """Main function to run the DNS zone extractor"""
    print("DNS Zone Records Extractor")
    print("="*60)
    
    # Get domain from command line or user input
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain name (e.g., example.com): ").strip()
    
    if not domain:
        print("Error: Domain name cannot be empty")
        sys.exit(1)
    
    # Remove trailing dot if present
    domain = domain.rstrip('.')
    
    # Create extractor instance
    extractor = DNSZoneExtractor(domain)
    
    # Extract all records
    results = extractor.extract_all_records(use_zone_transfer=True)
    
    # Print results
    extractor.print_results(results)
    
    # Ask if user wants to save results
    save = input("\nSave results to file? (y/n): ").strip().lower()
    if save == 'y':
        extractor.save_to_file()
    
    # Ask if user wants to try zone transfer explicitly
    if not results:
        retry = input("\nTry zone transfer only? (y/n): ").strip().lower()
        if retry == 'y':
            print("\nAttempting zone transfer...")
            zone_data = extractor.get_zone_transfer()
            if zone_data:
                print("✓ Zone transfer successful!")
                extractor.print_results(zone_data)
            else:
                print("✗ Zone transfer failed")

if __name__ == "__main__":
    # Install required package:
    # pip install dnspython
    
    try:
        import dns.resolver
        import dns.zone
        import dns.query
    except ImportError:
        print("Error: dnspython package is required.")
        print("Install it using: pip install dnspython")
        sys.exit(1)
    
    main()