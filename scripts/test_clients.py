#!/usr/bin/env python3
"""
Test script for NIST and CISA API clients.

Usage:
    python scripts/test_clients.py
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from soc_alerting.clients.nist_client import NISTClient
from soc_alerting.clients.cisa_client import CISAClient
from soc_alerting.config.logging_config import setup_logging


async def test_nist_client():
    """Test NIST NVD API client."""
    print("\n" + "=" * 80)
    print("Testing NIST NVD Client")
    print("=" * 80)

    async with NISTClient() as nist:
        # Test 1: Fetch recent CVEs (last 24 hours)
        print("\n[Test 1] Fetching CVEs from last 24 hours...")
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(hours=24)

        try:
            cves = await nist.fetch_cves_by_modified_date(
                start_date=start_date,
                end_date=end_date,
                max_results=5,  # Limit to 5 for testing
            )

            print(f"✓ Fetched {len(cves)} CVEs")

            for cve in cves[:3]:  # Show first 3
                print(f"\n  CVE ID: {cve.id}")
                print(f"  Published: {cve.published}")
                print(f"  Modified: {cve.lastModified}")
                print(f"  Description: {cve.get_english_description()[:100]}...")
                print(f"  CVSS v3: {cve.get_primary_cvss_v3()}")

                # Convert to domain model
                domain_cve = nist.convert_to_domain_model(cve)
                print(f"  NIST Severity: {domain_cve.severity_nist}")
                print(f"  Final Severity: {domain_cve.final_severity}")

        except Exception as e:
            print(f"✗ Error: {e}")
            raise

        # Test 2: Fetch specific CVE
        print("\n[Test 2] Fetching specific CVE: CVE-2024-21762")
        try:
            cve = await nist.fetch_cve_by_id("CVE-2024-21762")
            if cve:
                print(f"✓ Found: {cve.id}")
                print(f"  Description: {cve.get_english_description()[:150]}...")
                print(f"  CVSS: {cve.get_primary_cvss_v3()}")
            else:
                print("✗ CVE not found")
        except Exception as e:
            print(f"✗ Error: {e}")


async def test_cisa_client():
    """Test CISA KEV client."""
    print("\n" + "=" * 80)
    print("Testing CISA KEV Client")
    print("=" * 80)

    async with CISAClient() as cisa:
        # Test 1: Fetch KEV catalog
        print("\n[Test 1] Fetching CISA KEV catalog...")
        try:
            catalog = await cisa.fetch_kev_catalog()
            print(f"✓ Fetched KEV catalog")
            print(f"  Version: {catalog.catalogVersion}")
            print(f"  Released: {catalog.dateReleased}")
            print(f"  Total vulnerabilities: {len(catalog.vulnerabilities)}")

            # Show a few examples
            print("\n  First 3 KEV entries:")
            for vuln in catalog.vulnerabilities[:3]:
                print(f"\n    {vuln.cveID}")
                print(f"    Vendor: {vuln.vendorProject}")
                print(f"    Product: {vuln.product}")
                print(f"    Added: {vuln.dateAdded}")
                print(f"    Action: {vuln.requiredAction[:60]}...")

        except Exception as e:
            print(f"✗ Error: {e}")
            raise

        # Test 2: Check if CVEs are in KEV
        print("\n[Test 2] Checking if CVEs are in KEV...")
        test_cves = [
            "CVE-2024-21762",  # Likely in KEV (Fortinet)
            "CVE-2021-44228",  # Definitely in KEV (Log4j)
            "CVE-9999-99999",  # Fake CVE (not in KEV)
        ]

        for cve_id in test_cves:
            in_kev = await cisa.is_cve_in_kev(cve_id)
            status = "✓ IN KEV" if in_kev else "✗ NOT in KEV"
            print(f"  {cve_id}: {status}")

            if in_kev:
                kev_entry = await cisa.get_kev_entry(cve_id)
                if kev_entry:
                    print(f"    Added: {kev_entry.dateAdded}")
                    print(f"    Due: {kev_entry.dueDate}")
                    print(f"    Action: {kev_entry.requiredAction[:60]}...")

        # Test 3: Get statistics
        print("\n[Test 3] KEV statistics...")
        stats = await cisa.get_kev_statistics()
        print(f"  Total KEV entries: {stats['total_vulnerabilities']}")
        print(f"  Unique vendors: {stats['unique_vendors']}")
        print(f"  Unique products: {stats['unique_products']}")


async def test_integration():
    """Test NIST + CISA integration."""
    print("\n" + "=" * 80)
    print("Testing NIST + CISA Integration")
    print("=" * 80)

    async with NISTClient() as nist, CISAClient() as cisa:
        # Fetch a known KEV CVE from NIST
        print("\n[Test] Fetching CVE-2021-44228 (Log4Shell) from NIST...")

        try:
            nist_cve = await nist.fetch_cve_by_id("CVE-2021-44228")

            if nist_cve:
                print(f"✓ Found in NIST: {nist_cve.id}")
                print(f"  CVSS: {nist_cve.get_primary_cvss_v3()}")

                # Convert to domain model
                domain_cve = nist.convert_to_domain_model(nist_cve)
                print(f"  NIST Severity: {domain_cve.severity_nist}")
                print(f"  Before KEV check: final_severity = {domain_cve.final_severity}")

                # Enrich with CISA KEV data
                domain_cve = await cisa.enrich_cve_with_kev_data(domain_cve)
                print(f"  In CISA KEV: {domain_cve.is_in_cisa_kev}")
                print(f"  After KEV check: final_severity = {domain_cve.final_severity}")

                if domain_cve.is_in_cisa_kev:
                    print(f"  CISA Added: {domain_cve.cisa_exploit_add}")
                    print(f"  CISA Action: {domain_cve.cisa_required_action}")

        except Exception as e:
            print(f"✗ Error: {e}")
            raise


async def main():
    """Run all tests."""
    # Setup logging
    setup_logging(level="INFO", json_format=False)

    print("\n" + "=" * 80)
    print("SOC Alerting System - API Client Tests")
    print("=" * 80)

    try:
        # Test individual clients
        await test_nist_client()
        await test_cisa_client()

        # Test integration
        await test_integration()

        print("\n" + "=" * 80)
        print("✓ All tests completed successfully!")
        print("=" * 80)

    except Exception as e:
        print("\n" + "=" * 80)
        print(f"✗ Tests failed: {e}")
        print("=" * 80)
        raise


if __name__ == "__main__":
    asyncio.run(main())
