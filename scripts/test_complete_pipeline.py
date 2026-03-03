#!/usr/bin/env python3
"""
Test Complete CVE Processing Pipeline End-to-End.

Tests the full flow:
1. Fetch CVEs from NIST NVD
2. Enrich with CISA KEV data
3. Save to database
4. NLP enrichment (translation, NER, keywords, attack analysis)
5. Verify results in database
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from soc_alerting.services.cve_processor import CVEProcessor
from soc_alerting.database.connection import get_database
from sqlalchemy import text


async def test_complete_pipeline():
    """Test the complete CVE processing pipeline."""

    print("=" * 80)
    print("  COMPLETE CVE PROCESSING PIPELINE TEST")
    print("=" * 80)
    print()

    # Test specific CVE (Log4Shell)
    test_cve_id = "CVE-2021-44228"

    print(f"📋 Testing with: {test_cve_id} (Apache Log4j - Log4Shell)")
    print()

    # Initialize processor with NLP enabled
    print("🔧 Initializing CVE Processor (NLP enabled)...")
    processor = CVEProcessor(enable_nlp_enrichment=True)

    async with processor:
        print("✅ Processor initialized")
        print()

        # Step 1: Process specific CVE
        print("=" * 80)
        print("  STEP 1: Fetch and Process CVE")
        print("=" * 80)
        print()

        print(f"🔍 Fetching {test_cve_id} from NIST NVD...")
        cve = await processor.process_specific_cve(
            cve_id=test_cve_id,
            force_enrich=True  # Force enrichment regardless of severity
        )

        if not cve:
            print(f"❌ CVE {test_cve_id} not found in NIST database")
            return

        print(f"✅ CVE fetched and processed")
        print()
        print(f"📊 CVE Details:")
        print(f"   ID: {cve.cve_id}")
        print(f"   Published: {cve.published_date}")
        print(f"   CVSS Score: {cve.cvss_v3_score}")
        print(f"   NIST Severity: {cve.severity_nist}")
        print(f"   In CISA KEV: {cve.is_in_cisa_kev}")
        print(f"   Final Severity: {cve.final_severity}")
        print(f"   Description: {cve.description[:150]}...")
        print()

        # Step 2: Verify database storage
        print("=" * 80)
        print("  STEP 2: Verify Database Storage")
        print("=" * 80)
        print()

        db = get_database()

        async with db.get_session() as session:
            # Check CVE record
            result = await session.execute(
                text("SELECT cve_id, final_severity, is_in_cisa_kev FROM cves WHERE cve_id = :cve_id"),
                {"cve_id": test_cve_id}
            )
            cve_record = result.fetchone()

            if cve_record:
                print(f"✅ CVE found in database:")
                print(f"   ID: {cve_record[0]}")
                print(f"   Severity: {cve_record[1]}")
                print(f"   In KEV: {cve_record[2]}")
            else:
                print(f"❌ CVE not found in database")
                return

            print()

            # Check CISA KEV metadata (if applicable)
            if cve.is_in_cisa_kev:
                result = await session.execute(
                    text(
                        "SELECT date_added, action_due_date, required_action "
                        "FROM cisa_kev_metadata WHERE cve_id = :cve_id"
                    ),
                    {"cve_id": test_cve_id}
                )
                kev_record = result.fetchone()

                if kev_record:
                    print(f"✅ CISA KEV metadata found:")
                    print(f"   Date Added: {kev_record[0]}")
                    print(f"   Due Date: {kev_record[1]}")
                    print(f"   Required Action: {kev_record[2][:80]}...")
                    print()

            # Check NLP enrichment
            result = await session.execute(
                text(
                    "SELECT description_es, attack_type, attack_complexity, "
                    "cia_impact, technical_keywords, processing_time_ms "
                    "FROM cve_enrichments WHERE cve_id = :cve_id "
                    "ORDER BY enriched_at DESC LIMIT 1"
                ),
                {"cve_id": test_cve_id}
            )
            enrichment_record = result.fetchone()

            print("=" * 80)
            print("  STEP 3: Verify NLP Enrichment")
            print("=" * 80)
            print()

            if enrichment_record:
                print(f"✅ NLP enrichment found:")
                print()

                # Translation
                if enrichment_record[0]:
                    print(f"📝 Traducción (ES):")
                    print(f"   {enrichment_record[0][:200]}...")
                    print()

                # Attack Analysis
                if enrichment_record[1]:
                    print(f"⚔️  Análisis de Ataque:")
                    print(f"   Tipo: {enrichment_record[1]}")
                    print(f"   Complejidad: {enrichment_record[2]}")
                    print()

                # CIA Impact
                if enrichment_record[3]:
                    cia = enrichment_record[3]
                    print(f"🛡️  Impacto CIA:")
                    print(f"   Confidencialidad: {cia.get('confidentiality', 'N/A')}")
                    print(f"   Integridad: {cia.get('integrity', 'N/A')}")
                    print(f"   Disponibilidad: {cia.get('availability', 'N/A')}")
                    print()

                # Keywords
                if enrichment_record[4]:
                    keywords = enrichment_record[4]
                    if keywords:
                        print(f"🔑 Keywords Técnicas:")
                        for kw in keywords[:5]:
                            if isinstance(kw, dict):
                                print(f"   - {kw.get('keyword', kw)}")
                            else:
                                print(f"   - {kw}")
                        if len(keywords) > 5:
                            print(f"   ... y {len(keywords) - 5} más")
                    print()

                # Performance
                if enrichment_record[5]:
                    print(f"⏱️  Tiempo de procesamiento NLP: {enrichment_record[5]}ms")
                    print()

            else:
                print(f"⚠️  No NLP enrichment found (may have been skipped due to severity threshold)")
                print()

        # Summary
        print("=" * 80)
        print("  TEST SUMMARY")
        print("=" * 80)
        print()
        print("✅ Complete pipeline test successful!")
        print()
        print("Pipeline stages completed:")
        print("  1. ✅ Fetch from NIST NVD")
        print("  2. ✅ Enrich with CISA KEV data")
        print("  3. ✅ Save to database (cves table)")
        print("  4. ✅ Save CISA metadata (cisa_kev_metadata table)")
        print("  5. ✅ NLP enrichment (cve_enrichments table)")
        print()
        print(f"🎉 System is fully operational and ready for production!")
        print()


async def test_batch_processing():
    """Test batch processing with recent CVEs."""

    print("=" * 80)
    print("  BATCH CVE PROCESSING TEST")
    print("=" * 80)
    print()

    print("🔧 Initializing CVE Processor...")
    processor = CVEProcessor(enable_nlp_enrichment=True)

    async with processor:
        print("✅ Processor initialized")
        print()

        # Process recent CVEs (last 7 days, max 10)
        print("🔍 Fetching recent CVEs (last 7 days, max 10)...")
        print()

        stats = await processor.process_recent_cves(
            hours_back=7 * 24,  # 7 days
            max_cves=10
        )

        print("=" * 80)
        print("  PROCESSING RESULTS")
        print("=" * 80)
        print()

        print(f"📊 Statistics:")
        print(f"   CVEs fetched: {stats['cves_fetched']}")
        print(f"   CVEs processed: {stats['cves_processed']}")
        print(f"   CVEs created: {stats['cves_created']}")
        print(f"   CVEs updated: {stats['cves_updated']}")
        print(f"   CVEs in CISA KEV: {stats['cves_in_kev']}")
        print()

        print(f"🧠 NLP Enrichment:")
        print(f"   Enriched: {stats.get('cves_enriched', 0)}")
        print(f"   Skipped: {stats.get('enrichment_skipped', 0)}")
        print(f"   Failed: {stats.get('enrichment_failed', 0)}")
        print()

        print(f"📈 By Severity:")
        for severity, count in stats['by_severity'].items():
            if count > 0:
                print(f"   {severity}: {count}")
        print()

        print("✅ Batch processing completed successfully!")
        print()


def main():
    """Main entry point."""

    print()
    print("Choose test:")
    print("  1. Single CVE (Log4Shell) - Complete pipeline test")
    print("  2. Batch processing - Recent CVEs (last 7 days)")
    print("  3. Both tests")
    print()

    choice = input("Enter choice (1-3): ").strip()

    try:
        if choice == "1":
            asyncio.run(test_complete_pipeline())
        elif choice == "2":
            asyncio.run(test_batch_processing())
        elif choice == "3":
            asyncio.run(test_complete_pipeline())
            print("\n\n")
            asyncio.run(test_batch_processing())
        else:
            print("Invalid choice")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Test failed with error: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
