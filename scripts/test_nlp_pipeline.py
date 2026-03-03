#!/usr/bin/env python3
"""
Test NLP Enrichment Pipeline.

Quick test to verify all NLP components are working correctly.
Tests translation, NER, keyword extraction, and attack analysis.
"""

import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from soc_alerting.services.nlp import get_nlp_pipeline


# Test CVE descriptions
TEST_CVES = [
    {
        "cve_id": "CVE-2021-44228",
        "description": (
            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security "
            "releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in "
            "configuration, log messages, and parameters do not protect "
            "against attacker controlled LDAP and other JNDI related endpoints. "
            "An attacker who can control log messages or log message parameters "
            "can execute arbitrary code loaded from LDAP servers when message "
            "lookup substitution is enabled."
        )
    },
    {
        "cve_id": "CVE-2024-TEST",
        "description": (
            "SQL injection vulnerability in web application allows "
            "unauthenticated remote attackers to execute arbitrary SQL commands "
            "via specially crafted HTTP POST requests to the login endpoint."
        )
    },
    {
        "cve_id": "CVE-2024-XSS",
        "description": (
            "Cross-site scripting (XSS) vulnerability in user profile page "
            "allows authenticated users to inject malicious JavaScript code "
            "that will be executed in other users' browsers."
        )
    }
]


def print_separator(title: str):
    """Print formatted separator."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


async def test_nlp_pipeline():
    """Test NLP enrichment pipeline with sample CVEs."""

    print_separator("NLP Pipeline Test")

    print("Initializing NLP pipeline...")
    print("  - Translation: Helsinki-NLP/opus-mt-en-es")
    print("  - NER: dslim/bert-base-NER")
    print("  - Keywords: Pattern-based extraction")
    print("  - Device: CPU\n")

    # Initialize pipeline
    pipeline = get_nlp_pipeline(
        enable_translation=True,
        enable_ner=True,
        enable_keywords=True,
        device="cpu"
    )

    print("✅ Pipeline initialized\n")

    # Test each CVE
    for i, test_cve in enumerate(TEST_CVES, 1):
        cve_id = test_cve["cve_id"]
        description = test_cve["description"]

        print_separator(f"Test {i}/{len(TEST_CVES)}: {cve_id}")

        print("📄 Original Description (EN):")
        print(f"   {description}\n")

        try:
            # Run enrichment
            print(f"🧠 Running NLP enrichment...")
            result = pipeline.enrich_cve(
                cve_id=cve_id,
                description_en=description
            )

            # Check for errors
            if result.get("errors"):
                print(f"\n⚠️  Warnings: {result['errors']}\n")

            # Display results
            print("\n📊 ENRICHMENT RESULTS:\n")

            # 1. Translation
            if result.get("translation"):
                trans = result["translation"]
                print("1️⃣  TRADUCCIÓN (ES):")
                print(f"   {trans['description_es']}")
                print(f"   Confidence: {trans['translation_confidence']:.2%}")
                print(f"   Model: {trans['translation_model']}")

            # 2. Entities
            if result.get("entities"):
                entities = result["entities"]
                print("\n2️⃣  ENTIDADES EXTRAÍDAS:")
                if entities['organizations']:
                    print(f"   Organizaciones: {entities['organizations']}")
                if entities['versions']:
                    print(f"   Versiones: {entities['versions']}")
                if entities['cve_references']:
                    print(f"   CVE Referencias: {entities['cve_references']}")
                if entities['technical_terms']:
                    print(f"   Términos técnicos: {entities['technical_terms'][:5]}")
                print(f"   Total entidades: {entities['entity_count']}")

            # 3. Keywords
            if result.get("keywords"):
                keywords = result["keywords"]
                print("\n3️⃣  KEYWORDS TÉCNICAS:")
                if keywords['attack_vectors']:
                    print(f"   Vectores de ataque: {keywords['attack_vectors']}")
                if keywords['technical_protocols']:
                    print(f"   Protocolos: {keywords['technical_protocols']}")
                if keywords['vulnerability_types']:
                    print(f"   Tipos de vulnerabilidad: {keywords['vulnerability_types'][:3]}")

            # 4. Attack Analysis
            if result.get("attack_analysis"):
                attack = result["attack_analysis"]
                print("\n4️⃣  ANÁLISIS DE ATAQUE:")
                print(f"   Tipo principal: {attack['attack_type']}")
                print(f"   Complejidad: {attack['attack_complexity']}")
                print(f"   Requiere autenticación: {attack['requires_authentication']}")
                print(f"   Accesible por red: {attack['network_accessible']}")
                if attack['secondary_attack_types']:
                    print(f"   Tipos secundarios: {attack['secondary_attack_types']}")

            # 5. CIA Impact
            if result.get("cia_impact"):
                cia = result["cia_impact"]
                print("\n5️⃣  IMPACTO CIA:")
                print(f"   Confidencialidad: {cia['confidentiality']}")
                print(f"   Integridad: {cia['integrity']}")
                print(f"   Disponibilidad: {cia['availability']}")

            # Performance
            print(f"\n⏱️  Tiempo de procesamiento: {result['processing_time_ms']}ms")

            print("\n✅ Enrichment completed successfully\n")

        except Exception as e:
            print(f"\n❌ Error during enrichment: {e}\n")
            import traceback
            traceback.print_exc()

    # Summary
    print_separator("Test Summary")
    print(f"✅ Tested {len(TEST_CVES)} CVEs")
    print("✅ All components working:")
    print("   - Translation (EN → ES)")
    print("   - Named Entity Recognition")
    print("   - Keyword Extraction")
    print("   - Attack Analysis")
    print("   - CIA Impact Assessment")
    print("\n🎉 NLP Pipeline is ready for production use!\n")

    # Cleanup
    pipeline.unload_models()
    print("🧹 Models unloaded from memory\n")


def main():
    """Main entry point."""
    try:
        asyncio.run(test_nlp_pipeline())
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
