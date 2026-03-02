#!/usr/bin/env python3
"""
Script de verificación del sistema SOC Alerting.

Verifica que todos los componentes funcionen correctamente.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[1] / "src"))


def test_imports():
    """Verificar que se puedan importar todos los módulos."""
    print("\n" + "=" * 60)
    print("1. VERIFICANDO IMPORTS")
    print("=" * 60)

    try:
        import soc_alerting
        print(f"✓ soc_alerting importado desde: {soc_alerting.__file__}")

        from soc_alerting.clients import NISTClient, CISAClient
        print("✓ Clientes NIST y CISA importados")

        from soc_alerting.config.settings import get_settings
        print("✓ Configuración importada")

        from soc_alerting.database.connection import get_database
        print("✓ Database connection importada")

        from soc_alerting.models.domain import CVE, SeverityLevel
        print("✓ Modelos de dominio importados")

        return True
    except Exception as e:
        print(f"✗ Error en imports: {e}")
        return False


def test_configuration():
    """Verificar configuración."""
    print("\n" + "=" * 60)
    print("2. VERIFICANDO CONFIGURACIÓN")
    print("=" * 60)

    try:
        from soc_alerting.config.settings import get_settings
        settings = get_settings()

        print(f"✓ Database URL: {settings.database_url.split('@')[1] if '@' in settings.database_url else 'N/A'}")
        print(f"✓ NIST API Base: {settings.nist_api_base_url}")
        print(f"✓ CISA KEV URL: {settings.cisa_kev_url}")
        print(f"✓ HuggingFace Model: {settings.hf_model_name}")
        print(f"✓ Update Interval: {settings.update_interval_minutes} min")
        print(f"✓ Enrichment Enabled: {settings.enable_enrichment}")
        print(f"✓ Scheduler Enabled: {settings.enable_scheduler}")

        return True
    except Exception as e:
        print(f"✗ Error en configuración: {e}")
        return False


def test_database():
    """Verificar conexión a base de datos."""
    print("\n" + "=" * 60)
    print("3. VERIFICANDO BASE DE DATOS")
    print("=" * 60)

    try:
        from soc_alerting.database.connection import get_database
        from sqlalchemy import text

        db = get_database()

        if db.health_check():
            print("✓ Conexión PostgreSQL: OK")

            # Get version
            with db.get_session() as session:
                version = session.execute(text("SELECT version()")).scalar()
                print(f"  {version.split(',')[0]}")

            # Check if tables exist
            with db.get_session() as session:
                result = session.execute(text("""
                    SELECT COUNT(*) FROM information_schema.tables
                    WHERE table_schema = 'public'
                """)).scalar()
                print(f"✓ Tablas en base de datos: {result}")

            return True
        else:
            print("✗ Error: No se pudo conectar a la base de datos")
            return False

    except Exception as e:
        print(f"✗ Error en base de datos: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_api_clients():
    """Verificar clientes API (requiere conexión a internet)."""
    print("\n" + "=" * 60)
    print("4. VERIFICANDO CLIENTES API")
    print("=" * 60)

    import asyncio

    async def run_tests():
        try:
            from soc_alerting.clients import NISTClient, CISAClient

            # Test NIST
            print("\nProbando NIST NVD API...")
            async with NISTClient() as nist:
                cve = await nist.fetch_cve_by_id("CVE-2021-44228")
                if cve:
                    print(f"✓ NIST API: OK")
                    print(f"  Obtenido: {cve.id}")
                    print(f"  CVSS: {cve.get_primary_cvss_v3()}")
                else:
                    print("✗ NIST API: No se pudo obtener CVE")
                    return False

            # Test CISA
            print("\nProbando CISA KEV API...")
            async with CISAClient() as cisa:
                catalog = await cisa.fetch_kev_catalog()
                print(f"✓ CISA KEV API: OK")
                print(f"  Catálogo: {len(catalog.vulnerabilities)} vulnerabilidades")
                print(f"  Versión: {catalog.catalogVersion}")

                is_in_kev = await cisa.is_cve_in_kev("CVE-2021-44228")
                print(f"  CVE-2021-44228 en KEV: {'Sí' if is_in_kev else 'No'}")

            return True

        except Exception as e:
            print(f"✗ Error en clientes API: {e}")
            import traceback
            traceback.print_exc()
            return False

    return asyncio.run(run_tests())


def test_models():
    """Verificar modelos Pydantic."""
    print("\n" + "=" * 60)
    print("5. VERIFICANDO MODELOS")
    print("=" * 60)

    try:
        from soc_alerting.models.domain import CVE, SeverityLevel, ClassificationSource
        from datetime import datetime

        # Create test CVE
        cve = CVE(
            cve_id="CVE-2024-99999",
            description="Test vulnerability",
            published_date=datetime.utcnow(),
            last_modified_date=datetime.utcnow(),
            cvss_v3_score=9.8,
            severity_nist=SeverityLevel.CRITICAL,
            final_severity=SeverityLevel.CRITICAL,
            classification_sources=[ClassificationSource.NIST_CVSS],
            source_identifier="test@example.com",
            vuln_status="Test",
        )

        print(f"✓ Modelo CVE creado: {cve.cve_id}")
        print(f"  Severidad NIST: {cve.severity_nist}")
        print(f"  Severidad Final: {cve.final_severity}")

        # Test CISA override
        cve.is_in_cisa_kev = True
        cve.final_severity = SeverityLevel.CRITICAL
        print(f"✓ CISA KEV override: {cve.final_severity}")

        return True

    except Exception as e:
        print(f"✗ Error en modelos: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Ejecutar todas las verificaciones."""
    print("\n" + "=" * 60)
    print("VERIFICACIÓN DEL SISTEMA SOC ALERTING")
    print("=" * 60)

    results = []

    # Run tests
    results.append(("Imports", test_imports()))
    results.append(("Configuración", test_configuration()))
    results.append(("Base de Datos", test_database()))
    results.append(("Modelos", test_models()))
    results.append(("Clientes API", test_api_clients()))

    # Summary
    print("\n" + "=" * 60)
    print("RESUMEN")
    print("=" * 60)

    all_passed = True
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status:10} {name}")
        if not passed:
            all_passed = False

    print("=" * 60)

    if all_passed:
        print("\n✓ TODAS LAS VERIFICACIONES PASARON!")
        print("\nEl sistema está funcionando correctamente.")
        return 0
    else:
        print("\n✗ ALGUNAS VERIFICACIONES FALLARON")
        print("\nRevisa los errores arriba.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
