from fastapi import APIRouter, Query
from modules.domain_enrich.services.domain_service import get_domain_report
from fastapi.responses import JSONResponse
import json

router = APIRouter()
@router.get("/")
def domain_lookup(
    param: str = Query(..., description="Domain name to enrich")
):
    report = get_domain_report(param)

    if "error" in report:
        return JSONResponse(
            content={"error": report["error"]},
            status_code=404
        )

    formatted = {
        "Domain": report["domain"],
        "IP Address": report["ip_address"],          # NOUVEAU
        "Registrar": report["registrar"],
        "Creation Date": report["creation_date"],

        # --- SOURCE : VIRUSTOTAL ---
        "VirusTotal": {
            "Reputation Score": report["virustotal"]["reputation_score"],
            "Categories": report["virustotal"]["categories"],
            "Detection": {
                "Malicious": report["virustotal"]["detection"]["malicious"],
                "Suspicious": report["virustotal"]["detection"]["suspicious"],
                "Undetected": report["virustotal"]["detection"]["undetected"]
            },
            "Last Analysis Date": report["virustotal"]["last_analysis_date"],
            "Risk Score": report["virustotal"]["risk_score"],
            "Risk Level": report["virustotal"]["risk_level"]
        },

        # --- SOURCE : SHODAN ---
        "Shodan": {
            "Subdomains": report["shodan"]["subdomains"],
            "Subdomains Count": report["shodan"]["subdomains_count"],
            "Tags": report["shodan"]["tags"],
            "Open Ports": report["shodan"]["open_ports"],
            "Open Ports Count": report["shodan"]["open_ports_count"],
            "CVEs Count": report["shodan"]["cves_count"]
        },

        # --- RISK GLOBAL ---
        "Global Risk": {
            "Score": report["global_risk_score"],
            "Level": report["global_risk_level"],
            "Confidence": report["confidence"]
        }
    }

    return JSONResponse(
        content=json.loads(json.dumps(formatted, indent=4)),
        media_type="application/json"
    )