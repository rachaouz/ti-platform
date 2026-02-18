from fastapi import APIRouter, Query
from services.domain_service import get_domain_report
from fastapi.responses import JSONResponse
import json

router = APIRouter(
    prefix="/domain",
    tags=["Domain Enrichment"]
)

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
        "Registrar": report["registrar"],
        "Creation Date": report["creation_date"],
        "Reputation Score": report["reputation_score"],
        "Categories": report["categories"],
        "Detection": {
            "Malicious": report["detection"]["malicious"],
            "Suspicious": report["detection"]["suspicious"],
            "Undetected": report["detection"]["undetected"]
        },
        "Last Analysis Date": report["last_analysis_date"],
        "Risk": {
            "Score": report["risk_score"],
            "Level": report["risk_level"]
        },
        "Shodan": {
            "Subdomains": report["shodan"].get("shodan_subdomains", []),
            "Subdomains Count": report["shodan"].get("shodan_subdomains_count", 0),
            "Tags": report["shodan"].get("shodan_tags", []),
            "Open Ports": report["shodan"].get("shodan_ports", []),
            "Open Ports Count": report["shodan"].get("shodan_ports_count", 0),
            "CVEs Count": report["shodan"].get("shodan_vulns_count", 0)
        },
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
