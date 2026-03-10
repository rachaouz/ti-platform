import re
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse

# ------------------------------
# Routers depuis modules
# ------------------------------
from modules.hash_enrich.services import get_hash_report
from modules.hash_enrich.router import router as hash_router
from modules.dashboard.router import router as dashboard_router
from modules.domain_enrich.routers.domain_router import router as domain_router
from modules.ip_enrich.services.ip_service import check_ip_reputation
from modules.url_enrich.routers.url_router import router as url_router
from modules.ip_enrich.routers.ip_router import router as ip_router
from modules.mail_enrich.routes.mail_router import router as mail_router
# ------------------------------
# DB
# ------------------------------
from database.db import init_db

# ------------------------------
# Création de l'application FastAPI
# ------------------------------
app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme TI pour enrichissement de hash, domaines, IP, URLs et emails",
    version="1.0"
)

# ------------------------------
# Création des tables au démarrage
# ------------------------------
init_db()

# ------------------------------
# Inclusion des routers
# ------------------------------
app.include_router(hash_router, prefix="/hash", tags=["Hash Enrichment"])
app.include_router(domain_router, prefix="/domain", tags=["Domain Enrichment"])
app.include_router(ip_router, prefix="/ip", tags=["IP Reputation"])
app.include_router(url_router)  # garde le prefix défini dans ton router
app.include_router(dashboard_router, prefix="/dashboard", tags=["Dashboard"])
app.include_router(mail_router, prefix="/mail", tags=["Mail Reputation"])
# ------------------------------
# Route racine / Health
# ------------------------------
@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "message": "Threat Intelligence Platform is running"}

# ------------------------------
# Scan Hash simple
# ------------------------------
@app.get("/scan/", tags=["Hash Enrichment"])
def scan_hash(param: str = Query(..., description="Hash value to enrich")):
    result = get_hash_report(param)

    if "error" in result:
        return JSONResponse(
            content={"error": result["error"]},
            status_code=400
        )

    return JSONResponse(
        content=result,
        status_code=200
    )

# ------------------------------
# IOC Unified Endpoint
# ------------------------------
@app.get("/ioc/", tags=["IOC Unified Scan"])
def scan_ioc(value: str = Query(..., description="IOC value (IP, Domain, Hash, URL, Email)")):

    # 1️⃣ Hash (MD5 / SHA1 / SHA256)
    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return get_hash_report(value)

    # 2️⃣ Email
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        from modules.mail_enrich.services.mail_service import check_mail_reputation
        return check_mail_reputation(value)

    # 3️⃣ IP
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value):
        from modules.ip_enrich.services.ip_service import check_ip_reputation
        return check_ip_reputation(value)

    # 4️⃣ URL
    if value.startswith("http://") or value.startswith("https://"):
        from modules.url_enrich.services.url_service import get_url_report
        return get_url_report(value)

    # 5️⃣ Sinon → Domain
    from modules.domain_enrich.services.domain_service import get_domain_report
    return get_domain_report(value)