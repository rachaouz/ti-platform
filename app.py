from fastapi import FastAPI
from routers.domain_router import router as domain_router
from database.db import engine
from database import models

app = FastAPI(
    title="Threat Intelligence Platform",
    description="Plateforme pour enrichissement de domaines via VirusTotal et Shodan",
    version="1.0"
)

app.include_router(domain_router)

models.Base.metadata.create_all(bind=engine)