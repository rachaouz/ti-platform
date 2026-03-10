from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

# URL unique pour la base centralisée
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threatintel.db")

# Création du moteur
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # nécessaire pour SQLite
)

# Création de la session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base pour tous les modèles
Base = declarative_base()


# Dependency FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Fonction pour créer les tables si elles n'existent pas
def init_db():
    from . import models  # important pour importer tous les modèles
    Base.metadata.create_all(bind=engine)