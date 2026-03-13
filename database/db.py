from sqlalchemy import create_engine
<<<<<<< HEAD
from sqlalchemy.orm import sessionmaker, declarative_base
=======
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
>>>>>>> 3562cf76fda63f37d9767c982246ffe4f7ac7c27
import os
from dotenv import load_dotenv

load_dotenv()

<<<<<<< HEAD
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
=======
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./threat_intel.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
>>>>>>> 3562cf76fda63f37d9767c982246ffe4f7ac7c27
