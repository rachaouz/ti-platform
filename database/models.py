from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from database.db import Base

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String, index=True)
    risk_level = Column(String)
    risk_score = Column(Integer)
    confidence = Column(String)
    source = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
