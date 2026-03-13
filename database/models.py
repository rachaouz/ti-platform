<<<<<<< HEAD
from sqlalchemy import Column, Integer, String, JSON, DateTime
from sqlalchemy.sql import func
from datetime import datetime
from .db import Base
=======
from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime
from database.db import Base
>>>>>>> 3562cf76fda63f37d9767c982246ffe4f7ac7c27

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String, index=True)
    risk_level = Column(String)
    risk_score = Column(Integer)
    confidence = Column(String)
    source = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
<<<<<<< HEAD


class IPReputation(Base):
    __tablename__ = "ip_reputation"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)  # ❌ unique supprimé
    final_verdict = Column(String)
    country = Column(String)
    data = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
=======
>>>>>>> 3562cf76fda63f37d9767c982246ffe4f7ac7c27
