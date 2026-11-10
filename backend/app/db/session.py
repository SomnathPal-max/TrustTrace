import json
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from backend.app.core.config import settings
from backend.app.db.models import Base, ScanRecord, IndicatorRecord, CommitRecord

# Handle SQLite vs Postgres connection strings
db_url = settings.database_url
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

connect_args = {}
if db_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(db_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
    # Ensure added columns exist in SQLite database
    try:
        with engine.connect() as conn:
            for col, col_def in [
                ("status", "VARCHAR(32) DEFAULT 'Reported'"),
                ("reporter", "VARCHAR(64) DEFAULT '0x70997970C51812dc3A010C7d01b50e0d17dc79C8'"),
                ("is_simulated", "BOOLEAN DEFAULT 1")
            ]:
                try:
                    conn.execute(text(f"ALTER TABLE commits ADD COLUMN {col} {col_def}"))
                    conn.commit()
                except Exception:
                    pass
    except Exception:
        pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
