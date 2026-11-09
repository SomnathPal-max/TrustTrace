from sqlalchemy import Column, String, Integer, Boolean, Text, Index, DateTime
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = "scans"
    
    report_id = Column(String(64), primary_key=True)
    created_at = Column(String(64), nullable=False)
    input_type = Column(String(16), nullable=False)
    risk_label = Column(String(32), nullable=False)
    risk_score = Column(Integer, nullable=False, default=0)
    full_report_json = Column(Text, nullable=False)
    canonical_text = Column(Text, nullable=True)  # Populated at commit time
    report_hash = Column(String(64), nullable=True)
    is_committed = Column(Boolean, default=False, nullable=False)
    is_demo_seed = Column(Boolean, default=False, nullable=False)
    tamper_backup_json = Column(Text, nullable=True)  # Used for demo tamper/restore

class IndicatorRecord(Base):
    __tablename__ = "indicators"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), nullable=False, index=True)
    indicator_type = Column(String(64), nullable=False)
    indicator_value = Column(String(256), nullable=False)
    strength_class = Column(String(32), nullable=False)  # "strong" or "possible"
    created_at = Column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_indicators_type_value", "indicator_type", "indicator_value"),
    )

class CommitRecord(Base):
    __tablename__ = "commits"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(String(64), nullable=False, unique=True, index=True)
    tx_hash = Column(String(128), nullable=False)
    block_number = Column(Integer, nullable=False, default=0)
    network = Column(String(64), nullable=False)
    chain_id = Column(Integer, nullable=False)
    contract_address = Column(String(64), nullable=False)
    revision = Column(Integer, nullable=False, default=1)
    committed_at = Column(String(64), nullable=False)
