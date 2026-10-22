"""SQLAlchemy models for SentinelForge."""
import json
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from app.db import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    risk_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    summary = Column(Text, nullable=True)  # JSON summary

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    intel_results = relationship("IntelResult", back_populates="scan", cascade="all, delete-orphan")
    risk_items = relationship("RiskItem", back_populates="scan", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="scan", cascade="all, delete-orphan")

    @property
    def summary_dict(self):
        if self.summary:
            return json.loads(self.summary)
        return {}


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    finding_id = Column(String, nullable=False)  # e.g. HDR-001
    title = Column(String, nullable=False)
    category = Column(String, nullable=False)  # headers, cors, cookies, tls, bola
    severity = Column(String, nullable=False)  # Info, Low, Medium, High, Critical
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    stride_category = Column(String, nullable=True)
    nist_function = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")


class IntelResult(Base):
    __tablename__ = "intel_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    target = Column(String, nullable=False)  # domain or IP
    source = Column(String, nullable=False)  # virustotal, otx, mock
    is_mock = Column(Boolean, default=False)
    reputation_score = Column(Float, default=0.0)
    malicious_count = Column(Integer, default=0)
    data = Column(Text, nullable=True)  # JSON blob
    cached_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="intel_results")

    @property
    def data_dict(self):
        if self.data:
            return json.loads(self.data)
        return {}


class RiskItem(Base):
    __tablename__ = "risk_items"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    risk_id = Column(String, nullable=False)  # e.g. RISK-001
    asset = Column(String, nullable=False)
    threat = Column(String, nullable=False)
    stride_category = Column(String, nullable=False)
    nist_function = Column(String, nullable=False)
    likelihood = Column(Integer, default=3)  # 1-5
    impact = Column(Integer, default=3)  # 1-5
    risk_score = Column(Float, default=0.0)
    owner = Column(String, default="Security Team")
    treatment = Column(String, default="Remediate")  # Accept, Mitigate, Transfer, Avoid, Remediate
    status = Column(String, default="Open")  # Open, In Progress, Closed
    finding_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="risk_items")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    playbook_name = Column(String, nullable=False)
    trigger_condition = Column(Text, nullable=True)
    actions_taken = Column(Text, nullable=True)  # JSON list
    status = Column(String, default="executed")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="incidents")

    @property
    def actions_list(self):
        if self.actions_taken:
            return json.loads(self.actions_taken)
        return []


class IntelCache(Base):
    """Separate cache table to avoid duplicate API calls."""
    __tablename__ = "intel_cache"

    id = Column(Integer, primary_key=True, index=True)
    cache_key = Column(String, unique=True, index=True, nullable=False)
    data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
