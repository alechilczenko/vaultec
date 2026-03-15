"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, ForeignKey, Text, func
from sqlalchemy.orm import relationship
from database.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    type = Column(String)
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")

class VulnerabilityDefinition(Base):
    __tablename__ = "vulnerability_definitions"
    id = Column(Integer, primary_key=True)
    title = Column(String, unique=True, index=True)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    tags = Column(String, nullable=True)
    instances = relationship("Vulnerability", back_populates="definition", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    status = Column(String, default="open")
    evidence_type = Column(String) # "http", "terminal", "log"
    http_request = Column(Text, nullable=True)
    http_response = Column(Text, nullable=True)
    general_evidence = Column(Text, nullable=True)
    discovered_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    asset_id = Column(Integer, ForeignKey("assets.id"))
    definition_id = Column(Integer, ForeignKey("vulnerability_definitions.id"))
    definition = relationship("VulnerabilityDefinition", back_populates="instances")
    asset = relationship("Asset")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)