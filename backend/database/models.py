"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy import Boolean, Column, DateTime, Integer, String, ForeignKey, Text, func, ARRAY, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from database.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    client_name = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # SQLAlchemy level cascade: If the Project object is deleted, 
    # these related objects will be deleted from the session.
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Vulnerability", back_populates="project", cascade="all, delete-orphan")
    notes = relationship("Note", back_populates="project", cascade="all, delete-orphan")

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    name = Column(String, index=True, nullable=False)
    type = Column(String)
    description = Column(Text, nullable=True)

    # Database level cascade: If the row in 'projects' is deleted, 
    # the DB engine will automatically remove this asset.
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    project = relationship("Project", back_populates="assets")
    
    # Relationship with vulnerabilities (findings)
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    __table_args__ = (UniqueConstraint('name', 'project_id', name='_asset_project_uc'),)

class VulnerabilityDefinition(Base):
    __tablename__ = "vulnerability_definitions"
    id = Column(Integer, primary_key=True)
    title = Column(String, unique=True, index=True)
    severity = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    tags = Column(ARRAY(String), default=[])
    instances = relationship("Vulnerability", back_populates="definition", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    status = Column(String, default="open")
    evidence_type = Column(String) # "http", "terminal", "log"
    evidence = Column(JSONB, nullable=True)
    discovered_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text, nullable=True)

    # Both FKs use ondelete="CASCADE" to ensure that deleting 
    # either the Project or the Asset removes the finding.
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    
    # Notice: No ondelete="CASCADE" for definition_id to avoid accidental catalog deletion
    definition_id = Column(Integer, ForeignKey("vulnerability_definitions.id"), nullable=False)
    
    project = relationship("Project", back_populates="findings")
    asset = relationship("Asset", back_populates="vulnerabilities")
    definition = relationship("VulnerabilityDefinition", back_populates="instances")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)

    # Relations
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    project = relationship("Project", back_populates="notes")