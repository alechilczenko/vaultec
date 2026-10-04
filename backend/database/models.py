"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy import Boolean, Column, DateTime, Integer, String, ForeignKey, Text, UniqueConstraint, func, ARRAY
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from database.db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

class Workspace(Base):
    """
    Represents the single active audit workspace context.
    Only one row (id=1) should exist or be active at any given time.
    """
    __tablename__ = "workspace"
    id = Column(Integer, primary_key=True, default=1)
    name = Column(String(100), nullable=True)
    client_name = Column(String(100), nullable=True)
    status = Column(String(20), default="empty")  # "active", "empty"
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    # Added unique=True to prevent race conditions at the database level
    name = Column(String, unique=True, index=True, nullable=False)
    type = Column(String, nullable=False)
    # Existing DBs: scripts/sql/add_notes_to_assets.sql
    # Drop legacy scope: scripts/sql/drop_scope_from_assets.sql
    notes = Column(Text, nullable=True)
    
    # Removed cascade="all, delete-orphan" to preserve audit history
    vulnerabilities = relationship("Vulnerability", back_populates="asset")

class VulnerabilityDefinition(Base):
    __tablename__ = "vulnerability_definitions"
    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    title = Column(String, unique=True, index=True)
    severity = Column(String, nullable=False)
    # Existing DBs: scripts/sql/add_category_to_vulnerability_definitions.sql
    category = Column(String(100), nullable=False, server_default="General")
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    tags = Column(ARRAY(String), default=[])
    
    # Removed cascade="all, delete-orphan" to preserve audit history
    instances = relationship("Vulnerability", back_populates="definition")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    # Existing DBs: scripts/sql/add_unique_vulnerability_definition_asset.sql
    __table_args__ = (
        UniqueConstraint(
            "definition_id",
            "asset_id",
            name="uq_vulnerability_definition_asset",
        ),
    )
    id = Column(Integer, primary_key=True)
    status = Column(String, default="open")
    evidence_type = Column(String) # "http", "terminal", "log"
    evidence = Column(JSONB, nullable=True)
    discovered_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    notes = Column(Text, nullable=True)

    # Removed ondelete="CASCADE" to block accidental deletion of assets with active findings
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    definition_id = Column(Integer, ForeignKey("vulnerability_definitions.id"), nullable=False)
    
    asset = relationship("Asset", back_populates="vulnerabilities")
    definition = relationship("VulnerabilityDefinition", back_populates="instances")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)