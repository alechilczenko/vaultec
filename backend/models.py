from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from db import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)

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
    instances = relationship("Vulnerability", back_populates="definition", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    severity = Column(String)
    status = Column(String, default="open")
    asset_id = Column(Integer, ForeignKey("assets.id"))
    definition_id = Column(Integer, ForeignKey("vulnerability_definitions.id"))
    definition = relationship("VulnerabilityDefinition", back_populates="instances")
    asset = relationship("Asset")

class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)