import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI-Powered Email Threat Detection & Forensic Intelligence Platform"
    SIH_PS_ID: str = "26106"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Database Configuration (SQLite default for rapid dev/test, PostgreSQL supported)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./forensics.db")
    
    # Security & Authentication
    SECRET_KEY: str = os.getenv("SECRET_KEY", "sih-2026-cybersecurity-secret-key-change-in-prod-987654321")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    
    # Blockchain Settings
    WEB3_RPC_PROVIDER: str = os.getenv("WEB3_RPC_PROVIDER", "http://127.0.0.1:8545")
    CONTRACT_ADDRESS: str = os.getenv("CONTRACT_ADDRESS", "0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
    PRIVATE_KEY: str = os.getenv("PRIVATE_KEY", "0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d")
    
    # External Intelligence Keys (Optional for OSINT lookups)
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    
    # Neo4j Threat Relationship Graph Settings
    NEO4J_URI: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "neo4j")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "password")
    NEO4J_DATABASE: str = os.getenv("NEO4J_DATABASE", "neo4j")
    
    class Config:
        case_sensitive = True

settings = Settings()
