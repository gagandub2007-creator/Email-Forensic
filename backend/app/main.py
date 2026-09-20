from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.models.database import engine, Base
from app.api.routes import router as api_router

# Auto-create SQLite database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    version=settings.VERSION,
    description="AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform (SIH 2026 PS ID: 26106)"
)

# Configure CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow all origins for dev/testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.get("/")
def root():
    return {
        "status": "online",
        "system": settings.PROJECT_NAME,
        "sih_ps_id": settings.SIH_PS_ID,
        "organization": "AICTE - Cyber Security Cell",
        "version": settings.VERSION,
        "docs_url": "/docs"
    }
