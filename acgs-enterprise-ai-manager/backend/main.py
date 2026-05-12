"""
ACGS Enterprise Manager - FastAPI Main Application
Main entry point for the backend API server
"""

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import time

from backend.database import init_db, close_db
from backend.middleware.governance_interceptor import GovernanceMiddleware
from backend.auth.dependencies import get_current_user
from backend.auth.router import router as auth_router

# Import API routers
from backend.api import (
    tasks,
    recommendations,
    search,
    projects,
    assets,
    infrastructure,
    documents,
    financial,
    reports,
    feedback,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    # Startup
    logger.info("Starting ACGS Enterprise Manager API...")
    await init_db()
    logger.info("Database initialized successfully")

    yield

    # Shutdown
    logger.info("Shutting down ACGS Enterprise Manager API...")
    await close_db()
    logger.info("Database connections closed")


# Initialize FastAPI application
app = FastAPI(
    title="ACGS Enterprise Manager API",
    description="Enterprise AI Agent Management System with Constitutional Governance",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8080",
    ],  # Frontend origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add governance interceptor middleware
app.add_middleware(GovernanceMiddleware)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time to response headers."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle uncaught exceptions globally."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error", "type": "internal_error"},
    )


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "service": "acgs-enterprise-manager",
        "version": "1.0.0",
    }


# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """Root endpoint with API information."""
    return {
        "message": "ACGS Enterprise Manager API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }


# Register API routers
auth_dependency = [Depends(get_current_user)]

app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(
    tasks.router, prefix="/api/v1/tasks", tags=["Tasks"], dependencies=auth_dependency
)
app.include_router(
    recommendations.router,
    prefix="/api/v1/recommendations",
    tags=["Recommendations"],
    dependencies=auth_dependency,
)
app.include_router(
    search.router,
    prefix="/api/v1/search",
    tags=["Search"],
    dependencies=auth_dependency,
)
app.include_router(
    projects.router,
    prefix="/api/v1/projects",
    tags=["Projects"],
    dependencies=auth_dependency,
)
app.include_router(
    assets.router,
    prefix="/api/v1/assets",
    tags=["IT Assets"],
    dependencies=auth_dependency,
)
app.include_router(
    infrastructure.router,
    prefix="/api/v1/infrastructure",
    tags=["Infrastructure"],
    dependencies=auth_dependency,
)
app.include_router(
    documents.router,
    prefix="/api/v1/documents",
    tags=["Documents"],
    dependencies=auth_dependency,
)
app.include_router(
    financial.router,
    prefix="/api/v1/financial",
    tags=["Financial"],
    dependencies=auth_dependency,
)
app.include_router(
    reports.router,
    prefix="/api/v1/reports",
    tags=["Reports"],
    dependencies=auth_dependency,
)
app.include_router(
    feedback.router,
    prefix="/api/v1/feedback",
    tags=["Feedback"],
    dependencies=auth_dependency,
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app", host="0.0.0.0", port=8000, reload=True, log_level="info"
    )
