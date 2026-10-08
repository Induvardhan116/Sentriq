from fastapi import APIRouter
from app.api.system import router as system_router
from app.api.projects import router as projects_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router

api_router = APIRouter()

# Canonical modular routers (mounted under /api)
api_router.include_router(system_router)
api_router.include_router(projects_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
