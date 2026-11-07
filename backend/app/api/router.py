from fastapi import APIRouter
from app.api.system import router as system_router
from app.api.auth import router as auth_router
from app.api.projects import router as projects_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.analytics import router as analytics_router
from app.api.repositories import router as repositories_router
from app.api.api_security import router as api_security_router
from app.api.cloud_security import router as cloud_security_router
from app.api.reports import router as reports_router
from app.api.settings import router as settings_router
from app.api.integrations import router as integrations_router
from app.api.workspaces import router as workspaces_router

api_router = APIRouter()

# Canonical modular routers (mounted under /api)
api_router.include_router(system_router)
api_router.include_router(auth_router)
api_router.include_router(projects_router)
api_router.include_router(scans_router)
api_router.include_router(findings_router)
api_router.include_router(analytics_router)
api_router.include_router(repositories_router)
api_router.include_router(api_security_router)
api_router.include_router(cloud_security_router)
api_router.include_router(reports_router)
api_router.include_router(settings_router)
api_router.include_router(integrations_router)
api_router.include_router(workspaces_router)
