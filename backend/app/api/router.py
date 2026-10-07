from fastapi import APIRouter
from app.api.system import router as system_router

api_router = APIRouter()

# Mount canonical modular routes
api_router.include_router(system_router)
