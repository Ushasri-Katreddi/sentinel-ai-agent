from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config.settings import settings
from app.api.routes.health import router as health_router
from app.api.routes.threat import router as threat_router
from app.api.routes.caspian import router as caspian_router


app = FastAPI(
    title=settings.APP_NAME,
    description=settings.APP_DESCRIPTION,
    version=settings.APP_VERSION,
)


# Allow the React frontend to communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API routes
app.include_router(health_router)
app.include_router(threat_router)
app.include_router(caspian_router)


@app.get("/")
def root():
    return {
        "message": "Sentinel AI Backend Running 🚀"
    }