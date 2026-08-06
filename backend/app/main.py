from fastapi import FastAPI

from app.api.routes.health import router as health_router

app = FastAPI(
    title="Sentinel AI",
    description="Autonomous Cybersecurity Threat Intelligence Agent",
    version="1.0.0",
)

app.include_router(health_router)


@app.get("/")
def root():
    return {
        "message": "Sentinel AI Backend Running 🚀"
    }