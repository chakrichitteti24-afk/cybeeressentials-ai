from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pymongo.errors import ConfigurationError, PyMongoError

from database.config import get_settings
from database.session import create_indexes, get_client
from routes import analyze, auth, logs, threats


settings = get_settings()


def create_app() -> FastAPI:
    application = FastAPI(
        title="AI Security Threat Detection API",
        description="Backend for log ingestion, threat detection, risk scoring, and AI explanations.",
        version="1.0.0",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @application.exception_handler(PyMongoError)
    async def database_exception_handler(request: Request, exc: PyMongoError):
        return JSONResponse(status_code=500, content={"detail": "Database operation failed"})

    @application.exception_handler(ConfigurationError)
    async def database_config_exception_handler(request: Request, exc: ConfigurationError):
        return JSONResponse(
            status_code=500,
            content={
                "detail": (
                    "MongoDB configuration failed. Check MONGODB_URI in backend/.env "
                    "and replace the placeholder cluster host with your real MongoDB Atlas URI."
                )
            },
        )

    @application.get("/")
    async def root():
        return {"status": "running", "service": settings.app_name, "environment": settings.environment}

    @application.get("/health")
    async def health():
        return {"status": "healthy"}

    @application.on_event("startup")
    def startup():
        if "CLUSTER.mongodb.net" in settings.mongodb_uri or "cluster.mongodb.net" in settings.mongodb_uri:
            print("WARNING: MONGODB_URI still contains the placeholder Atlas host.")
            return
        try:
            get_client().admin.command("ping")
            if settings.create_indexes_on_startup:
                create_indexes()
        except PyMongoError as exc:
            print(f"WARNING: MongoDB connection failed during startup: {exc}")

    application.include_router(auth.router, prefix=settings.api_prefix)
    application.include_router(logs.router, prefix=settings.api_prefix)
    application.include_router(threats.router, prefix=settings.api_prefix)
    application.include_router(analyze.router, prefix=settings.api_prefix)
    return application


app = create_app()
