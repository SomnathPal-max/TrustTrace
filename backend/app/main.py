from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.db.session import init_db
from backend.app.api.routes import router

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database schema...")
    init_db()
    logger.info("Database initialized successfully.")
    yield

app = FastAPI(
    title="Link & Scam Detective API",
    description="AI-Powered Web Threat Detection & Digital Trust Intelligence",
    version="1.0.0",
    lifespan=lifespan
)

origins = [
    settings.frontend_origin,
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
