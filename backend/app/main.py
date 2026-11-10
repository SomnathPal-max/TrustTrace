import time
from collections import defaultdict
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.db.session import init_db
from backend.app.api.routes import router

# Sliding window in-memory rate limiter based on settings.rate_limit_per_minute
_rate_limit_records = defaultdict(list)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing database schema...")
    init_db()
    logger.info("Database initialized successfully.")
    
    # Load demonstration seed data for campaign correlation
    try:
        from backend.app.db.seed_data import seed_demo_campaigns
        from backend.app.db.session import SessionLocal
        db = SessionLocal()
        seed_demo_campaigns(db)
        db.close()
        logger.info("Demo campaign seed indicators loaded successfully.")
    except Exception as e:
        logger.warning(f"Demo campaign seeding notice: {e}")

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
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]
allowed_origins = [o.strip() for o in origins if o and o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|.*\.onrender\.com)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    # Bypass health checks and API docs from rate limit
    if request.url.path in ("/api/health", "/docs", "/redoc", "/openapi.json"):
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window_start = now - 60.0

    recent = [ts for ts in _rate_limit_records[client_ip] if ts > window_start]
    if len(recent) >= settings.rate_limit_per_minute:
        return JSONResponse(
            status_code=429,
            content={"detail": f"Rate limit exceeded. Maximum {settings.rate_limit_per_minute} requests per minute."}
        )

    recent.append(now)
    _rate_limit_records[client_ip] = recent
    return await call_next(request)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
