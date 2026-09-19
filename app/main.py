import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler

import httpx
from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import DateTime, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

APP_NAME = "VT Hash Checker"
VT_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

DB_PATH = os.getenv("DB_PATH", "/data/vt_history.sqlite3")
LOG_PATH = os.getenv("LOG_PATH", "/logs/app.log")
CACHE_TTL_DAYS = int(os.getenv("CACHE_TTL_DAYS", "7"))
REQUESTS_PER_HOUR = int(os.getenv("REQUESTS_PER_HOUR", "20"))
MAX_HISTORY = int(os.getenv("MAX_HISTORY", "1000"))

db_dir = os.path.dirname(DB_PATH)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)
log_dir = os.path.dirname(LOG_PATH)
if log_dir:
    os.makedirs(log_dir, exist_ok=True)

logger = logging.getLogger("vt_checker")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_PATH, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
logger.addHandler(handler)
logger.addHandler(logging.StreamHandler())

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class HashRequest(Base):
    __tablename__ = "hash_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hash: Mapped[str] = mapped_column(String(64), index=True)
    algorithm: Mapped[str] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(String(32))
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hash: Mapped[str] = mapped_column(String(64), index=True)
    author: Mapped[str] = mapped_column(String(80), default="Anonymous")
    text: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


Base.metadata.create_all(engine)

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# In-memory global limiter. It resets on container restart; persistent throttling is
# intentionally avoided so the SQLite DB remains focused on history/results.
request_times: list[datetime] = []
rate_lock = asyncio.Lock()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalize_hash(value: str) -> tuple[str, str]:
    h = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{32}", h):
        return h, "MD5"
    if re.fullmatch(r"[0-9a-f]{40}", h):
        return h, "SHA-1"
    if re.fullmatch(r"[0-9a-f]{64}", h):
        return h, "SHA-256"
    raise ValueError("Нужен MD5, SHA-1 или SHA-256.")


async def acquire_rate_slot() -> bool:
    now = datetime.now(timezone.utc)
    async with rate_lock:
        cutoff = now - timedelta(hours=1)
        request_times[:] = [t for t in request_times if t > cutoff]
        if len(request_times) >= REQUESTS_PER_HOUR:
            return False
        request_times.append(now)
        return True


def cleanup_old_data(db: Session) -> None:
    cutoff = utcnow() - timedelta(days=CACHE_TTL_DAYS)
    old_requests = db.scalars(select(HashRequest).where(HashRequest.expires_at < utcnow())).all()
    for row in old_requests:
        db.delete(row)
    old_comments = db.scalars(select(Comment).where(Comment.created_at < cutoff)).all()
    for row in old_comments:
        db.delete(row)
    db.commit()


def parse_report(payload: dict) -> dict:
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}

    engines = []
    for name, item in sorted(results.items(), key=lambda x: x[0].lower()):
        engines.append({
            "engine": name,
            "category": item.get("category"),
            "result": item.get("result"),
            "version": item.get("engine_version"),
            "update": item.get("engine_update"),
        })

    return {
        "stats": {
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "timeout": int(stats.get("timeout", 0) or 0),
            "confirmed-timeout": int(stats.get("confirmed-timeout", 0) or 0),
            "failure": int(stats.get("failure", 0) or 0),
            "type-unsupported": int(stats.get("type-unsupported", 0) or 0),
        },
        "reputation": attrs.get("reputation"),
        "meaningful_name": attrs.get("meaningful_name"),
        "size": attrs.get("size"),
        "type_description": attrs.get("type_description"),
        "first_submission_date": attrs.get("first_submission_date"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "times_submitted": attrs.get("times_submitted"),
        "engines": engines,
    }


async def query_virustotal(file_hash: str) -> tuple[str, dict | None, str | None]:
    if not VT_API_KEY:
        return "configuration_error", None, "VT_API_KEY не задан."

    headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
    url = f"{VT_BASE}/files/{file_hash}"

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 200:
            return "ok", parse_report(response.json()), None
        if response.status_code == 404:
            return "not_found", None, "VirusTotal не имеет отчёта для этого хэша."
        if response.status_code == 429:
            return "rate_limited", None, "VirusTotal вернул 429: превышена квота или rate limit."
        if response.status_code in (401, 403):
            return "auth_error", None, "VirusTotal отклонил API-ключ или доступ к API."
        return "upstream_error", None, f"VirusTotal HTTP {response.status_code}: {response.text[:300]}"
    except httpx.TimeoutException:
        return "timeout", None, "Таймаут при обращении к VirusTotal."
    except httpx.HTTPError as exc:
        return "network_error", None, f"Ошибка сети: {exc}"
    except Exception as exc:
        logger.exception("Unexpected VirusTotal error")
        return "internal_error", None, f"Внутренняя ошибка: {exc}"


@app.on_event("startup")
def startup() -> None:
    logger.info("Application started; DB=%s LOG=%s", DB_PATH, LOG_PATH)
    with SessionLocal() as db:
        cleanup_old_data(db)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, hash_value: str = Query("", alias="hash")):
    result = None
    error = None
    result_hash = None
    result_comments = []
    status_code = 200

    with SessionLocal() as db:
        cleanup_old_data(db)
        rows = db.scalars(
            select(HashRequest).order_by(HashRequest.requested_at.desc()).limit(MAX_HISTORY)
        ).all()
        comments = db.scalars(
            select(Comment).order_by(Comment.created_at.desc()).limit(MAX_HISTORY)
        ).all()

        # Открытие анализа по ссылке из истории: берём данные из локального кэша,
        # новый запрос к VirusTotal здесь не делаем (GET без побочных эффектов).
        if hash_value:
            try:
                file_hash, _ = normalize_hash(hash_value)
            except ValueError as exc:
                error = str(exc)
                status_code = 400
            else:
                hash_value = file_hash
                cached = db.scalar(
                    select(HashRequest)
                    .where(
                        HashRequest.hash == file_hash,
                        HashRequest.status == "ok",
                        HashRequest.result_json.is_not(None),
                    )
                    .order_by(HashRequest.requested_at.desc())
                )
                if cached:
                    result = json.loads(cached.result_json)
                    result_hash = file_hash
                    result_comments = db.scalars(
                        select(Comment)
                        .where(Comment.hash == file_hash)
                        .order_by(Comment.created_at.desc())
                    ).all()
                else:
                    last = db.scalar(
                        select(HashRequest)
                        .where(HashRequest.hash == file_hash)
                        .order_by(HashRequest.requested_at.desc())
                    )
                    error = (last.error if last and last.error else None) or (
                        "Сохранённого отчёта для этого хэша нет. Нажмите «Проверить», чтобы запросить его заново."
                    )

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "rows": rows,
            "comments": comments,
            "result": result,
            "error": error,
            "hash_value": hash_value,
            "result_hash": result_hash,
            "result_comments": result_comments,
            "requests_per_hour": REQUESTS_PER_HOUR,
        },
        status_code=status_code,
    )


@app.post("/lookup", response_class=HTMLResponse)
async def lookup(request: Request, hash_value: str = Form(...)):
    with SessionLocal() as db:
        cleanup_old_data(db)

        try:
            file_hash, algorithm = normalize_hash(hash_value)
        except ValueError as exc:
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "rows": [], "comments": [], "result": None,
                 "error": str(exc), "hash_value": hash_value, "requests_per_hour": REQUESTS_PER_HOUR},
                status_code=400,
            )

        cached = db.scalar(
            select(HashRequest)
            .where(HashRequest.hash == file_hash, HashRequest.expires_at >= utcnow(), HashRequest.status == "ok")
            .order_by(HashRequest.requested_at.desc())
        )
        if cached and cached.result_json:
            result = json.loads(cached.result_json)
            logger.info("Cache hit hash=%s", file_hash)
            comments = db.scalars(select(Comment).where(Comment.hash == file_hash).order_by(Comment.created_at.desc())).all()
            rows = db.scalars(select(HashRequest).order_by(HashRequest.requested_at.desc()).limit(MAX_HISTORY)).all()
            all_comments = db.scalars(select(Comment).order_by(Comment.created_at.desc()).limit(MAX_HISTORY)).all()
            return templates.TemplateResponse("index.html", {
                "request": request, "rows": rows, "comments": all_comments,
                "result": result, "error": None, "hash_value": file_hash,
                "result_hash": file_hash, "result_comments": comments,
                "requests_per_hour": REQUESTS_PER_HOUR,
            })

        if not await acquire_rate_slot():
            logger.warning("Application rate limit reached hash=%s", file_hash)
            rows = db.scalars(select(HashRequest).order_by(HashRequest.requested_at.desc()).limit(MAX_HISTORY)).all()
            comments = db.scalars(select(Comment).order_by(Comment.created_at.desc()).limit(MAX_HISTORY)).all()
            return templates.TemplateResponse("index.html", {
                "request": request, "rows": rows, "comments": comments, "result": None,
                "error": f"Локальный лимит: не более {REQUESTS_PER_HOUR} новых запросов в час.",
                "hash_value": file_hash, "requests_per_hour": REQUESTS_PER_HOUR,
            }, status_code=429)

        status, result, error = await query_virustotal(file_hash)
        row = HashRequest(
            hash=file_hash,
            algorithm=algorithm,
            status=status,
            requested_at=utcnow(),
            expires_at=utcnow() + timedelta(days=CACHE_TTL_DAYS),
            client_ip=(request.client.host if request.client else ""),
            error=error,
        )
        if result is not None:
            row.result_json = json.dumps(result, ensure_ascii=False)
        db.add(row)
        db.commit()

        logger.info("Lookup hash=%s algorithm=%s status=%s", file_hash, algorithm, status)

        rows = db.scalars(select(HashRequest).order_by(HashRequest.requested_at.desc()).limit(MAX_HISTORY)).all()
        comments = db.scalars(select(Comment).order_by(Comment.created_at.desc()).limit(MAX_HISTORY)).all()
        result_comments = db.scalars(select(Comment).where(Comment.hash == file_hash).order_by(Comment.created_at.desc())).all()

        return templates.TemplateResponse("index.html", {
            "request": request, "rows": rows, "comments": comments,
            "result": result, "error": error, "hash_value": file_hash,
            "result_hash": file_hash, "result_comments": result_comments,
            "requests_per_hour": REQUESTS_PER_HOUR,
        })


@app.post("/comments")
def add_comment(
    hash_value: str = Form(...),
    text: str = Form(...),
    author: str = Form("Anonymous"),
):
    try:
        file_hash, _ = normalize_hash(hash_value)
    except ValueError:
        return RedirectResponse("/", status_code=303)

    text = text.strip()[:4000]
    author = (author.strip() or "Anonymous")[:80]
    if text:
        with SessionLocal() as db:
            db.add(Comment(hash=file_hash, author=author, text=text, created_at=utcnow()))
            db.commit()
        logger.info("Comment added hash=%s author=%s", file_hash, author)
    return RedirectResponse(f"/?hash={file_hash}", status_code=303)
