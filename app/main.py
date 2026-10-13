import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler

import httpx
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import DateTime, Integer, String, Text, create_engine, delete, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app import security

APP_NAME = "VT Hash Checker"
VT_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()

DB_PATH = os.getenv("DB_PATH", "/data/vt_history.sqlite3")
LOG_PATH = os.getenv("LOG_PATH", "/logs/app.log")
CACHE_TTL_DAYS = int(os.getenv("CACHE_TTL_DAYS", "7"))
REQUESTS_PER_HOUR = int(os.getenv("REQUESTS_PER_HOUR", "20"))
MAX_HISTORY = int(os.getenv("MAX_HISTORY", "1000"))
ENABLE_DOCS = os.getenv("ENABLE_DOCS", "0") == "1"      # Swagger/ReDoc только для разработки
MAX_COMMENTS_PER_HASH = int(os.getenv("MAX_COMMENTS_PER_HASH", "100"))
MAX_COMMENTS_TOTAL = int(os.getenv("MAX_COMMENTS_TOTAL", "5000"))

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

app = FastAPI(
    title=APP_NAME,
    docs_url="/docs" if ENABLE_DOCS else None,
    redoc_url="/redoc" if ENABLE_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_DOCS else None,
)
security.install(app)   # заголовки безопасности, проверка Origin, per-IP лимиты
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
    now = utcnow()
    db.execute(delete(HashRequest).where(HashRequest.expires_at < now))
    db.execute(delete(Comment).where(Comment.created_at < now - timedelta(days=CACHE_TTL_DAYS)))
    db.commit()


def _top_values(items, limit: int = 4) -> list[dict]:
    """Первые элементы списка {value, count} из popular_threat_classification."""
    out = []
    for item in (items or [])[:limit]:
        if isinstance(item, dict) and item.get("value"):
            out.append({"value": str(item["value"]), "count": int(item.get("count", 0) or 0)})
    return out


def parse_report(payload: dict) -> dict:
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats") or {}
    results = attrs.get("last_analysis_results") or {}
    threat = attrs.get("popular_threat_classification") or {}

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
        # Все имена файла, под которыми его загружали пользователи.
        # Предохранитель 2000 нужен только на случай аномально длинных списков.
        "names": [str(n) for n in (attrs.get("names") or []) if n][:2000],
        # Популярная метка угрозы, категории и семейства (как на странице VirusTotal)
        "threat_label": threat.get("suggested_threat_label"),
        "threat_categories": _top_values(threat.get("popular_threat_category")),
        "threat_names": _top_values(threat.get("popular_threat_name")),
        "engines": engines,
    }


def summarize_result(result: dict | None) -> dict | None:
    """Компактная сводка отчёта для интерфейса: счётчик, кольцо, имя файла, метка угрозы.

    Знаменатель считается как в VirusTotal: движки, которые дали вердикт
    (malicious + suspicious + undetected + harmless). Таймауты и неподдерживаемые
    типы файлов в него не входят.
    """
    if not result:
        return None
    stats = result.get("stats") or {}
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    total = malicious + suspicious + undetected + harmless

    def pct(value: int) -> float:
        return round(value * 100 / total, 2) if total else 0.0

    names = [n for n in (result.get("names") or []) if n]
    file_name = result.get("meaningful_name") or (names[0] if names else None)

    if not total:
        verdict = "unknown"
    elif malicious:
        verdict = "malicious"
    elif suspicious:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "verdict": verdict,
        "ring_malicious": pct(malicious),      # доли кольца в процентах
        "ring_suspicious": pct(suspicious),
        "file_name": file_name,
        "names": names,
        "names_known": "names" in result,      # у старых записей кэша этого поля нет
        "other_names": [n for n in names if n != file_name],
        "threat_label": result.get("threat_label"),
        "threat_categories": result.get("threat_categories") or [],
        "threat_names": result.get("threat_names") or [],
    }


def _load_summary(row: HashRequest) -> dict | None:
    if row.status != "ok" or not row.result_json:
        return None
    try:
        return summarize_result(json.loads(row.result_json))
    except ValueError:
        return None


def build_history(db: Session) -> list[dict]:
    """История запросов вместе со сводкой отчёта и комментариями по каждому хэшу."""
    requests_ = db.scalars(
        select(HashRequest).order_by(HashRequest.requested_at.desc()).limit(MAX_HISTORY)
    ).all()
    by_hash: dict[str, list[Comment]] = {}
    shown = {r.hash for r in requests_}
    if shown and COMMENTS_MODE >= 1:
        recent = select(Comment).where(Comment.hash.in_(shown)).order_by(Comment.created_at.desc()).limit(2000)
        for c in db.scalars(recent).all():
            bucket = by_hash.setdefault(c.hash, [])
            if len(bucket) < 20:          # в истории показываем не больше 20 комментариев на хэш
                bucket.append(c)
    return [
        {
            "requested_at": r.requested_at,
            "hash": r.hash,
            "algorithm": r.algorithm,
            "status": r.status,
            "summary": _load_summary(r),
            "comments": by_hash.get(r.hash, []),
        }
        for r in requests_
    ]


def comments_for(db: Session, file_hash: str) -> list[Comment]:
    if COMMENTS_MODE == 0:
        return []
    return db.scalars(
        select(Comment).where(Comment.hash == file_hash).order_by(Comment.created_at.desc())
    ).all()


def latest_summaries(db: Session, hashes: set[str]) -> dict[str, dict]:
    """Сводка последнего успешного отчёта для каждого хэша из набора."""
    if not hashes:
        return {}
    rows = db.scalars(
        select(HashRequest)
        .where(HashRequest.hash.in_(hashes), HashRequest.status == "ok", HashRequest.result_json.is_not(None))
        .order_by(HashRequest.requested_at.desc())
    ).all()
    out: dict[str, dict] = {}
    for r in rows:
        if r.hash not in out:
            summary = _load_summary(r)
            if summary:
                out[r.hash] = summary
    return out


def _static_version(filename: str) -> str:
    """Короткий хэш содержимого файла для параметра ?v= (сброс кэша браузера при изменении)."""
    try:
        with open(os.path.join("app", "static", filename), "rb") as f:
            return hashlib.md5(f.read()).hexdigest()[:10]
    except OSError:
        return "0"


templates.env.globals["summarize"] = summarize_result
templates.env.globals["cache_days"] = CACHE_TTL_DAYS
templates.env.globals["css_version"] = _static_version("style.css")

# Название сайта зависит от домена (заголовок Host, его передаёт nginx).
# Формат переменной SITE_NAMES: "домен=Название;домен2=Название2".
# Домены с кириллицей указываются в punycode. Остальные домены получают APP_NAME.
SITE_NAMES: dict[str, str] = {}
for _item in os.getenv("SITE_NAMES", "xn--80adsnnlhibg.xn--p1ai=вирустотал.рф").split(";"):
    _host, _sep, _name = _item.partition("=")
    if _sep and _host.strip() and _name.strip():
        SITE_NAMES[_host.strip().lower()] = _name.strip()


def site_name(request: Request) -> str:
    host = (request.url.hostname or "").rstrip(".")   # без порта, в нижнем регистре
    return SITE_NAMES.get(host, APP_NAME)


templates.env.globals["site_name"] = site_name


# Режим комментариев (переменная COMMENTS_MODE):
#   0 — комментарии скрыты, писать нельзя;
#   1 — комментарии видны, писать нельзя;
#   2 — комментарии видны и можно писать (по умолчанию, если переменная не задана).
# Неверное значение считается самым строгим режимом 0 (и пишется в лог).
def _parse_comments_mode(raw: str) -> int:
    raw = raw.strip()
    if raw == "":
        return 2
    if raw in ("0", "1", "2"):
        return int(raw)
    logger.warning("COMMENTS_MODE=%r не распознан (нужно 0, 1 или 2): комментарии скрыты (режим 0)", raw)
    return 0


COMMENTS_MODE = _parse_comments_mode(os.getenv("COMMENTS_MODE", "2"))
templates.env.globals["comments_mode"] = COMMENTS_MODE
logger.info("Comments mode: %s", COMMENTS_MODE)


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
        logger.warning("VT upstream HTTP %s: %s", response.status_code, response.text[:300])
        return "upstream_error", None, f"VirusTotal вернул HTTP {response.status_code}."
    except httpx.TimeoutException:
        return "timeout", None, "Таймаут при обращении к VirusTotal."
    except httpx.HTTPError as exc:
        logger.warning("VT network error: %s", exc)
        return "network_error", None, "Ошибка сети при обращении к VirusTotal."
    except Exception as exc:
        logger.exception("Unexpected VirusTotal error")
        return "internal_error", None, "Внутренняя ошибка сервиса."


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
        rows = build_history(db)

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
                    result_comments = comments_for(db, file_hash)
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
async def lookup(request: Request, hash_value: str = Form(..., max_length=128), refresh: str = Form("", max_length=8)):
    with SessionLocal() as db:
        cleanup_old_data(db)

        try:
            file_hash, algorithm = normalize_hash(hash_value)
        except ValueError as exc:
            return templates.TemplateResponse(
                "index.html",
                {"request": request, "rows": build_history(db), "result": None,
                 "error": str(exc), "hash_value": hash_value, "requests_per_hour": REQUESTS_PER_HOUR},
                status_code=400,
            )

        cached = db.scalar(
            select(HashRequest)
            .where(HashRequest.hash == file_hash, HashRequest.expires_at >= utcnow(), HashRequest.status == "ok")
            .order_by(HashRequest.requested_at.desc())
        )
        # Кэш не используем, если пользователь нажал «Обновить» или запись сохранена
        # старой версией приложения (в ней нет поля names: не было имён и метки угрозы).
        cached_result = None
        if cached and cached.result_json and not refresh:
            candidate = json.loads(cached.result_json)
            if "names" in candidate:
                cached_result = candidate

        if cached_result is not None:
            result = cached_result
            logger.info("Cache hit hash=%s", file_hash)
            return templates.TemplateResponse("index.html", {
                "request": request, "rows": build_history(db),
                "result": result, "error": None, "hash_value": file_hash,
                "result_hash": file_hash, "result_comments": comments_for(db, file_hash),
                "requests_per_hour": REQUESTS_PER_HOUR,
            })

        if not security.upstream_limiter.allow(security.client_ip(request)):
            return templates.TemplateResponse("index.html", {
                "request": request, "rows": build_history(db), "result": None,
                "error": "Слишком много обращений к VirusTotal с вашего адреса. Попробуйте через час.",
                "hash_value": file_hash, "requests_per_hour": REQUESTS_PER_HOUR,
            }, status_code=429)

        if not await acquire_rate_slot():
            logger.warning("Application rate limit reached hash=%s", file_hash)
            return templates.TemplateResponse("index.html", {
                "request": request, "rows": build_history(db), "result": None,
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

        return templates.TemplateResponse("index.html", {
            "request": request, "rows": build_history(db),
            "result": result, "error": error, "hash_value": file_hash,
            "result_hash": file_hash, "result_comments": comments_for(db, file_hash),
            "requests_per_hour": REQUESTS_PER_HOUR,
        })


@app.get("/comments", response_class=HTMLResponse)
def comments_page(request: Request):
    """Вкладка «Комментарии»: все комментарии с именем файла и счётчиком детектов."""
    if COMMENTS_MODE == 0:
        raise HTTPException(status_code=404, detail="Not Found")
    with SessionLocal() as db:
        cleanup_old_data(db)
        items = db.scalars(select(Comment).order_by(Comment.created_at.desc()).limit(MAX_HISTORY)).all()
        summaries = latest_summaries(db, {c.hash for c in items})
        entries = [
            {"author": c.author, "text": c.text, "created_at": c.created_at,
             "hash": c.hash, "summary": summaries.get(c.hash)}
            for c in items
        ]
    return templates.TemplateResponse("comments.html", {"request": request, "entries": entries})


@app.post("/comments")
def add_comment(
    hash_value: str = Form(...),
    text: str = Form(..., max_length=4000),
    author: str = Form("Anonymous", max_length=80),
    website: str = Form(""),          # honeypot: человек это поле не видит и не заполняет
):
    if COMMENTS_MODE != 2:
        raise HTTPException(status_code=403, detail="Добавление комментариев отключено.")
    if website:
        return RedirectResponse("/", status_code=303)   # бот: молча игнорируем
    try:
        file_hash, _ = normalize_hash(hash_value)
    except ValueError:
        return RedirectResponse("/", status_code=303)

    text = text.strip()[:4000]
    author = (author.strip() or "Anonymous")[:80]
    if text:
        with SessionLocal() as db:
            total = db.scalar(select(func.count()).select_from(Comment)) or 0
            per_hash = db.scalar(select(func.count()).select_from(Comment).where(Comment.hash == file_hash)) or 0
            if total >= MAX_COMMENTS_TOTAL or per_hash >= MAX_COMMENTS_PER_HASH:
                logger.warning("Comment cap reached hash=%s total=%s per_hash=%s", file_hash, total, per_hash)
                return RedirectResponse(f"/?hash={file_hash}", status_code=303)
            db.add(Comment(hash=file_hash, author=author, text=text, created_at=utcnow()))
            db.commit()
        logger.info("Comment added hash=%s author=%s", file_hash, author)
    return RedirectResponse(f"/?hash={file_hash}", status_code=303)
