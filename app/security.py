"""Защитные middleware и лимитеры для VT Hash Checker."""
import time
from collections import defaultdict, deque
from urllib.parse import urlparse

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

CSP = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    # same-origin, а не no-referrer: при no-referrer браузер шлёт «Origin: null»
    # на same-origin POST, и проверка Origin ниже отклонила бы обычные формы.
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


class SlidingWindowLimiter:
    """Скользящее окно в памяти: не более `limit` событий на ключ за `window` секунд."""

    def __init__(self, limit: int, window: float, max_keys: int = 10_000):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        if len(self._hits) > self.max_keys:  # защита от раздувания памяти
            self._purge(now)
        hits = self._hits[key]
        while hits and hits[0] <= now - self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False
        hits.append(now)
        return True

    def _purge(self, now: float) -> None:
        for k in [k for k, h in self._hits.items() if not h or h[-1] <= now - self.window]:
            del self._hits[k]


# Общие лимиты на POST-запросы с одного IP
comment_limiter = SlidingWindowLimiter(limit=5, window=600)    # 5 комментариев / 10 минут
lookup_limiter = SlidingWindowLimiter(limit=30, window=600)    # 30 проверок / 10 минут
# Лимит именно на обращения к VirusTotal (кэш-попадания его не тратят)
upstream_limiter = SlidingWindowLimiter(limit=5, window=3600)  # 5 запросов к VT / час


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def origin_is_same_site(request: Request) -> bool:
    """Защита от CSRF без токенов: форма должна быть отправлена с нашего же сайта.

    Браузеры всегда присылают Origin (или Sec-Fetch-Site) на межсайтовый POST.
    Клиенты без этих заголовков (curl, скрипты) браузерной CSRF-атаки не создают.
    """
    origin = request.headers.get("origin")
    if origin:
        return urlparse(origin).netloc == request.headers.get("host", "")
    fetch_site = request.headers.get("sec-fetch-site")
    if fetch_site:
        return fetch_site in ("same-origin", "none")
    return True


def install(app: FastAPI) -> None:
    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        if request.method == "POST":
            if not origin_is_same_site(request):
                return PlainTextResponse("Forbidden: cross-site request", status_code=403)
            limiter = {"/comments": comment_limiter, "/lookup": lookup_limiter}.get(request.url.path)
            if limiter and not limiter.allow(client_ip(request)):
                return PlainTextResponse(
                    "Слишком много запросов. Попробуйте позже.",
                    status_code=429,
                    headers={"Retry-After": "600"},
                )
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response
