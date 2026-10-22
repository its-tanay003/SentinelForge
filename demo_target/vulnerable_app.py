"""
Demo Target - Intentionally Vulnerable FastAPI App (Port 9000)
==========================================================================
⚠️  EDUCATIONAL USE ONLY - This app is INTENTIONALLY INSECURE.
    It is designed to demonstrate common web security vulnerabilities
    for the SentinelForge cybersecurity bootcamp.

    DO NOT deploy this in production or expose to the internet.
==========================================================================

Vulnerabilities included:
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- CORS wildcard with credentials enabled (CRS-001/CRS-002)
- Insecure cookies (no Secure, HttpOnly, SameSite flags)
- No HTTPS / TLS
- BOLA/IDOR: /api/users/{id} accessible without any authentication

Run: uvicorn demo_target.vulnerable_app:vulnerable_app --port 9000
"""
import uvicorn
from fastapi import FastAPI, Response, Cookie, Request
from fastapi.responses import JSONResponse, HTMLResponse
from typing import Optional

# ── Vulnerable App (port 9000) ────────────────────────────────────────────────
vulnerable_app = FastAPI(
    title="Demo Vulnerable App",
    description="⚠️ INTENTIONALLY INSECURE - For SentinelForge demo only",
    docs_url="/docs",
)

# Fake user database
USERS = {
    1: {"id": 1, "name": "Alice Admin", "email": "alice@example.com", "role": "admin", "ssn": "123-45-6789", "salary": 150000},
    2: {"id": 2, "name": "Bob User", "email": "bob@example.com", "role": "user", "ssn": "987-65-4321", "salary": 75000},
    3: {"id": 3, "name": "Carol Dev", "email": "carol@example.com", "role": "developer", "ssn": "555-12-3456", "salary": 95000},
}


@vulnerable_app.middleware("http")
async def add_insecure_headers(request, call_next):
    """Middleware that adds NO security headers (vulnerability demonstration)."""
    response = await call_next(request)
    # Intentionally NOT setting: CSP, HSTS, X-Frame-Options, etc.
    # Adding version disclosure (another vulnerability):
    response.headers["Server"] = "Python/3.11 uvicorn/0.24"
    response.headers["X-Powered-By"] = "FastAPI/0.104"
    return response


@vulnerable_app.get("/", response_class=HTMLResponse)
async def home(response: Response):
    """Home page - sets insecure cookies."""
    # Set cookies WITHOUT Secure, HttpOnly, or SameSite flags
    response.set_cookie(
        key="session",
        value="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjoyLCJyb2xlIjoidXNlciJ9.",
        # Missing: secure=True, httponly=True, samesite="Strict"
    )
    response.set_cookie(
        key="auth_token",
        value="secret-auth-token-12345",
        # Missing all security flags
    )
    return """<!DOCTYPE html>
<html>
<head><title>Vulnerable Demo App</title></head>
<body style="font-family:sans-serif;padding:40px;background:#1a1a2e;color:#e0e0e0">
  <h1>⚠️ Intentionally Vulnerable Demo App</h1>
  <p>This app is for SentinelForge security scanning demos.</p>
  <ul>
    <li>Port 9000: <strong>Vulnerable</strong> (this app)</li>
    <li>Port 9001: <strong>Hardened</strong> version</li>
  </ul>
  <h2>API Endpoints</h2>
  <ul>
    <li><a href="/api/users/1" style="color:#58a6ff">/api/users/1</a> - IDOR: No auth required</li>
    <li><a href="/api/users/2" style="color:#58a6ff">/api/users/2</a> - Access any user ID</li>
    <li><a href="/api/products" style="color:#58a6ff">/api/products</a> - Product listing</li>
  </ul>
</body>
</html>"""


@vulnerable_app.get("/api/users/{user_id}")
async def get_user_vulnerable(user_id: int):
    """
    INTENTIONAL VULNERABILITY: BOLA/IDOR
    No authentication or authorization check.
    Any user ID is accessible without any credentials.
    """
    user = USERS.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "User not found"})
    # Returns sensitive data without auth - IDOR vulnerability
    return user


@vulnerable_app.get("/api/users")
async def list_users_vulnerable():
    """Returns all users without authentication."""
    return list(USERS.values())


@vulnerable_app.get("/api/products")
async def get_products():
    return [
        {"id": 1, "name": "Widget A", "price": 9.99},
        {"id": 2, "name": "Widget B", "price": 19.99},
    ]


# ── Hardened App (port 9001) ──────────────────────────────────────────────────
hardened_app = FastAPI(
    title="Demo Hardened App",
    description="✅ Security-hardened version for comparison",
    docs_url="/docs",
)

# Simple auth tokens for demo
VALID_TOKENS = {"demo-token-alice": 1, "demo-token-bob": 2}


@hardened_app.middleware("http")
async def add_security_headers(request, call_next):
    """Adds comprehensive security headers."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Remove server disclosure
    if "server" in response.headers:
        del response.headers["server"]
    return response


@hardened_app.get("/", response_class=HTMLResponse)
async def home_hardened(response: Response):
    """Home page with secure cookies."""
    response.set_cookie(
        key="session",
        value="secure-session-token-xyz",
        secure=True,
        httponly=True,
        samesite="strict",
        max_age=3600,
    )
    return """<!DOCTYPE html>
<html>
<head>
<title>Hardened Demo App</title>
</head>
<body style="font-family:sans-serif;padding:40px;background:#0d1117;color:#e6edf3">
  <h1>✅ Hardened Demo App</h1>
  <p>This is the security-hardened version. Compare scan results with port 9000.</p>
  <p>Security headers, secure cookies, and authorization are all configured.</p>
</body>
</html>"""


@hardened_app.get("/api/users/{user_id}")
async def get_user_hardened(user_id: int, request: Request):
    """
    SECURE: Requires Authorization header and checks user ownership.
    Returns 401 if no auth token, 403 if accessing another user's data.
    """
    authorization = request.headers.get("authorization", "")
    if not authorization or not authorization.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"error": "Authentication required"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.replace("Bearer ", "")
    authenticated_user_id = VALID_TOKENS.get(token)

    if not authenticated_user_id:
        return JSONResponse(status_code=401, content={"error": "Invalid token"})

    # Authorization check: users can only access their own data
    if authenticated_user_id != user_id:
        return JSONResponse(
            status_code=403,
            content={"error": "Forbidden: Cannot access other users' data"}
        )

    user = USERS.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"error": "Not found"})

    # Return only non-sensitive fields
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        # SSN and salary NOT returned
    }


if __name__ == "__main__":
    import sys
    import threading

    def run_vulnerable():
        uvicorn.run(vulnerable_app, host="0.0.0.0", port=9000, log_level="warning")

    def run_hardened():
        uvicorn.run(hardened_app, host="0.0.0.0", port=9001, log_level="warning")

    print("Starting demo targets:")
    print("  🔴 Vulnerable app: http://localhost:9000")
    print("  🟢 Hardened  app:  http://localhost:9001")
    print("\n⚠️  For educational use only!")

    t1 = threading.Thread(target=run_vulnerable, daemon=True)
    t2 = threading.Thread(target=run_hardened, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
