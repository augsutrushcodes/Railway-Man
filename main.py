import base64
import hashlib
import json
import os
import secrets
import time
import requests
from fastapi import FastAPI, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse

GEMINI_KEY = os.environ.get("GEMINI_KEY", "")
GEMINI_MODEL = "gemini-3-pro-image-preview"
BASE_URL = os.environ.get("BASE_URL", "https://celebrated-consideration-production-e2bb.up.railway.app")

# In-memory stores (fine for single instance)
auth_codes = {}   # code -> {client_id, redirect_uri, code_challenge, expires}
tokens = {}       # token -> {client_id, expires}

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── 1. DISCOVERY ───────────────────────────────────────────────────────────
@app.get("/.well-known/oauth-authorization-server")
def discovery():
    return {
        "issuer": BASE_URL,
        "authorization_endpoint": BASE_URL + "/authorize",
        "token_endpoint": BASE_URL + "/token",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"]
    }

# ── 2. AUTHORIZE — shows consent page, stores PKCE challenge ───────────────
@app.get("/authorize")
async def authorize(request: Request):
    p = dict(request.query_params)
    client_id = p.get("client_id", "")
    redirect_uri = p.get("redirect_uri", "")
    code_challenge = p.get("code_challenge", "")
    state = p.get("state", "")

    # Validate redirect URI
    allowed = [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.ai/api/auth/callback"
    ]
    if redirect_uri not in allowed:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)

    if not code_challenge:
        return JSONResponse({"error": "code_challenge required"}, status_code=400)

    # Generate auth code
    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "expires": time.time() + 300
    }

    # Show consent page
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NB Pro Studio</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ background: #0a0a0a; color: #f0f0f0; font-family: -apple-system, sans-serif;
           min-height: 100vh; display: flex; align-items: center; justify-content: center; }}
    .card {{ background: #111; border: 1px solid #222; border-radius: 12px;
             padding: 40px 32px; max-width: 380px; width: 90%; text-align: center; }}
    .logo {{ color: #e8ff47; font-size: 13px; letter-spacing: 0.2em; font-weight: bold;
             font-family: monospace; margin-bottom: 8px; }}
    .subtitle {{ color: #555; font-size: 12px; font-family: monospace; margin-bottom: 32px; }}
    h2 {{ font-size: 20px; margin-bottom: 12px; }}
    p {{ color: #888; font-size: 14px; line-height: 1.6; margin-bottom: 32px; }}
    .btn {{ display: block; width: 100%; padding: 14px;
            background: #e8ff47; color: #000; font-weight: bold;
            font-size: 15px; border-radius: 8px; text-decoration: none;
            transition: background 0.15s; }}
    .btn:hover {{ background: #d4eb30; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">NB PRO STUDIO</div>
    <div class="subtitle">gemini-3-pro-image-preview</div>
    <h2>Connect to Claude</h2>
    <p>Allow Claude to generate images using NB Pro directly in your chat.</p>
    <a class="btn" href="{redirect_uri}?code={code}&state={state}">Authorize</a>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html)

# ── 3. TOKEN — verifies PKCE S256, returns access token ───────────────────
@app.post("/token")
async def token(request: Request):
    ct = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in ct:
        form = await request.form()
        data = dict(form)
    else:
        data = await request.json()

    grant_type = data.get("grant_type")
    code = data.get("code")
    code_verifier = data.get("code_verifier", "")
    redirect_uri = data.get("redirect_uri", "")

    if grant_type == "refresh_token":
        token_val = secrets.token_urlsafe(32)
        tokens[token_val] = {"expires": time.time() + 86400 * 30}
        return JSONResponse({
            "access_token": token_val,
            "token_type": "bearer",
            "expires_in": 86400 * 30,
            "refresh_token": secrets.token_urlsafe(32)
        })

    if not code or code not in auth_codes:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)

    stored = auth_codes.pop(code)

    if time.time() > stored["expires"]:
        return JSONResponse({"error": "code_expired"}, status_code=400)

    # Verify PKCE S256
    digest = hashlib.sha256(code_verifier.encode()).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    if computed != stored["code_challenge"]:
        return JSONResponse({"error": "invalid_code_verifier"}, status_code=400)

    access_token = secrets.token_urlsafe(32)
    refresh_token = secrets.token_urlsafe(32)
    tokens[access_token] = {"expires": time.time() + 3600}

    return JSONResponse({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "refresh_token": refresh_token
    })

# ── 4. MCP ENDPOINT — JSON-RPC with Bearer auth ────────────────────────────
@app.post("/mcp")
async def mcp(request: Request):
    # Verify bearer token
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token_val = auth[7:]
        if token_val not in tokens:
            return JSONResponse({"error": "invalid_token"}, status_code=401)
    elif auth.startswith("Basic "):
        pass  # allow basic auth for dev/testing
    else:
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    body = await request.json()
    method = body.get("method")
    req_id = body.get("id", 1)

    # tools/list
    if method == "tools/list":
        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "tools": [{
                    "name": "generate_image",
                    "description": "Generate or edit an image using NB Pro (gemini-3-pro-image-preview). Use this whenever the user wants to create or edit any image.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "prompt": {"type": "string", "description": "Detailed image generation prompt"},
                            "ref_image_b64": {"type": "string", "description": "Optional base64 reference image"},
                            "ref_mime": {"type": "string", "default": "image/jpeg"}
                        },
                        "required": ["prompt"]
                    }
                }]
            }
        })

    # tools/call
    if method == "tools/call":
        params = body.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        if tool_name != "generate_image":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": "Tool not found"}})

        try:
            prompt = args.get("prompt", "")
            ref_b64 = args.get("ref_image_b64")
            ref_mime = args.get("ref_mime", "image/jpeg")

            parts = []
            if ref_b64:
                parts.append({"inline_data": {"mime_type": ref_mime, "data": ref_b64}})
            parts.append({"text": prompt})

            gemini_body = {
                "contents": [{"role": "user", "parts": parts}],
                "generationConfig": {"responseModalities": ["TEXT", "IMAGE"]}
            }

            url = ("https://generativelanguage.googleapis.com/v1beta/models/"
                   + GEMINI_MODEL + ":generateContent?key=" + GEMINI_KEY)

            r = requests.post(url, json=gemini_body, timeout=90)
            r.raise_for_status()
            data = r.json()

            for candidate in data.get("candidates", []):
                for part in candidate.get("content", {}).get("parts", []):
                    idata = part.get("inline_data", {})
                    if idata.get("mime_type", "").startswith("image/"):
                        return JSONResponse({
                            "jsonrpc": "2.0", "id": req_id,
                            "result": {
                                "content": [{
                                    "type": "image",
                                    "data": idata["data"],
                                    "mimeType": idata["mime_type"]
                                }]
                            }
                        })

            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": "No image returned from Gemini."}]}
            })

        except Exception as e:
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32000, "message": str(e)}
            })

    # initialize handshake
    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "NB Pro Studio", "version": "1.0.0"}
            }
        })

    return JSONResponse({
        "jsonrpc": "2.0", "id": req_id,
        "error": {"code": -32601, "message": "Method not found"}
    })

# ── HEALTH ─────────────────────────────────────────────────────────────────
@app.get("/ping")
def ping():
    return {"status": "live", "model": GEMINI_MODEL}

@app.get("/")
def root():
    return {"status": "NB Pro MCP Server", "model": GEMINI_MODEL}


# ── GET /mcp — SSE stream handler (Claude polls this after OAuth) ───────────
from fastapi.responses import StreamingResponse
import asyncio

@app.get("/mcp")
async def mcp_get(request: Request):
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        token_val = auth[7:]
        if token_val not in tokens:
            return JSONResponse({"error": "invalid_token"}, status_code=401,
                headers={"WWW-Authenticate": f'Bearer realm="{BASE_URL}"'})

    async def event_stream():
        yield "data: {}\n\n"
        await asyncio.sleep(30)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )
