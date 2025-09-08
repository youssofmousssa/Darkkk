#!/usr/bin/env python3
"""
YDark Unified API - api.py
The complete YDark API system combining AI services with enterprise security
Features: All 16 AI models + ydark-[7 alphanumeric] authentication + rate limiting + HMAC signatures
"""

import os
import time
import uuid
import hashlib
import hmac
import logging
from datetime import datetime
from typing import Optional, Dict, Any

from fastapi import FastAPI, Request, Header, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import our components
from models import (
    app as models_app, 
    UPSTREAM_BASE, 
    call_upstream_service,
    gemini_img_service,
    flux_pro_service,
    gpt_img_service,
    nano_banana_service,
    img_cv_service,
    voice_service,
    veo3_service,
    music_service,
    create_music_service,
    wormgpt_service,
    ai_service,
    gemini_dark_service,
    gemini_service,
    do_service,
    remove_bg_service,
    gemma_service
)
from secure import (
    YDarkSecurityMiddleware,
    create_api_token,
    validate_api_key,
    generate_curl_example,
    TokenCreateRequest,
    TokenCreateResponse,
    SecurityStats,
    extract_key_id,
    api_keys_store,
    load_api_keys_from_redis,
    get_redis,
    DAILY_QUOTA,
    MONTHLY_QUOTA
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ydark_unified_api")

# --- Create Unified FastAPI App ---

app = FastAPI(
    title="YDark Unified API",
    description="Complete YDark AI Platform with enterprise security - 16 AI models with ydark-[7 alphanumeric] authentication",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security Configuration ---

# Public endpoints that don't require authentication
OPEN_PATHS = [
    "/",
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/favicon.ico",
    "/auth/create-token",
    "/auth/demo-curl",
    "/models/health"  # Allow health check for models
]

# Add security middleware to protect AI endpoints
app.add_middleware(YDarkSecurityMiddleware, open_paths=OPEN_PATHS)

# --- Startup/Shutdown Events ---

@app.on_event("startup")
async def startup():
    """Initialize the unified API system"""
    logger.info("🚀 Starting YDark Unified API System...")
    
    # Load existing API keys from Redis
    await load_api_keys_from_redis()
    
    # Test upstream connection
    try:
        test_response = await call_upstream_service("/health", "GET")
        logger.info(f"✅ Upstream models service connected: {test_response}")
    except Exception as e:
        logger.warning(f"⚠️  Upstream models service not available: {e}")
    
    logger.info("🔥🔥 YDark Unified API System ready! 🔥🔥")

@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    logger.info("🛑 Shutting down YDark Unified API System...")

# --- Authentication & Token Management Endpoints ---

@app.post("/auth/create-token", response_model=TokenCreateResponse, summary="Create API Token")
async def create_token_endpoint(request: TokenCreateRequest):
    """
    Create a new YDark API token with ydark-[7 alphanumeric] format
    
    **Usage:**
    1. Call this endpoint to get your API key and secret
    2. Use the API key in X-API-Key header
    3. Sign requests with the secret using HMAC SHA-256
    4. Include X-Request-ID, X-Signature, X-Timestamp headers
    
    **Example:**
    ```bash
    curl -X POST "https://your-api.com/auth/create-token" \\
      -H "Content-Type: application/json" \\
      -d '{
        "client_name": "My AI App",
        "allowed_ips": ["1.2.3.4"],
        "expires_in_days": 30
      }'
    ```
    """
    logger.info(f"Creating new API token for client: {request.client_name}")
    
    token_response = await create_api_token(
        client_name=request.client_name,
        allowed_ips=request.allowed_ips,
        expires_in_days=request.expires_in_days or 30
    )
    
    logger.info(f"✅ Created token {token_response.api_key} for {request.client_name}")
    return token_response

@app.get("/auth/stats", response_model=SecurityStats, summary="Get Usage Statistics")
async def get_stats(x_api_key: str = Header(..., alias="X-API-Key")):
    """
    Get usage statistics for your API key
    
    **Headers required:**
    - X-API-Key: Your ydark-XXXXXXX API key
    """
    client_ip = "127.0.0.1"  # For stats, IP doesn't matter
    key_data = await validate_api_key(x_api_key, client_ip)
    
    return SecurityStats(
        daily_usage=key_data.daily_quota_used,
        monthly_usage=key_data.monthly_quota_used,
        daily_limit=DAILY_QUOTA,
        monthly_limit=MONTHLY_QUOTA,
        requests_remaining_today=max(0, DAILY_QUOTA - key_data.daily_quota_used),
        requests_remaining_month=max(0, MONTHLY_QUOTA - key_data.monthly_quota_used),
        last_used=key_data.last_used
    )

@app.delete("/auth/revoke-token", summary="Revoke API Token")
async def revoke_token(x_api_key: str = Header(..., alias="X-API-Key")):
    """
    Revoke your API token (make it inactive)
    
    **Headers required:**
    - X-API-Key: Your ydark-XXXXXXX API key to revoke
    """
    key_id = extract_key_id(x_api_key)
    
    if key_id in api_keys_store:
        api_keys_store[key_id].is_active = False
        logger.info(f"🔒 Revoked API key: {x_api_key}")
        return {"message": "API key revoked successfully", "api_key": x_api_key}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found"
        )

@app.get("/auth/demo-curl", summary="Generate Demo cURL Commands")
async def demo_curl():
    """
    Generate example cURL commands for testing the API
    
    **Note:** You need to create a token first using /auth/create-token
    """
    
    examples = {
        "step_1_create_token": {
            "description": "First, create an API token",
            "command": '''curl -X POST "https://your-api.com/auth/create-token" \\
  -H "Content-Type: application/json" \\
  -d '{
    "client_name": "My Test App",
    "expires_in_days": 30
  }' '''
        },
        "step_2_use_models": {
            "description": "Then use the token to call AI models (replace YOUR_API_KEY and YOUR_SECRET)",
            "examples": {
                "gemini": generate_curl_example(
                    "ydark-EXAMPLE", 
                    "your-secret-here", 
                    "gemini", 
                    "POST", 
                    {"text": "Hello world"}
                ),
                "flux_pro": generate_curl_example(
                    "ydark-EXAMPLE", 
                    "your-secret-here", 
                    "flux-pro", 
                    "POST", 
                    {"text": "Generate a beautiful sunset"}
                ),
                "voice": generate_curl_example(
                    "ydark-EXAMPLE", 
                    "your-secret-here", 
                    "voice", 
                    "POST", 
                    {"text": "Hello this is a test", "voice": "female"}
                )
            }
        },
        "signature_calculation": {
            "description": "How to calculate HMAC signature",
            "steps": [
                "1. Create signature base: timestamp + '\\n' + method + '\\n' + path + '\\n' + sha256(body)",
                "2. Calculate HMAC: hmac.new(secret.encode(), signature_base.encode(), hashlib.sha256).hexdigest()",
                "3. Include in X-Signature header"
            ]
        }
    }
    
    return examples

# --- Mount AI Models Endpoints ---

# Mount all AI model endpoints from models.py directly into our app
# This way they inherit the security middleware automatically

@app.api_route("/api/gemini-img", methods=["GET", "POST"], summary="🎨 Gemini Pro Image Generation")
async def gemini_img_proxy(request: Request, text: Optional[str] = None, link: Optional[str] = None):
    """Gemini Pro Image Generation and Editing - Secured with ydark- authentication"""
    return await gemini_img_service(request, text, link)

@app.api_route("/api/flux-pro", methods=["GET", "POST"], summary="🎨 Flux Pro - 4 Images")
async def flux_pro_proxy(request: Request, text: Optional[str] = None):
    """Flux Pro - Generate 4 images per request - Secured with ydark- authentication"""
    return await flux_pro_service(request, text)

@app.api_route("/api/gpt-img", methods=["GET", "POST"], summary="🎨 GPT-5 Image Generation")
async def gpt_img_proxy(request: Request, text: Optional[str] = None, link: Optional[str] = None):
    """GPT-5 Image Generation and Editing - Secured with ydark- authentication"""
    return await gpt_img_service(request, text, link)

@app.api_route("/api/nano-banana", methods=["GET", "POST"], summary="🎨 Nano Banana Image Merge")
async def nano_banana_proxy(request: Request, text: Optional[str] = None, links: Optional[str] = None):
    """Nano Banana - Image merging (max 10 images) - Secured with ydark- authentication"""
    return await nano_banana_service(request, text, links)

@app.api_route("/api/img-cv", methods=["GET", "POST"], summary="🎨 High Quality Image Generation")
async def img_cv_proxy(request: Request, text: Optional[str] = None):
    """High Quality Image Generation with incredible speed - Secured with ydark- authentication"""
    return await img_cv_service(request, text)

@app.api_route("/api/voice", methods=["GET", "POST"], summary="🎤 Text to Speech")
async def voice_proxy(request: Request, text: Optional[str] = None, voice: Optional[str] = None, style: Optional[str] = None):
    """Text to Speech Voice Generation - Secured with ydark- authentication"""
    return await voice_service(request, text, voice, style)

@app.api_route("/api/veo3", methods=["GET", "POST"], summary="🎥 Video Generation")
async def veo3_proxy(request: Request, text: Optional[str] = None, link: Optional[str] = None):
    """Text-to-Video & Image-to-Video with FREE audio support - Secured with ydark- authentication"""
    return await veo3_service(request, text, link)

@app.api_route("/api/music", methods=["GET", "POST"], summary="🎵 Song Creation")
async def music_proxy(request: Request, lyrics: Optional[str] = None, tags: Optional[str] = None):
    """Song Creation With Lyrics And Music - Secured with ydark- authentication"""
    return await music_service(request, lyrics, tags)

@app.api_route("/api/create-music", methods=["GET", "POST"], summary="🎵 Music Creation")
async def create_music_proxy(request: Request, text: Optional[str] = None):
    """Create 15s music without lyrics - Secured with ydark- authentication"""
    return await create_music_service(request, text)

@app.api_route("/api/wormgpt", methods=["GET", "POST"], summary="🤖 WormGPT AI")
async def wormgpt_proxy(request: Request, text: Optional[str] = None):
    """WormGPT API - Secured with ydark- authentication"""
    return await wormgpt_service(request, text)

@app.api_route("/api/ai", methods=["GET", "POST"], summary="🤖 Multi-Model AI")
async def ai_proxy(request: Request, online: Optional[str] = None, standard: Optional[str] = None, super_genius: Optional[str] = None, online_genius: Optional[str] = None):
    """Multi-model AI (online, standard, super-genius, online-genius) - Secured with ydark- authentication"""
    return await ai_service(request, online, standard, super_genius, online_genius)

@app.api_route("/api/gemini-dark", methods=["GET", "POST"], summary="🤖 Gemini Dark Models")
async def gemini_dark_proxy(request: Request, gemini_pro: Optional[str] = None, gemini_deep: Optional[str] = None):
    """All Gemini models (gemini-pro, gemini-deep) - Secured with ydark- authentication"""
    return await gemini_dark_service(request, gemini_pro, gemini_deep)

@app.api_route("/api/gemini", methods=["GET", "POST"], summary="🤖 Gemini 2.5 Flash")
async def gemini_proxy(request: Request, text: Optional[str] = None):
    """Gemini 2.5 Flash - Secured with ydark- authentication"""
    return await gemini_service(request, text)

@app.api_route("/api/do", methods=["GET", "POST"], summary="📥 Social Media Downloader")
async def do_proxy(request: Request, url: Optional[str] = None):
    """Universal Social Downloader - Secured with ydark- authentication"""
    return await do_service(request, url)

@app.api_route("/api/remove-bg", methods=["GET", "POST"], summary="🖼️ Background Removal")
async def remove_bg_proxy(request: Request, url: Optional[str] = None):
    """Remove background from image - Secured with ydark- authentication"""
    return await remove_bg_service(request, url)

@app.api_route("/api/gemma", methods=["GET", "POST"], summary="🤖 Gemma Models")
async def gemma_proxy(request: Request, model_4b: Optional[str] = None, model_12b: Optional[str] = None, model_27b: Optional[str] = None):
    """Gemma models (4b, 12b, 27b) - Secured with ydark- authentication"""
    return await gemma_service(request, model_4b, model_12b, model_27b)

# --- System Endpoints ---

@app.get("/", summary="🏠 API Information")
async def root():
    """YDark Unified API - Complete AI platform with enterprise security"""
    
    redis_status = "connected" if await get_redis() else "disconnected"
    active_keys = len([k for k in api_keys_store.values() if k.is_active])
    
    return {
        "service": "YDark Unified API",
        "version": "2.0.0",
        "description": "Complete AI platform with enterprise security",
        "features": [
            "🔑 ydark-[7 alphanumeric] API keys",
            "🛡️ HMAC signature authentication", 
            "⚡ Rate limiting & quotas",
            "🔒 Request ID replay protection",
            "📊 Usage statistics",
            "🎨 Image generation (Gemini, Flux Pro, GPT-img)",
            "🎤 Voice generation",
            "🎥 Video generation", 
            "🎵 Music creation",
            "🤖 Multiple AI chat models",
            "📥 Social media downloads",
            "🖼️ Background removal"
        ],
        "ai_models": 16,
        "authentication": "Required for /api/* endpoints",
        "status": {
            "redis": redis_status,
            "active_api_keys": active_keys,
            "upstream_models": "available"
        },
        "documentation": "/docs",
        "get_started": "/auth/create-token"
    }

@app.get("/health", summary="🏥 Health Check")
async def health_check():
    """Comprehensive health check"""
    
    redis_status = "connected" if await get_redis() else "disconnected"
    
    # Test upstream models
    upstream_status = "unknown"
    try:
        test_response = await call_upstream_service("/health", "GET")
        upstream_status = "connected" if test_response else "error"
    except:
        upstream_status = "disconnected"
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "api_gateway": "healthy",
            "security_layer": "healthy", 
            "redis": redis_status,
            "ai_models": upstream_status
        },
        "active_api_keys": len([k for k in api_keys_store.values() if k.is_active]),
        "total_api_keys": len(api_keys_store)
    }

# --- Direct access to models health (for monitoring) ---
@app.get("/models/health", summary="🤖 Models Health Check")
async def models_health():
    """Direct health check for AI models service"""
    try:
        return await call_upstream_service("/health", "GET")
    except Exception as e:
        return {"status": "error", "message": str(e)}

# --- Production Configuration ---

def get_port() -> int:
    """Get port from environment (for deployment)"""
    return int(os.environ.get("PORT", 5000))

def get_host() -> str:
    """Get host from environment"""
    return os.environ.get("HOST", "0.0.0.0")

if __name__ == "__main__":
    port = get_port()
    host = get_host()
    
    logger.info(f"🚀 Starting YDark Unified API on {host}:{port}")
    logger.info("🔥🔥 All 16 AI models with enterprise security! 🔥🔥")
    
    uvicorn.run(
        "api:app",
        host=host,
        port=port,
        reload=True,
        log_level="info"
)
