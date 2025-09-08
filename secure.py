#!/usr/bin/env python3
"""
YDark Security Layer - secure.py
Implements comprehensive API security for YDark services
Features: ydark-[7 alphanumeric] API keys, request validation, rate limiting, HMAC signing
"""

import os
import time
import uuid
import hmac
import hashlib
import logging
import asyncio
import random
import string
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, Request, Header, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import redis.asyncio as redis
from starlette.middleware.base import BaseHTTPMiddleware

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ydark_security")

# --- Security Configuration ---

API_KEY_SECRET = os.getenv("API_KEY_SECRET", "ydark-super-secret-hmac-key-2024")
API_KEY_LENGTH = 7  # 7 alphanumeric characters after "ydark-"
API_KEY_PREFIX = "ydark-"

# Request protection
REQUEST_ID_TTL_SECONDS = 300  # 5 minutes TTL for request ID dedupe
HMAC_TIMESTAMP_SKEW = 120  # seconds allowed clock skew for signatures
MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MB max body size

# Rate limiting configuration
RATE_LIMIT_RPS = int(os.getenv("RATE_LIMIT_RPS", "100"))  # requests per second
RATE_LIMIT_BURST = int(os.getenv("RATE_LIMIT_BURST", "300"))  # burst capacity
DAILY_QUOTA = int(os.getenv("DAILY_QUOTA", "10000"))
MONTHLY_QUOTA = int(os.getenv("MONTHLY_QUOTA", "300000"))

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Token expiration
TOKEN_EXPIRE_DAYS = int(os.getenv("TOKEN_EXPIRE_DAYS", "30"))

# Global Redis client
redis_client: Optional[redis.Redis] = None

# --- Data Models ---

class APIKeyData(BaseModel):
    """API Key data structure"""
    key_id: str = Field(..., description="The key identifier (without ydark- prefix)")
    client_name: str = Field(..., description="Client application name")
    secret: str = Field(..., description="HMAC secret for signing")
    allowed_ips: Optional[List[str]] = Field(default=None, description="Whitelisted IPs")
    is_active: bool = Field(default=True, description="Whether key is active")
    daily_quota_used: int = Field(default=0, description="Daily usage count")
    monthly_quota_used: int = Field(default=0, description="Monthly usage count")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(..., description="Token expiration time")
    last_used: Optional[datetime] = Field(default=None, description="Last usage timestamp")

class TokenCreateRequest(BaseModel):
    """Request model for creating API tokens"""
    client_name: str = Field(..., min_length=1, max_length=100)
    allowed_ips: Optional[List[str]] = Field(default=None)
    expires_in_days: Optional[int] = Field(default=30, ge=1, le=365)

class TokenCreateResponse(BaseModel):
    """Response model for token creation"""
    api_key: str = Field(..., description="The full API key (ydark-XXXXXXX)")
    secret: str = Field(..., description="HMAC secret for signing requests")
    expires_at: datetime = Field(..., description="Token expiration time")
    client_name: str = Field(..., description="Client application name")

class SecurityStats(BaseModel):
    """Security statistics response"""
    daily_usage: int
    monthly_usage: int
    daily_limit: int
    monthly_limit: int
    requests_remaining_today: int
    requests_remaining_month: int
    last_used: Optional[datetime]

# --- API Key Store (In-memory with Redis backup) ---

api_keys_store: Dict[str, APIKeyData] = {}

# --- Utility Functions ---

def generate_api_key_id() -> str:
    """Generate a 7-character alphanumeric key ID"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(API_KEY_LENGTH))

def generate_hmac_secret() -> str:
    """Generate a secure HMAC secret"""
    return hashlib.sha256(str(uuid.uuid4()).encode() + str(time.time()).encode()).hexdigest()

def create_full_api_key(key_id: str) -> str:
    """Create full API key with ydark- prefix"""
    return f"{API_KEY_PREFIX}{key_id}"

def extract_key_id(api_key: str) -> str:
    """Extract key ID from full API key"""
    if api_key.startswith(API_KEY_PREFIX):
        return api_key[len(API_KEY_PREFIX):]
    return api_key

def verify_hmac_signature(secret: str, signature: str, timestamp: str, method: str, path: str, body: bytes) -> bool:
    """
    Verify HMAC_SHA256 signature for request integrity.
    Signature base: timestamp + '\n' + method + '\n' + path + '\n' + sha256(body)
    """
    try:
        body_hash = hashlib.sha256(body if body else b'').hexdigest()
        signature_base = f"{timestamp}\n{method.upper()}\n{path}\n{body_hash}".encode()
        computed_hmac = hmac.new(secret.encode(), signature_base, hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed_hmac, signature)
    except Exception as e:
        logger.error(f"HMAC signature verification error: {e}")
        return False

async def get_redis() -> Optional[redis.Redis]:
    """Get Redis client instance"""
    global redis_client
    if redis_client is None:
        try:
            redis_client = redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
            await redis_client.ping()
            logger.info("Redis connected successfully")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            redis_client = None
    return redis_client

async def load_api_keys_from_redis():
    """Load API keys from Redis on startup"""
    try:
        redis_inst = await get_redis()
        if redis_inst:
            keys = await redis_inst.keys("api_key:*")
            for key in keys:
                key_data = await redis_inst.get(key)
                if key_data:
                    key_id = key.split(":")[-1]
                    api_keys_store[key_id] = APIKeyData.parse_raw(key_data)
            logger.info(f"Loaded {len(api_keys_store)} API keys from Redis")
    except Exception as e:
        logger.error(f"Failed to load API keys from Redis: {e}")

async def save_api_key_to_redis(key_data: APIKeyData):
    """Save API key to Redis"""
    try:
        redis_inst = await get_redis()
        if redis_inst:
            await redis_inst.set(
                f"api_key:{key_data.key_id}",
                key_data.json(),
                ex=int((key_data.expires_at - datetime.utcnow()).total_seconds())
            )
    except Exception as e:
        logger.error(f"Failed to save API key to Redis: {e}")

# --- Security Functions ---

async def create_api_token(client_name: str, allowed_ips: Optional[List[str]] = None, expires_in_days: int = 30) -> TokenCreateResponse:
    """Create a new API token with ydark-[7 alphanumeric] format"""
    
    # Generate unique key ID
    key_id = generate_api_key_id()
    while key_id in api_keys_store:
        key_id = generate_api_key_id()
    
    # Generate HMAC secret
    secret = generate_hmac_secret()
    
    # Create expiration time
    expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    
    # Create API key data
    api_key_data = APIKeyData(
        key_id=key_id,
        client_name=client_name,
        secret=secret,
        allowed_ips=allowed_ips,
        expires_at=expires_at
    )
    
    # Store in memory and Redis
    api_keys_store[key_id] = api_key_data
    await save_api_key_to_redis(api_key_data)
    
    full_api_key = create_full_api_key(key_id)
    
    logger.info(f"Created new API key for client: {client_name}, key: {full_api_key}")
    
    return TokenCreateResponse(
        api_key=full_api_key,
        secret=secret,
        expires_at=expires_at,
        client_name=client_name
    )

async def validate_api_key(api_key: str, client_ip: str) -> APIKeyData:
    """Validate API key and return key data"""
    
    if not api_key or not api_key.startswith(API_KEY_PREFIX):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key format. Expected format: ydark-XXXXXXX"
        )
    
    key_id = extract_key_id(api_key)
    
    # Check if key exists
    key_data = api_keys_store.get(key_id)
    if not key_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
    
    # Check if key is active
    if not key_data.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked"
        )
    
    # Check expiration
    if datetime.utcnow() > key_data.expires_at:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired"
        )
    
    # Check IP whitelist
    if key_data.allowed_ips and client_ip not in key_data.allowed_ips:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="IP address not allowed for this API key"
        )
    
    return key_data

async def check_rate_limit(key_data: APIKeyData, client_ip: str) -> bool:
    """Check rate limiting for API key and IP"""
    try:
        redis_inst = await get_redis()
        if not redis_inst:
            logger.warning("Redis unavailable for rate limiting")
            return True  # Fail open
        
        current_second = int(time.time())
        
        # Per-second rate limiting
        api_key_rl_key = f"ratelimit:{key_data.key_id}:{current_second}"
        api_key_ip_rl_key = f"ratelimit:{key_data.key_id}:{client_ip}:{current_second}"
        
        # Increment counters
        count = await redis_inst.incr(api_key_rl_key)
        if count == 1:
            await redis_inst.expire(api_key_rl_key, 2)
        
        count_ip = await redis_inst.incr(api_key_ip_rl_key)
        if count_ip == 1:
            await redis_inst.expire(api_key_ip_rl_key, 2)
        
        # Check limits
        if count > RATE_LIMIT_RPS or count_ip > RATE_LIMIT_RPS:
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Rate limiting error: {e}")
        return True  # Fail open

async def check_request_id_replay(request_id: str) -> bool:
    """Check if request ID has been used before (replay attack protection)"""
    try:
        redis_inst = await get_redis()
        if not redis_inst:
            logger.warning("Redis unavailable for replay protection")
            return True  # Fail open
        
        request_id_key = f"request_id:{request_id}"
        
        # Check if already exists
        if await redis_inst.get(request_id_key):
            return False  # Request ID already used
        
        # Store request ID with TTL
        await redis_inst.set(request_id_key, "1", ex=REQUEST_ID_TTL_SECONDS)
        return True
        
    except Exception as e:
        logger.error(f"Request ID replay check error: {e}")
        return True  # Fail open

async def update_usage_stats(key_data: APIKeyData):
    """Update daily and monthly usage statistics"""
    try:
        # Update in-memory store
        key_data.daily_quota_used += 1
        key_data.monthly_quota_used += 1
        key_data.last_used = datetime.utcnow()
        
        # Update in Redis
        await save_api_key_to_redis(key_data)
        
        # Check quotas
        if key_data.daily_quota_used > DAILY_QUOTA:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Daily quota exceeded"
            )
        
        if key_data.monthly_quota_used > MONTHLY_QUOTA:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Monthly quota exceeded"
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Usage stats update error: {e}")

# --- Security Middleware ---

class YDarkSecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for YDark API"""
    
    def __init__(self, app, open_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.open_paths = open_paths or [
            "/",
            "/health",
            "/docs",
            "/openapi.json",
            "/redoc",
            "/favicon.ico"
        ]
    
    async def dispatch(self, request: Request, call_next):
        # Skip security for open paths
        if request.url.path in self.open_paths:
            return await call_next(request)
        
        try:
            # Extract required headers
            x_api_key = request.headers.get("X-API-Key")
            x_request_id = request.headers.get("X-Request-ID")
            x_signature = request.headers.get("X-Signature")
            x_timestamp = request.headers.get("X-Timestamp")
            client_ip = request.client.host if request.client else "unknown"
            
            # Validate required headers
            if not x_api_key:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Missing X-API-Key header", "code": "MISSING_API_KEY"}
                )
            
            if not x_request_id:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Missing X-Request-ID header", "code": "MISSING_REQUEST_ID"}
                )
            
            if not x_signature:
                return JSONResponse(
                    status_code=401,
                    content={"error": "Missing X-Signature header", "code": "MISSING_SIGNATURE"}
                )
            
            if not x_timestamp:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Missing X-Timestamp header", "code": "MISSING_TIMESTAMP"}
                )
            
            # Validate timestamp
            try:
                ts_int = int(x_timestamp)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Invalid X-Timestamp format", "code": "INVALID_TIMESTAMP"}
                )
            
            now = int(time.time())
            if abs(now - ts_int) > HMAC_TIMESTAMP_SKEW:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Request timestamp out of allowed range", "code": "TIMESTAMP_SKEW"}
                )
            
            # Validate API key
            key_data = await validate_api_key(x_api_key, client_ip)
            
            # Check request ID replay
            if not await check_request_id_replay(x_request_id):
                return JSONResponse(
                    status_code=409,
                    content={"error": "Duplicate request ID detected", "code": "DUPLICATE_REQUEST_ID"}
                )
            
            # Read body for signature verification
            body_bytes = await request.body()
            if len(body_bytes) > MAX_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request body too large", "code": "BODY_TOO_LARGE"}
                )
            
            # Verify HMAC signature
            if not verify_hmac_signature(
                secret=key_data.secret,
                signature=x_signature,
                timestamp=x_timestamp,
                method=request.method,
                path=request.url.path,
                body=body_bytes
            ):
                return JSONResponse(
                    status_code=401,
                    content={"error": "Invalid HMAC signature", "code": "INVALID_SIGNATURE"}
                )
            
            # Check rate limiting
            if not await check_rate_limit(key_data, client_ip):
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded", 
                        "code": "RATE_LIMIT_EXCEEDED",
                        "retry_after": 1
                    },
                    headers={"Retry-After": "1"}
                )
            
            # Update usage statistics
            await update_usage_stats(key_data)
            
            # Reset request body for downstream processing
            async def receive():
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            request._receive = receive
            
            # Attach security context to request
            request.state.api_key_data = key_data
            request.state.client_ip = client_ip
            request.state.request_id = x_request_id
            
            # Process request
            response = await call_next(request)
            
            # Add security headers to response
            response.headers["X-Request-ID"] = x_request_id
            response.headers["X-RateLimit-Remaining"] = str(RATE_LIMIT_RPS - key_data.daily_quota_used % RATE_LIMIT_RPS)
            response.headers["X-Daily-Quota-Remaining"] = str(max(0, DAILY_QUOTA - key_data.daily_quota_used))
            
            return response
            
        except HTTPException as e:
            return JSONResponse(
                status_code=e.status_code,
                content={"error": e.detail, "code": "SECURITY_ERROR"}
            )
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return JSONResponse(
                status_code=500,
                content={"error": "Internal security error", "code": "INTERNAL_ERROR"}
            )

# --- Security API Endpoints ---

def create_security_app() -> FastAPI:
    """Create FastAPI app with security endpoints"""
    
    app = FastAPI(
        title="YDark Security API",
        description="Security layer for YDark AI services",
        version="1.0.0"
    )
    
    @app.on_event("startup")
    async def startup():
        """Load API keys on startup"""
        await load_api_keys_from_redis()
        logger.info("YDark Security API started")
    
    @app.post("/auth/create-token", response_model=TokenCreateResponse)
    async def create_token_endpoint(request: TokenCreateRequest):
        """Create a new API token"""
        return await create_api_token(
            client_name=request.client_name,
            allowed_ips=request.allowed_ips,
            expires_in_days=request.expires_in_days or TOKEN_EXPIRE_DAYS
        )
    
    @app.get("/auth/stats")
    async def get_stats(x_api_key: str = Header(..., alias="X-API-Key")):
        """Get usage statistics for API key"""
        client_ip = "127.0.0.1"  # For stats endpoint, IP doesn't matter
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
    
    @app.delete("/auth/revoke-token")
    async def revoke_token(x_api_key: str = Header(..., alias="X-API-Key")):
        """Revoke an API token"""
        key_id = extract_key_id(x_api_key)
        
        if key_id in api_keys_store:
            api_keys_store[key_id].is_active = False
            await save_api_key_to_redis(api_keys_store[key_id])
            logger.info(f"Revoked API key: {x_api_key}")
            return {"message": "API key revoked successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="API key not found"
            )
    
    @app.get("/security/health")
    async def security_health():
        """Security service health check"""
        redis_status = "connected" if await get_redis() else "disconnected"
        return {
            "status": "healthy",
            "service": "YDark Security",
            "redis": redis_status,
            "active_keys": len([k for k in api_keys_store.values() if k.is_active]),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    return app

# --- Example Integration with models.py ---

def secure_models_app(models_app: FastAPI, open_paths: Optional[List[str]] = None) -> FastAPI:
    """Add security middleware to models app"""
    
    # Add security middleware
    models_app.add_middleware(YDarkSecurityMiddleware, open_paths=open_paths)
    
    # Add security endpoints to models app
    security_app = create_security_app()
    
    # Mount security routes
    models_app.mount("/security", security_app)
    
    logger.info("Added YDark security layer to models app")
    return models_app

# --- Utility for generating curl examples ---

def generate_curl_example(api_key: str, secret: str, endpoint: str, method: str = "POST", data: Optional[Dict] = None) -> str:
    """Generate a curl command example with proper security headers"""
    
    request_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    path = f"/api/{endpoint}"
    
    # Prepare body
    if data and method.upper() == "POST":
        body_str = "&".join([f"{k}={v}" for k, v in data.items()])
        body_bytes = body_str.encode()
    else:
        body_bytes = b""
    
    # Generate HMAC signature
    body_hash = hashlib.sha256(body_bytes).hexdigest()
    signature_base = f"{timestamp}\n{method.upper()}\n{path}\n{body_hash}".encode()
    signature = hmac.new(secret.encode(), signature_base, hashlib.sha256).hexdigest()
    
    # Build curl command
    curl_cmd = f'curl -X {method.upper()} "https://your-domain.com{path}" \\\n'
    curl_cmd += f'  -H "X-API-Key: {api_key}" \\\n'
    curl_cmd += f'  -H "X-Request-ID: {request_id}" \\\n'
    curl_cmd += f'  -H "X-Signature: {signature}" \\\n'
    curl_cmd += f'  -H "X-Timestamp: {timestamp}"'
    
    if data and method.upper() == "POST":
        for k, v in data.items():
            curl_cmd += f' \\\n  -d "{k}={v}"'
    
    return curl_cmd

if __name__ == "__main__":
    # Example usage
    print("YDark Security Layer")
    print("===================")
    print("This module provides comprehensive API security for YDark services.")
    print("Features:")
    print("- API keys in ydark-[7 alphanumeric] format")
    print("- HMAC signature validation")
    print("- Request ID replay protection")
    print("- Rate limiting")
    print("- Usage quotas")
    print("- IP whitelisting")
    print("- Comprehensive logging")
