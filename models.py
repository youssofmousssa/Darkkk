#!/usr/bin/env python3
"""
YDark Services Backend - models.py
Direct implementation of all YDark services as documented
Runs as backend with CORS support
"""

import hashlib
import httpx
import time
import uuid
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import asyncio
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# FastAPI app for backend services
app = FastAPI(
    title="YDark Services Backend",
    description="Direct backend implementation of all YDark AI services",
    version="1.0.0"
)

# CORS middleware - allow all origins for backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Upstream service configuration
UPSTREAM_BASE = "https://sii3.moayman.top"
REQUEST_TIMEOUT = 60.0

# HTTP client for upstream requests
async def get_http_client():
    return httpx.AsyncClient(timeout=REQUEST_TIMEOUT)

async def call_upstream_service(path: str, method: str, params: Dict[str, Any] = None, data: Dict[str, Any] = None):
    """Call upstream YDark service directly"""
    async with await get_http_client() as client:
        url = f"{UPSTREAM_BASE}{path}"
        
        try:
            if method.upper() == "GET":
                response = await client.get(url, params=params)
            else:
                response = await client.post(url, data=data)
            
            # Return JSON if possible, otherwise return text
            try:
                return response.json()
            except:
                return {"response": response.text, "status_code": response.status_code}
                
        except Exception as e:
            logger.error(f"Upstream call failed: {e}")
            raise HTTPException(status_code=502, detail=f"Upstream service error: {str(e)}")

# --- YDark Service Implementations ---

@app.api_route("/api/gemini-img", methods=["GET", "POST"])
async def gemini_img_service(
    request: Request,
    text: Optional[str] = None,
    link: Optional[str] = None
):
    """Gemini Pro Image Generation and Editing"""
    if request.method == "GET":
        text = request.query_params.get("text")
        link = request.query_params.get("link")
    else:
        form = await request.form()
        text = form.get("text")
        link = form.get("link")
    
    params = {}
    if text:
        params["text"] = text
    if link:
        params["link"] = link
    
    if request.method == "GET":
        return await call_upstream_service("/api/gemini-img.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/gemini-img.php", "POST", data=params)

@app.api_route("/api/flux-pro", methods=["GET", "POST"])
async def flux_pro_service(
    request: Request,
    text: Optional[str] = None
):
    """Flux Pro - Generate 4 images per request"""
    if request.method == "GET":
        text = request.query_params.get("text")
    else:
        form = await request.form()
        text = form.get("text")
    
    params = {}
    if text:
        params["text"] = text
    
    if request.method == "GET":
        return await call_upstream_service("/api/flux-pro.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/flux-pro.php", "POST", data=params)

@app.api_route("/api/gpt-img", methods=["GET", "POST"])
async def gpt_img_service(
    request: Request,
    text: Optional[str] = None,
    link: Optional[str] = None
):
    """GPT-5 Image Generation and Editing"""
    if request.method == "GET":
        text = request.query_params.get("text")
        link = request.query_params.get("link")
    else:
        form = await request.form()
        text = form.get("text")
        link = form.get("link")
    
    params = {}
    if text:
        params["text"] = text
    if link:
        params["link"] = link
    
    if request.method == "GET":
        return await call_upstream_service("/api/gpt-img.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/gpt-img.php", "POST", data=params)

@app.api_route("/api/nano-banana", methods=["GET", "POST"])
async def nano_banana_service(
    request: Request,
    text: Optional[str] = None,
    links: Optional[str] = None
):
    """Nano Banana - Image merging (max 10 images)"""
    if request.method == "GET":
        text = request.query_params.get("text")
        links = request.query_params.get("links")
    else:
        form = await request.form()
        text = form.get("text")
        links = form.get("links")
    
    params = {}
    if text:
        params["text"] = text
    if links:
        params["links"] = links
    
    if request.method == "GET":
        return await call_upstream_service("/api/nano-banana.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/nano-banana.php", "POST", data=params)

@app.api_route("/api/img-cv", methods=["GET", "POST"])
async def img_cv_service(
    request: Request,
    text: Optional[str] = None
):
    """High Quality Image Generation with incredible speed"""
    if request.method == "GET":
        text = request.query_params.get("text")
    else:
        form = await request.form()
        text = form.get("text")
    
    params = {}
    if text:
        params["text"] = text
    
    if request.method == "GET":
        return await call_upstream_service("/api/img-cv.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/img-cv.php", "POST", data=params)

@app.api_route("/api/voice", methods=["GET", "POST"])
async def voice_service(
    request: Request,
    text: Optional[str] = None,
    voice: Optional[str] = None,
    style: Optional[str] = None
):
    """Text to Speech Voice Generation"""
    if request.method == "GET":
        text = request.query_params.get("text")
        voice = request.query_params.get("voice")
        style = request.query_params.get("style")
    else:
        form = await request.form()
        text = form.get("text")
        voice = form.get("voice")
        style = form.get("style")
    
    params = {}
    if text:
        params["text"] = text
    if voice:
        params["voice"] = voice
    if style:
        params["style"] = style
    
    if request.method == "GET":
        return await call_upstream_service("/api/voice.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/voice.php", "POST", data=params)

@app.api_route("/api/veo3", methods=["GET", "POST"])
async def veo3_service(
    request: Request,
    text: Optional[str] = None,
    link: Optional[str] = None
):
    """Text-to-Video & Image-to-Video with FREE audio support"""
    if request.method == "GET":
        text = request.query_params.get("text")
        link = request.query_params.get("link")
    else:
        form = await request.form()
        text = form.get("text")
        link = form.get("link")
    
    params = {}
    if text:
        params["text"] = text
    if link:
        params["link"] = link
    
    if request.method == "GET":
        return await call_upstream_service("/api/veo3.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/veo3.php", "POST", data=params)

@app.api_route("/api/music", methods=["GET", "POST"])
async def music_service(
    request: Request,
    lyrics: Optional[str] = None,
    tags: Optional[str] = None
):
    """Song Creation With Lyrics And Music"""
    if request.method == "GET":
        lyrics = request.query_params.get("lyrics")
        tags = request.query_params.get("tags")
    else:
        form = await request.form()
        lyrics = form.get("lyrics")
        tags = form.get("tags")
    
    params = {}
    if lyrics:
        params["lyrics"] = lyrics
    if tags:
        params["tags"] = tags
    
    if request.method == "GET":
        return await call_upstream_service("/api/music.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/music.php", "POST", data=params)

@app.api_route("/api/create-music", methods=["GET", "POST"])
async def create_music_service(
    request: Request,
    text: Optional[str] = None
):
    """Create 15s music without lyrics"""
    if request.method == "GET":
        text = request.query_params.get("text")
    else:
        form = await request.form()
        text = form.get("text")
    
    params = {}
    if text:
        params["text"] = text
    
    if request.method == "GET":
        return await call_upstream_service("/api/create-music.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/create-music.php", "POST", data=params)

@app.api_route("/api/wormgpt", methods=["GET", "POST"])
async def wormgpt_service(
    request: Request,
    text: Optional[str] = None
):
    """WormGPT API"""
    if request.method == "GET":
        text = request.query_params.get("text")
    else:
        form = await request.form()
        text = form.get("text")
    
    params = {}
    if text:
        params["text"] = text
    
    if request.method == "GET":
        return await call_upstream_service("/DARK/api/wormgpt.php", "GET", params=params)
    else:
        return await call_upstream_service("/DARK/api/wormgpt.php", "POST", data=params)

@app.api_route("/api/ai", methods=["GET", "POST"])
async def ai_service(
    request: Request,
    online: Optional[str] = None,
    standard: Optional[str] = None,
    super_genius: Optional[str] = None,
    online_genius: Optional[str] = None
):
    """Multi-model AI (online, standard, super-genius, online-genius)"""
    if request.method == "GET":
        online = request.query_params.get("online")
        standard = request.query_params.get("standard")
        super_genius = request.query_params.get("super-genius")
        online_genius = request.query_params.get("online-genius")
    else:
        form = await request.form()
        online = form.get("online")
        standard = form.get("standard")
        super_genius = form.get("super-genius")
        online_genius = form.get("online-genius")
    
    params = {}
    if online:
        params["online"] = online
    if standard:
        params["standard"] = standard
    if super_genius:
        params["super-genius"] = super_genius
    if online_genius:
        params["online-genius"] = online_genius
    
    if request.method == "GET":
        return await call_upstream_service("/api/ai.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/ai.php", "POST", data=params)

@app.api_route("/api/gemini-dark", methods=["GET", "POST"])
async def gemini_dark_service(
    request: Request,
    gemini_pro: Optional[str] = None,
    gemini_deep: Optional[str] = None
):
    """All Gemini models (gemini-pro, gemini-deep)"""
    if request.method == "GET":
        gemini_pro = request.query_params.get("gemini-pro")
        gemini_deep = request.query_params.get("gemini-deep")
    else:
        try:
            # Try JSON first for POST
            json_data = await request.json()
            gemini_pro = json_data.get("gemini-pro")
            gemini_deep = json_data.get("gemini-deep")
        except:
            # Fallback to form data
            form = await request.form()
            gemini_pro = form.get("gemini-pro")
            gemini_deep = form.get("gemini-deep")
    
    params = {}
    if gemini_pro:
        params["gemini-pro"] = gemini_pro
    if gemini_deep:
        params["gemini-deep"] = gemini_deep
    
    if request.method == "GET":
        return await call_upstream_service("/api/gemini-dark.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/gemini-dark.php", "POST", data=params)

@app.api_route("/api/gemini", methods=["GET", "POST"])
async def gemini_service(
    request: Request,
    text: Optional[str] = None
):
    """Gemini 2.5 Flash"""
    if request.method == "GET":
        text = request.query_params.get("text")
    else:
        try:
            # Try JSON first for POST
            json_data = await request.json()
            text = json_data.get("text")
        except:
            # Fallback to form data
            form = await request.form()
            text = form.get("text")
    
    params = {}
    if text:
        params["text"] = text
    
    if request.method == "GET":
        return await call_upstream_service("/DARK/gemini.php", "GET", params=params)
    else:
        return await call_upstream_service("/DARK/gemini.php", "POST", data=params)

@app.api_route("/api/do", methods=["GET", "POST"])
async def do_service(
    request: Request,
    url: Optional[str] = None
):
    """Universal Social Downloader"""
    if request.method == "GET":
        url = request.query_params.get("url")
    else:
        form = await request.form()
        url = form.get("url")
    
    params = {}
    if url:
        params["url"] = url
    
    if request.method == "GET":
        return await call_upstream_service("/api/do.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/do.php", "POST", data=params)

@app.api_route("/api/remove-bg", methods=["GET", "POST"])
async def remove_bg_service(
    request: Request,
    url: Optional[str] = None
):
    """Remove background from image"""
    if request.method == "GET":
        url = request.query_params.get("url")
    else:
        form = await request.form()
        url = form.get("url")
    
    params = {}
    if url:
        params["url"] = url
    
    if request.method == "GET":
        return await call_upstream_service("/api/remove-bg.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/remove-bg.php", "POST", data=params)

@app.api_route("/api/gemma", methods=["GET", "POST"])
async def gemma_service(
    request: Request,
    model_4b: Optional[str] = None,
    model_12b: Optional[str] = None,
    model_27b: Optional[str] = None
):
    """Gemma models (4b, 12b, 27b)"""
    if request.method == "GET":
        model_4b = request.query_params.get("4b")
        model_12b = request.query_params.get("12b")
        model_27b = request.query_params.get("27b")
    else:
        form = await request.form()
        model_4b = form.get("4b")
        model_12b = form.get("12b")
        model_27b = form.get("27b")
    
    params = {}
    if model_4b:
        params["4b"] = model_4b
    if model_12b:
        params["12b"] = model_12b
    if model_27b:
        params["27b"] = model_27b
    
    if request.method == "GET":
        return await call_upstream_service("/api/gemma.php", "GET", params=params)
    else:
        return await call_upstream_service("/api/gemma.php", "POST", data=params)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "YDark Backend", "timestamp": time.time()}

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with service information"""
    return {
        "service": "YDark Services Backend",
        "version": "1.0.0",
        "description": "Direct backend implementation of all YDark AI services",
        "services": [
            "gemini-img", "flux-pro", "gpt-img", "nano-banana", "img-cv",
            "voice", "veo3", "music", "create-music", "wormgpt", "ai",
            "gemini-dark", "gemini", "do", "remove-bg", "gemma"
        ],
        "cors": "enabled",
        "methods": ["GET", "POST"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=3000, reload=True)
