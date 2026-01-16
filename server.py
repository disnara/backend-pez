from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import httpx
import json


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Add CORS middleware FIRST - before any routes
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# Define Models
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")  # Ignore MongoDB's _id field
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "Hello World"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    # Convert to dict and serialize datetime to ISO string for MongoDB
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    _ = await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    # Exclude MongoDB's _id field from the query results
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    # Convert ISO string timestamps back to datetime objects
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks


# ==================== LEADERBOARD ENDPOINTS ====================

# Metaspins Leaderboard
@api_router.get("/leaderboard/metaspins")
async def get_metaspins_leaderboard():
    """Fetch Metaspins leaderboard data"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                "https://exportdata.xcdn.tech/metaspins-affiliate-leaderboard-export/1808/182639827/1099561537.json"
            )
            response.raise_for_status()
            data = response.json()
            return {
                "success": True,
                "site": "metaspins",
                "data": data
            }
    except httpx.HTTPError as e:
        logger.error(f"Metaspins API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch Metaspins leaderboard: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error fetching Metaspins leaderboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# CSGO WIN Leaderboard
@api_router.get("/leaderboard/csgowin")
async def get_csgowin_leaderboard():
    """Fetch CSGO WIN leaderboard data"""
    try:
        api_key = "b4adbcafb8"
        affiliate_code = "pezslaps"
        headers = {
            "x-apikey": api_key
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Correct endpoint based on CSGO WIN API documentation
            response = await client.get(
                f"https://api.csgowin.com/api/leaderboard/{affiliate_code}",
                headers=headers
            )
            response.raise_for_status()
            data = response.json()
            return {
                "success": True,
                "site": "csgowin",
                "data": data
            }
    except httpx.HTTPError as e:
        logger.error(f"CSGO WIN API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch CSGO WIN leaderboard: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error fetching CSGO WIN leaderboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Winovo Leaderboard
@api_router.get("/leaderboard/winovo")
async def get_winovo_leaderboard():
    """Fetch Winovo leaderboard data"""
    try:
        api_key = "a9d4f2c7b0e1f6d8c5a3b9e0d2"
        headers = {
            "x-creator-auth": api_key
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Try alternative base URL - winovo.io instead of api.winovo.io
            response = await client.get(
                "https://winovo.io/api/creator/users",
                headers=headers
            )
            response.raise_for_status()
            data = response.json()
            return {
                "success": True,
                "site": "winovo",
                "data": data
            }
    except httpx.HTTPError as e:
        logger.error(f"Winovo API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch Winovo leaderboard: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error fetching Winovo leaderboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Menace Leaderboard
@api_router.get("/leaderboard/menace")
async def get_menace_leaderboard(
    date_start: Optional[str] = "2025-01-01",
    date_end: Optional[str] = "2025-01-31",
    limit: Optional[int] = 20
):
    """Fetch Menace leaderboard data with customizable date range"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"https://api-prod.gaze.bet/api/leaderboard/LSNCGAYMCPRJ/fb7d008f-a6e5-4d00-81f9-2e4afd9c5b7a"
            params = {
                "dateStart": date_start,
                "dateEnd": date_end,
                "limit": limit
            }
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()
            return {
                "success": True,
                "site": "menace",
                "data": data
            }
    except httpx.HTTPError as e:
        logger.error(f"Menace API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch Menace leaderboard: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error fetching Menace leaderboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== TIMER ENDPOINT ====================

# Define leaderboard end times (you can customize these)
LEADERBOARD_END_TIMES = {
    "menace": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),
    "metaspins": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),
    "winovo": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),
    "csgowin": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),
}

@api_router.get("/timer/{site}")
async def get_timer(site: str):
    """Get synchronized countdown timer for a specific leaderboard site"""
    try:
        site = site.lower()
        if site not in LEADERBOARD_END_TIMES:
            raise HTTPException(status_code=404, detail=f"Timer for site '{site}' not found")
        
        end_time = LEADERBOARD_END_TIMES[site]
        current_time = datetime.now(timezone.utc)
        
        time_remaining = end_time - current_time
        
        if time_remaining.total_seconds() <= 0:
            return {
                "success": True,
                "site": site,
                "ended": True,
                "days": 0,
                "hours": 0,
                "minutes": 0,
                "seconds": 0,
                "total_seconds": 0
            }
        
        days = time_remaining.days
        hours, remainder = divmod(time_remaining.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return {
            "success": True,
            "site": site,
            "ended": False,
            "days": days,
            "hours": hours,
            "minutes": minutes,
            "seconds": seconds,
            "total_seconds": int(time_remaining.total_seconds()),
            "end_time": end_time.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error calculating timer for {site}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# Get all timers at once
@api_router.get("/timers")
async def get_all_timers():
    """Get synchronized countdown timers for all leaderboard sites"""
    try:
        current_time = datetime.now(timezone.utc)
        timers = {}
        
        for site, end_time in LEADERBOARD_END_TIMES.items():
            time_remaining = end_time - current_time
            
            if time_remaining.total_seconds() <= 0:
                timers[site] = {
                    "ended": True,
                    "days": 0,
                    "hours": 0,
                    "minutes": 0,
                    "seconds": 0,
                    "total_seconds": 0
                }
            else:
                days = time_remaining.days
                hours, remainder = divmod(time_remaining.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                timers[site] = {
                    "ended": False,
                    "days": days,
                    "hours": hours,
                    "minutes": minutes,
                    "seconds": seconds,
                    "total_seconds": int(time_remaining.total_seconds()),
                    "end_time": end_time.isoformat()
                }
        
        return {
            "success": True,
            "current_time": current_time.isoformat(),
            "timers": timers
        }
    except Exception as e:
        logger.error(f"Error calculating timers: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Include the router in the main app
app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()