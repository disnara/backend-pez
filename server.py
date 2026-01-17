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
            api_response = response.json()
            
            # Format Metaspins response
            if isinstance(api_response, list):
                formatted_users = []
                for idx, user in enumerate(api_response[:20]):  # Top 20
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("username", "Unknown"),
                        "wagered": user.get("bets", 0),  # Metaspins uses "bets" instead of "wagered"
                        "avatar": ""  # Metaspins doesn't provide avatars in this endpoint
                    })
                
                return {
                    "success": True,
                    "site": "metaspins",
                    "data": formatted_users
                }
            else:
                logger.warning("Metaspins API returned unexpected format")
                return {
                    "success": False,
                    "site": "metaspins",
                    "data": []
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
    """Fetch CSGO WIN leaderboard data using affiliate/external endpoint"""
    try:
        api_key = "b4adbcafb8"
        affiliate_code = "pezslaps"
        headers = {
            "x-apikey": api_key
        }
        
        # Calculate time range - last 30 days to future
        from datetime import datetime, timedelta
        start_time = int((datetime.now() - timedelta(days=30)).timestamp() * 1000)
        end_time = int((datetime.now() + timedelta(days=365)).timestamp() * 1000)
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Use affiliate/external endpoint with proper parameters
            params = {
                "code": affiliate_code,
                "gt": start_time,
                "lt": end_time,
                "by": "wager",
                "sort": "desc",
                "take": 20
            }
            response = await client.get(
                "https://api.csgowin.com/api/affiliate/external",
                headers=headers,
                params=params
            )
            response.raise_for_status()
            data = response.json()
            
            # Transform the response to match expected format
            if data.get("success") and "data" in data:
                users = data["data"]
                # Convert coins to USD and format
                formatted_users = []
                for idx, user in enumerate(users[:20]):  # Top 20
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("name", "Unknown"),
                        "wagered": user.get("wagered", 0) / 1.61,  # Convert coins to USD
                        "avatar": user.get("steam_avatar", "")
                    })
                
                return {
                    "success": True,
                    "site": "csgowin",
                    "data": formatted_users
                }
            else:
                logger.warning("CSGO WIN API returned unexpected format")
                return {
                    "success": False,
                    "site": "csgowin",
                    "data": []
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
        api_key = "9e0c7b5d1a6f4e2d8a3c0b7f1e"
        headers = {
            "x-creator-auth": api_key
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                "https://winovo.io/api/creator/users",
                headers=headers
            )
            response.raise_for_status()
            api_response = response.json()
            
            # Parse Winovo response format
            if api_response.get("status") == "ok" and "data" in api_response:
                users = api_response["data"]
                # Format and rank users by wagered amount
                formatted_users = []
                for idx, user in enumerate(users[:20]):  # Top 20
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("name", "Unknown"),
                        "wagered": user.get("wagered", 0),
                        "avatar": user.get("pic", "")  # pic is optional
                    })
                
                return {
                    "success": True,
                    "site": "winovo",
                    "data": formatted_users
                }
            else:
                logger.warning("Winovo API returned unexpected format")
                return {
                    "success": False,
                    "site": "winovo",
                    "data": []
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
    date_start: Optional[str] = "2026-01-01",
    date_end: Optional[str] = "2026-02-28",
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
            api_response = response.json()
            
            # Parse Menace response - data is in "leaderboard" key
            if "leaderboard" in api_response and isinstance(api_response["leaderboard"], list):
                formatted_users = []
                for user in api_response["leaderboard"][:20]:  # Top 20
                    formatted_users.append({
                        "rank": user.get("place", 0),
                        "username": user.get("nickname", "Unknown"),
                        "wagered": user.get("wagered", 0),
                        "avatar": ""  # Menace doesn't provide avatars
                    })
                
                return {
                    "success": True,
                    "site": "menace",
                    "data": formatted_users
                }
            else:
                logger.warning(f"Menace API returned unexpected format: {api_response}")
                return {
                    "success": False,
                    "site": "menace",
                    "data": []
                }
    except httpx.HTTPError as e:
        logger.error(f"Menace API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch Menace leaderboard: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error fetching Menace leaderboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== TIMER ENDPOINT ====================

# Define FIXED leaderboard end times - Set these to actual competition end dates
# These should be updated when a new competition starts
# Format: datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
LEADERBOARD_END_TIMES = {
    "menace": datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc),  # February 1, 2026
    "metaspins": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),  # End of February 2026
    "winovo": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),  # End of February 2026
    "csgowin": datetime(2026, 2, 28, 23, 59, 59, tzinfo=timezone.utc),  # End of February 2026
}

@api_router.get("/timer/{site}")
async def get_timer(site: str):
    """Get synchronized countdown timer for a specific leaderboard site"""
    try:
        site = site.lower()
        # Use FIXED end times - no recalculation
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
        # Use FIXED end times - no recalculation
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

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
