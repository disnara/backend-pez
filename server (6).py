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


# Menace Leaderboard
@api_router.get("/leaderboard/menace")
async def get_menace_leaderboard(
    date_start: Optional[str] = "2026-01-24",
    date_end: Optional[str] = "2026-02-07",
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


# Bitfortune Leaderboard
@api_router.get("/leaderboard/bitfortune")
async def get_bitfortune_leaderboard():
    """Fetch Bitfortune leaderboard data"""
    try:
        # API Key for Bitfortune
        api_key = "082a6a65-4da1-425c-9b44-cf609e988672"
        
        # Date range: 27/01/2026 12:00am to 27/02/2026 12:00am (Unix timestamps)
        # Using UTC timestamps
        from_timestamp = 1738022400  # 27/01/2026 00:00:00 UTC
        to_timestamp = 1740614400    # 27/02/2026 00:00:00 UTC
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = "https://platformv2.bitfortune.com/api/v1/external/affiliates/leaderboard"
            params = {
                "api_key": api_key,
                "from": from_timestamp,
                "to": to_timestamp
            }
            response = await client.get(url, params=params)
            response.raise_for_status()
            api_response = response.json()
            
            # Parse Bitfortune response
            if isinstance(api_response, list):
                if len(api_response) == 0:
                    # No players found
                    return {
                        "success": True,
                        "site": "bitfortune",
                        "data": [],
                        "message": "No Players Found"
                    }
                
                formatted_users = []
                for idx, user in enumerate(api_response[:20]):  # Top 20
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("user_name", "Unknown"),
                        "wagered": user.get("total_wager_usd", 0),
                        "avatar": ""  # Bitfortune doesn't provide avatars
                    })
                
                return {
                    "success": True,
                    "site": "bitfortune",
                    "data": formatted_users
                }
            else:
                logger.warning(f"Bitfortune API returned unexpected format: {api_response}")
                return {
                    "success": False,
                    "site": "bitfortune",
                    "data": [],
                    "message": "No Players Found"
                }
    except httpx.HTTPError as e:
        logger.error(f"Bitfortune API error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch Bitfortune leaderboard: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error fetching Bitfortune leaderboard: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== TIMER ENDPOINT ====================

# Define FIXED leaderboard end times based on competition periods
# Metaspins: Monthly (January 1 - February 1)
# Menace: Bi-weekly (January 9 - January 23)
# Bitfortune: Monthly (January 27 - February 27)

# Set to end at midnight (12:00 AM) UTC for each competition period
LEADERBOARD_END_TIMES = {
    "metaspins": datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc),    # End: 12:00 AM, 1 February 2026 (UTC)
    "menace": datetime(2026, 2, 7, 0, 0, 0, tzinfo=timezone.utc),      # End: 12:00 AM, 7 February 2026 (UTC)
    "bitfortune": datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc),  # End: 12:00 AM, 27 February 2026 (UTC)
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
