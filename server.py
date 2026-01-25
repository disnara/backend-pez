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


# ==================== CHALLENGE MODELS ====================

class Challenge(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    image_url: str
    multiplier: str  # e.g., "2000x"
    min_bet: float  # e.g., 0.2
    reward: float  # e.g., 200
    play_now_url: str
    status: str = "active"  # "active" or "completed"
    completed_by: Optional[str] = None  # Username of winner
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ChallengeCreate(BaseModel):
    title: str
    image_url: str
    multiplier: str
    min_bet: float
    reward: float
    play_now_url: str


class ChallengeUpdate(BaseModel):
    title: Optional[str] = None
    image_url: Optional[str] = None
    multiplier: Optional[str] = None
    min_bet: Optional[float] = None
    reward: Optional[float] = None
    play_now_url: Optional[str] = None
    status: Optional[str] = None


class ChallengeComplete(BaseModel):
    completed_by: str  # Username of winner


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


# ==================== TIMER ENDPOINT ====================

# Define FIXED leaderboard end times based on competition periods
# Metaspins: Monthly (January 1 - February 1)
# Menace: Bi-weekly (January 9 - January 23)

# Set to end at midnight (12:00 AM) UTC for each competition period
LEADERBOARD_END_TIMES = {
    "metaspins": datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc),    # End: 12:00 AM, 1 February 2026 (UTC)
    "menace": datetime(2026, 2, 7, 0, 0, 0, tzinfo=timezone.utc),      # End: 12:00 AM, 7 February 2026 (UTC)
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


# ==================== CHALLENGE ENDPOINTS ====================

@api_router.get("/challenges/active", response_model=List[Challenge])
async def get_active_challenges():
    """Get all active challenges"""
    try:
        challenges = await db.challenges.find({"status": "active"}, {"_id": 0}).to_list(1000)
        
        # Convert ISO string timestamps back to datetime objects
        for challenge in challenges:
            if isinstance(challenge.get('created_at'), str):
                challenge['created_at'] = datetime.fromisoformat(challenge['created_at'])
            if isinstance(challenge.get('updated_at'), str):
                challenge['updated_at'] = datetime.fromisoformat(challenge['updated_at'])
        
        return challenges
    except Exception as e:
        logger.error(f"Error fetching active challenges: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/challenges/completed", response_model=List[Challenge])
async def get_completed_challenges():
    """Get all completed challenges"""
    try:
        challenges = await db.challenges.find({"status": "completed"}, {"_id": 0}).to_list(1000)
        
        # Convert ISO string timestamps back to datetime objects
        for challenge in challenges:
            if isinstance(challenge.get('created_at'), str):
                challenge['created_at'] = datetime.fromisoformat(challenge['created_at'])
            if isinstance(challenge.get('updated_at'), str):
                challenge['updated_at'] = datetime.fromisoformat(challenge['updated_at'])
        
        return challenges
    except Exception as e:
        logger.error(f"Error fetching completed challenges: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.get("/challenges", response_model=List[Challenge])
async def get_all_challenges():
    """Get all challenges (for admin panel)"""
    try:
        challenges = await db.challenges.find({}, {"_id": 0}).to_list(1000)
        
        # Convert ISO string timestamps back to datetime objects
        for challenge in challenges:
            if isinstance(challenge.get('created_at'), str):
                challenge['created_at'] = datetime.fromisoformat(challenge['created_at'])
            if isinstance(challenge.get('updated_at'), str):
                challenge['updated_at'] = datetime.fromisoformat(challenge['updated_at'])
        
        return challenges
    except Exception as e:
        logger.error(f"Error fetching all challenges: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.post("/challenges", response_model=Challenge)
async def create_challenge(input: ChallengeCreate):
    """Create a new challenge (admin)"""
    try:
        challenge_dict = input.model_dump()
        challenge_obj = Challenge(**challenge_dict)
        
        # Convert to dict and serialize datetime to ISO string for MongoDB
        doc = challenge_obj.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        doc['updated_at'] = doc['updated_at'].isoformat()
        
        await db.challenges.insert_one(doc)
        return challenge_obj
    except Exception as e:
        logger.error(f"Error creating challenge: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.put("/challenges/{challenge_id}", response_model=Challenge)
async def update_challenge(challenge_id: str, input: ChallengeUpdate):
    """Update a challenge (admin)"""
    try:
        # Get existing challenge
        existing = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
        if not existing:
            raise HTTPException(status_code=404, detail="Challenge not found")
        
        # Update only provided fields
        update_data = {k: v for k, v in input.model_dump().items() if v is not None}
        update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
        
        # Update in database
        await db.challenges.update_one(
            {"id": challenge_id},
            {"$set": update_data}
        )
        
        # Fetch and return updated challenge
        updated = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
        
        # Convert ISO string timestamps back to datetime objects
        if isinstance(updated.get('created_at'), str):
            updated['created_at'] = datetime.fromisoformat(updated['created_at'])
        if isinstance(updated.get('updated_at'), str):
            updated['updated_at'] = datetime.fromisoformat(updated['updated_at'])
        
        return Challenge(**updated)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating challenge: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.put("/challenges/{challenge_id}/complete", response_model=Challenge)
async def complete_challenge(challenge_id: str, input: ChallengeComplete):
    """Mark a challenge as completed with winner username (admin)"""
    try:
        # Get existing challenge
        existing = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
        if not existing:
            raise HTTPException(status_code=404, detail="Challenge not found")
        
        # Update challenge to completed
        update_data = {
            'status': 'completed',
            'completed_by': input.completed_by,
            'updated_at': datetime.now(timezone.utc).isoformat()
        }
        
        await db.challenges.update_one(
            {"id": challenge_id},
            {"$set": update_data}
        )
        
        # Fetch and return updated challenge
        updated = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
        
        # Convert ISO string timestamps back to datetime objects
        if isinstance(updated.get('created_at'), str):
            updated['created_at'] = datetime.fromisoformat(updated['created_at'])
        if isinstance(updated.get('updated_at'), str):
            updated['updated_at'] = datetime.fromisoformat(updated['updated_at'])
        
        return Challenge(**updated)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error completing challenge: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@api_router.delete("/challenges/{challenge_id}")
async def delete_challenge(challenge_id: str):
    """Delete a challenge (admin)"""
    try:
        result = await db.challenges.delete_one({"id": challenge_id})
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Challenge not found")
        
        return {"success": True, "message": "Challenge deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting challenge: {str(e)}")
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
