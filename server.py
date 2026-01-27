from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
import secrets
from datetime import datetime, timezone
import httpx


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MongoDB connection (optional - gracefully handle if not available)
mongo_url = os.environ.get('MONGO_URL', '')
db_name = os.environ.get('DB_NAME', 'pezrewards')
client = None
db = None

try:
    if mongo_url and 'localhost' not in mongo_url:
        client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=5000)
        db = client[db_name]
        logger.info("MongoDB connection initialized")
    else:
        logger.warning("MongoDB not configured or using localhost - running without database")
except Exception as e:
    logger.warning(f"MongoDB connection failed: {e} - running without database")

# Create the main app without a prefix
app = FastAPI()

# Add CORS middleware FIRST (before routes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# HTTP Basic Auth for admin
security = HTTPBasic()

# Admin credentials
ADMIN_USERNAME = "pezrewards"
ADMIN_PASSWORD = "pezrewardadmin123"

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USERNAME)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


# Define Models
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

class ChallengeCreate(BaseModel):
    site: str
    site_logo: str
    game_name: str
    game_image: str
    multiplier: str
    minimum_bet: str
    reward: str
    play_url: str
    is_active: bool = True

class ChallengeUpdate(BaseModel):
    site: Optional[str] = None
    site_logo: Optional[str] = None
    game_name: Optional[str] = None
    game_image: Optional[str] = None
    multiplier: Optional[str] = None
    minimum_bet: Optional[str] = None
    reward: Optional[str] = None
    play_url: Optional[str] = None
    is_active: Optional[bool] = None

class LeaderboardSettingsUpdate(BaseModel):
    prize_pool: Optional[str] = None
    period: Optional[str] = None
    prizes: Optional[dict] = None
    end_date: Optional[str] = None
    fetch_start: Optional[int] = None
    fetch_end: Optional[int] = None


# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "Hello World"}

@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    
    _ = await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    
    return status_checks


# ==================== LEADERBOARD SETTINGS ====================

# Default settings (will be overridden by DB)
DEFAULT_LEADERBOARD_SETTINGS = {
    "menace": {
        "prize_pool": "$1,500",
        "period": "Bi-Weekly",
        "register_link": "https://menace.com/?r=pez",
        "logo": "image/menace.png",
        "prizes": {
            "1": "$600", "2": "$300", "3": "$200", "4": "$150", "5": "$100",
            "6": "$60", "7": "$40", "8": "$30", "9": "$15", "10": "$5"
        },
        "end_date": "2026-02-07T00:00:00+00:00",
        "fetch_start": None,
        "fetch_end": None
    },
    "metaspins": {
        "prize_pool": "$3,200",
        "period": "Monthly",
        "register_link": "https://metaspins.com/?ref=pezslaps",
        "logo": "image/metaspins-logo.png",
        "prizes": {
            "1": "$1,300", "2": "$800", "3": "$500", "4": "$200", "5": "$120",
            "6": "$80 Bonus Buy", "7": "$80 Bonus Buy", "8": "$40 Bonus Buy", "9": "$40 Bonus Buy", "10": "$40 Bonus Buy"
        },
        "end_date": "2026-02-01T00:00:00+00:00",
        "fetch_start": None,
        "fetch_end": None
    },
    "bitfortune": {
        "prize_pool": "$5,000",
        "period": "Monthly",
        "register_link": "https://join.bitfortune.com/pezslaps",
        "logo": "image/bitfortune-logo.png",
        "prizes": {
            "1": "$2,000", "2": "$1,200", "3": "$700", "4": "$400", "5": "$250",
            "6": "$150", "7": "$120", "8": "$80", "9": "$60", "10": "$40"
        },
        "end_date": "2026-02-27T00:00:00+00:00",
        "fetch_start": 1769472000,
        "fetch_end": 1772150400
    }
}

async def get_leaderboard_settings(site: str):
    """Get leaderboard settings from DB or return defaults"""
    if db is not None:
        try:
            settings = await db.leaderboard_settings.find_one({"site": site}, {"_id": 0})
            if settings:
                return settings
        except Exception as e:
            logger.warning(f"Failed to get settings from DB: {e}")
    return DEFAULT_LEADERBOARD_SETTINGS.get(site, {})

@api_router.get("/settings/{site}")
async def get_site_settings(site: str):
    """Get settings for a specific leaderboard site"""
    settings = await get_leaderboard_settings(site.lower())
    if not settings:
        raise HTTPException(status_code=404, detail=f"Settings for site '{site}' not found")
    return {"success": True, "site": site, "settings": settings}

@api_router.get("/settings")
async def get_all_settings():
    """Get settings for all leaderboard sites"""
    all_settings = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        all_settings[site] = await get_leaderboard_settings(site)
    return {"success": True, "settings": all_settings}


# ==================== LEADERBOARD ENDPOINTS ====================

# Metaspins Leaderboard
@api_router.get("/leaderboard/metaspins")
async def get_metaspins_leaderboard():
    """Fetch Metaspins leaderboard data"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            response = await http_client.get(
                "https://exportdata.xcdn.tech/metaspins-affiliate-leaderboard-export/1808/182639827/1099561537.json"
            )
            response.raise_for_status()
            api_response = response.json()
            
            if isinstance(api_response, list):
                formatted_users = []
                for idx, user in enumerate(api_response[:20]):
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("username", "Unknown"),
                        "wagered": user.get("bets", 0),
                        "avatar": ""
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
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            url = f"https://api-prod.gaze.bet/api/leaderboard/LSNCGAYMCPRJ/fb7d008f-a6e5-4d00-81f9-2e4afd9c5b7a"
            params = {
                "dateStart": date_start,
                "dateEnd": date_end,
                "limit": limit
            }
            response = await http_client.get(url, params=params)
            response.raise_for_status()
            api_response = response.json()
            
            if "leaderboard" in api_response and isinstance(api_response["leaderboard"], list):
                formatted_users = []
                for user in api_response["leaderboard"][:20]:
                    formatted_users.append({
                        "rank": user.get("place", 0),
                        "username": user.get("nickname", "Unknown"),
                        "wagered": user.get("wagered", 0),
                        "avatar": ""
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
BITFORTUNE_API_KEY = "082a6a65-4da1-425c-9b44-cf609e988672"
BITFORTUNE_START_TIMESTAMP = 1769472000
BITFORTUNE_END_TIMESTAMP = 1772150400

@api_router.get("/leaderboard/bitfortune")
async def get_bitfortune_leaderboard():
    """Fetch Bitfortune leaderboard data"""
    try:
        # Use hardcoded defaults, try DB only if available
        fetch_start = BITFORTUNE_START_TIMESTAMP
        fetch_end = BITFORTUNE_END_TIMESTAMP
        
        try:
            settings = await get_leaderboard_settings("bitfortune")
            if settings.get("fetch_start"):
                fetch_start = settings.get("fetch_start")
            if settings.get("fetch_end"):
                fetch_end = settings.get("fetch_end")
        except Exception:
            pass  # Use defaults if DB not available
        
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            url = "https://platformv2.bitfortune.com/api/v1/external/affiliates/leaderboard"
            params = {
                "api_key": BITFORTUNE_API_KEY,
                "from": fetch_start,
                "to": fetch_end
            }
            response = await http_client.get(url, params=params)
            response.raise_for_status()
            api_response = response.json()
            
            if isinstance(api_response, list):
                # Sort by total_wager_usd descending
                sorted_users = sorted(api_response, key=lambda x: x.get("total_wager_usd", 0), reverse=True)
                
                formatted_users = []
                for idx, user in enumerate(sorted_users[:20]):
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("user_name", "Unknown"),
                        "wagered": user.get("total_wager_usd", 0),
                        "avatar": ""
                    })
                
                return {
                    "success": True,
                    "site": "bitfortune",
                    "data": formatted_users
                }
            else:
                logger.warning("Bitfortune API returned unexpected format")
                return {
                    "success": True,
                    "site": "bitfortune",
                    "data": []
                }
    except httpx.HTTPError as e:
        logger.error(f"Bitfortune API error: {str(e)}")
        return {
            "success": False,
            "site": "bitfortune",
            "data": [],
            "error": str(e)
        }
    except Exception as e:
        logger.error(f"Unexpected error fetching Bitfortune leaderboard: {str(e)}")
        return {
            "success": False,
            "site": "bitfortune",
            "data": [],
            "error": str(e)
        }


# ==================== TIMER ENDPOINT ====================

# Default end times (hardcoded fallback)
DEFAULT_END_TIMES = {
    "metaspins": datetime(2026, 2, 1, 0, 0, 0, tzinfo=timezone.utc),
    "menace": datetime(2026, 2, 7, 0, 0, 0, tzinfo=timezone.utc),
    "bitfortune": datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc),
}

async def get_leaderboard_end_time(site: str):
    """Get end time from DB settings or use defaults"""
    # Try to get from DB first
    try:
        settings = await get_leaderboard_settings(site)
        end_date_str = settings.get("end_date")
        
        if end_date_str:
            return datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
    except Exception:
        pass  # Use defaults if DB not available
    
    # Return default end time
    return DEFAULT_END_TIMES.get(site)

@api_router.get("/timer/{site}")
async def get_timer(site: str):
    """Get synchronized countdown timer for a specific leaderboard site"""
    try:
        site = site.lower()
        end_time = await get_leaderboard_end_time(site)
        
        if not end_time:
            raise HTTPException(status_code=404, detail=f"Timer for site '{site}' not found")
        
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


@api_router.get("/timers")
async def get_all_timers():
    """Get synchronized countdown timers for all leaderboard sites"""
    try:
        current_time = datetime.now(timezone.utc)
        timers = {}
        
        for site in ["menace", "metaspins", "bitfortune"]:
            end_time = await get_leaderboard_end_time(site)
            if not end_time:
                continue
                
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


# ==================== CHALLENGES ENDPOINTS ====================

@api_router.get("/challenges")
async def get_challenges():
    """Get all challenges"""
    if db is None:
        return {"success": True, "challenges": []}
    try:
        challenges = await db.challenges.find({}, {"_id": 0}).to_list(100)
        return {"success": True, "challenges": challenges}
    except Exception as e:
        logger.warning(f"Failed to get challenges: {e}")
        return {"success": True, "challenges": []}

@api_router.get("/challenges/active")
async def get_active_challenges():
    """Get active challenges only"""
    if db is None:
        return {"success": True, "challenges": []}
    try:
        challenges = await db.challenges.find({"is_active": True}, {"_id": 0}).to_list(100)
        return {"success": True, "challenges": challenges}
    except Exception as e:
        logger.warning(f"Failed to get active challenges: {e}")
        return {"success": True, "challenges": []}

@api_router.get("/challenges/completed")
async def get_completed_challenges():
    """Get completed challenges only"""
    if db is None:
        return {"success": True, "challenges": []}
    try:
        challenges = await db.challenges.find({"is_active": False}, {"_id": 0}).to_list(100)
        return {"success": True, "challenges": challenges}
    except Exception as e:
        logger.warning(f"Failed to get completed challenges: {e}")
        return {"success": True, "challenges": []}


# ==================== ADMIN ENDPOINTS ====================

@api_router.post("/admin/login")
async def admin_login(credentials: dict):
    """Admin login endpoint"""
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"success": True, "message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

@api_router.get("/admin/settings")
async def admin_get_all_settings(username: str = Depends(verify_admin)):
    """Get all leaderboard settings (admin only)"""
    all_settings = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        all_settings[site] = await get_leaderboard_settings(site)
    return {"success": True, "settings": all_settings}

@api_router.put("/admin/settings/{site}")
async def admin_update_settings(site: str, settings: LeaderboardSettingsUpdate, username: str = Depends(verify_admin)):
    """Update leaderboard settings for a site (admin only)"""
    site = site.lower()
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available. Please configure MongoDB on Vercel.")
    
    # Get existing settings
    existing = await get_leaderboard_settings(site)
    
    # Update only provided fields
    update_data = settings.model_dump(exclude_none=True)
    if update_data:
        existing.update(update_data)
        existing["site"] = site
        
        try:
            # Upsert to DB
            await db.leaderboard_settings.update_one(
                {"site": site},
                {"$set": existing},
                upsert=True
            )
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to save settings: {str(e)}")
    
    return {"success": True, "message": f"Settings for {site} updated", "settings": existing}

@api_router.get("/admin/challenges")
async def admin_get_challenges(username: str = Depends(verify_admin)):
    """Get all challenges (admin only)"""
    challenges = await db.challenges.find({}, {"_id": 0}).to_list(100)
    return {"success": True, "challenges": challenges}

@api_router.post("/admin/challenges")
async def admin_create_challenge(challenge: ChallengeCreate, username: str = Depends(verify_admin)):
    """Create a new challenge (admin only)"""
    challenge_dict = challenge.model_dump()
    challenge_dict["id"] = str(uuid.uuid4())
    challenge_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.challenges.insert_one(challenge_dict)
    
    # Remove MongoDB _id before returning
    challenge_dict.pop("_id", None)
    
    return {"success": True, "message": "Challenge created", "challenge": challenge_dict}

@api_router.put("/admin/challenges/{challenge_id}")
async def admin_update_challenge(challenge_id: str, challenge: ChallengeUpdate, username: str = Depends(verify_admin)):
    """Update a challenge (admin only)"""
    update_data = challenge.model_dump(exclude_none=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.challenges.update_one(
        {"id": challenge_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    updated = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
    return {"success": True, "message": "Challenge updated", "challenge": updated}

@api_router.delete("/admin/challenges/{challenge_id}")
async def admin_delete_challenge(challenge_id: str, username: str = Depends(verify_admin)):
    """Delete a challenge (admin only)"""
    result = await db.challenges.delete_one({"id": challenge_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return {"success": True, "message": "Challenge deleted"}


# Include the router in the main app
app.include_router(api_router)

@app.on_event("shutdown")
async def shutdown_db_client():
    if client:
        client.close()
