from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse, JSONResponse, FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
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
from datetime import datetime, timezone, timedelta
import httpx
import hashlib
import jwt
import urllib.parse


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
    if mongo_url:
        # Connect to MongoDB (works with Atlas or any MongoDB URL)
        client = AsyncIOMotorClient(mongo_url, serverSelectionTimeoutMS=10000)
        db = client[db_name]
        logger.info(f"MongoDB connection initialized to database: {db_name}")
    else:
        logger.warning("MONGO_URL not set - running without database")
except Exception as e:
    logger.warning(f"MongoDB connection failed: {e} - running without database")
    client = None
    db = None

# Kick OAuth configuration
KICK_CLIENT_ID = os.environ.get('KICK_CLIENT_ID', '')
KICK_CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET', '')
KICK_REDIRECT_URI = os.environ.get('KICK_REDIRECT_URI', '')
KICK_CHANNEL = os.environ.get('KICK_CHANNEL', 'pezslaps')
JWT_SECRET = os.environ.get('JWT_SECRET', 'pezrewards_super_secret_key_2026')

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

# Global exception handler to ensure CORS headers are always sent
from fastapi.responses import JSONResponse
from starlette.requests import Request

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*",
        }
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

# Shop & User Models
class ShopItemCreate(BaseModel):
    name: str
    description: str
    image_url: Optional[str] = None
    category: str = "digital"
    price_points: int
    stock: int = -1
    is_active: bool = True

class ShopItemUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    image_url: Optional[str] = None
    category: Optional[str] = None
    price_points: Optional[int] = None
    stock: Optional[int] = None
    is_active: Optional[bool] = None

class RedemptionCreate(BaseModel):
    item_id: str
    discord_username: str

class RedemptionStatusUpdate(BaseModel):
    status: str
    admin_notes: Optional[str] = None

class AdminUserUpdate(BaseModel):
    points_balance: Optional[int] = None
    is_banned: Optional[bool] = None
    can_redeem: Optional[bool] = None

class EarningRatesUpdate(BaseModel):
    chat_message_points: Optional[int] = None
    daily_cap: Optional[int] = None
    cooldown_seconds: Optional[int] = None

# JWT Helper Functions
def generate_code_verifier():
    return secrets.token_urlsafe(64)[:128]

def generate_code_challenge(verifier: str):
    import base64
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

def create_jwt_token(user_id: str, kick_username: str, is_admin: bool = False):
    payload = {
        "user_id": user_id,
        "kick_username": kick_username,
        "is_admin": is_admin,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(request: Request):
    token = request.cookies.get("auth_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
    
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    payload = verify_jwt_token(token)
    
    if db is not None:
        user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if user:
            if user.get("is_banned"):
                raise HTTPException(status_code=403, detail="Account is banned")
            return user
    
    return payload

async def get_admin_user(request: Request):
    user = await get_current_user(request)
    if user is None or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# PKCE store (in production use Redis)
pkce_store = {}


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
        "period_type": "bi-weekly",  # bi-weekly, monthly, weekly
        "register_link": "https://menace.com/?r=pez",
        "logo": "image/menace.png",
        "prizes": {
            "1": "$600", "2": "$300", "3": "$200", "4": "$150", "5": "$100",
            "6": "$60", "7": "$40", "8": "$30", "9": "$15", "10": "$5"
        },
        "start_date": "2026-02-07T00:00:00+00:00",
        "end_date": "2026-02-21T00:00:00+00:00",
        "needs_date_filter": True,  # This API uses date params
        "is_active": True
    },
    "metaspins": {
        "prize_pool": "$2,000",
        "period": "Monthly",
        "period_type": "monthly",
        "register_link": "https://metaspins.com/?ref=pezslaps",
        "logo": "image/metaspins-logo.png",
        "prizes": {
            "1": "$700", "2": "$400", "3": "$250", "4": "$175", "5": "$150",
            "6": "$110", "7": "$90", "8": "$75", "9": "$30", "10": "$20"
        },
        "start_date": "2026-02-01T00:00:00+00:00",
        "end_date": "2026-03-01T00:00:00+00:00",
        "needs_date_filter": False,  # Data filtered at their end
        "is_active": True
    },
    "bitfortune": {
        "prize_pool": "$5,000",
        "period": "Monthly",
        "period_type": "monthly",
        "register_link": "https://join.bitfortune.com/pezslaps",
        "logo": "image/bitfortune-logo.png",
        "prizes": {
            "1": "$2,000", "2": "$1,200", "3": "$700", "4": "$400", "5": "$250",
            "6": "$150", "7": "$120", "8": "$80", "9": "$60", "10": "$40"
        },
        "start_date": "2026-01-27T00:00:00+00:00",
        "end_date": "2026-02-27T00:00:00+00:00",
        "fetch_start": 1769472000,
        "fetch_end": 1772150400,
        "needs_date_filter": True,  # This API uses timestamp params
        "is_active": True
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
async def get_menace_leaderboard():
    """Fetch Menace leaderboard data with dates from settings"""
    try:
        # Get dates from settings
        settings = await get_leaderboard_settings("menace")
        
        # Parse dates from settings
        start_date = "2026-02-07"
        end_date = "2026-02-21"
        
        if settings.get("start_date"):
            try:
                start_dt = datetime.fromisoformat(settings["start_date"].replace('Z', '+00:00'))
                start_date = start_dt.strftime("%Y-%m-%d")
            except:
                pass
        
        if settings.get("end_date"):
            try:
                end_dt = datetime.fromisoformat(settings["end_date"].replace('Z', '+00:00'))
                end_date = end_dt.strftime("%Y-%m-%d")
            except:
                pass
        
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            url = f"https://api-prod.gaze.bet/api/leaderboard/LSNCGAYMCPRJ/fb7d008f-a6e5-4d00-81f9-2e4afd9c5b7a"
            params = {
                "dateStart": start_date,
                "dateEnd": end_date,
                "limit": 20
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
                    "data": formatted_users,
                    "period": {"start": start_date, "end": end_date}
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
    "metaspins": datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    "menace": datetime(2026, 2, 21, 0, 0, 0, tzinfo=timezone.utc),
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


# ==================== ADMIN LEADERBOARD TIMER MANAGEMENT ====================

def calculate_next_period_end(current_end: datetime, period_type: str) -> datetime:
    """Calculate the next period end date based on period type"""
    if period_type == "weekly":
        return current_end + timedelta(days=7)
    elif period_type == "bi-weekly":
        return current_end + timedelta(days=14)
    elif period_type == "monthly":
        # Add approximately one month
        if current_end.month == 12:
            return current_end.replace(year=current_end.year + 1, month=1)
        else:
            try:
                return current_end.replace(month=current_end.month + 1)
            except ValueError:
                # Handle months with different days (e.g., Jan 31 -> Feb 28)
                next_month = current_end.month + 1
                if next_month > 12:
                    next_month = 1
                    year = current_end.year + 1
                else:
                    year = current_end.year
                # Get last day of next month
                if next_month in [4, 6, 9, 11]:
                    day = min(current_end.day, 30)
                elif next_month == 2:
                    day = min(current_end.day, 28)
                else:
                    day = current_end.day
                return current_end.replace(year=year, month=next_month, day=day)
    else:
        return current_end + timedelta(days=30)  # Default to ~monthly


@api_router.get("/admin/leaderboard-timers")
async def admin_get_leaderboard_timers(username: str = Depends(verify_admin)):
    """Get all leaderboard timer settings (admin only)"""
    timers = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        settings = await get_leaderboard_settings(site)
        end_time = await get_leaderboard_end_time(site)
        current_time = datetime.now(timezone.utc)
        
        time_remaining = end_time - current_time if end_time else timedelta(0)
        is_ended = time_remaining.total_seconds() <= 0
        
        timers[site] = {
            "site": site,
            "period_type": settings.get("period_type", "monthly"),
            "period_label": settings.get("period", "Monthly"),
            "start_date": settings.get("start_date", ""),
            "end_date": settings.get("end_date", ""),
            "is_active": settings.get("is_active", True),
            "needs_date_filter": settings.get("needs_date_filter", False),
            "is_ended": is_ended,
            "days_remaining": max(0, time_remaining.days) if not is_ended else 0,
            "hours_remaining": max(0, time_remaining.seconds // 3600) if not is_ended else 0,
            "fetch_start": settings.get("fetch_start"),
            "fetch_end": settings.get("fetch_end")
        }
    
    return {"success": True, "timers": timers}


class LeaderboardTimerUpdate(BaseModel):
    period_type: Optional[str] = None  # weekly, bi-weekly, monthly
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    is_active: Optional[bool] = None
    fetch_start: Optional[int] = None  # For bitfortune timestamp
    fetch_end: Optional[int] = None


@api_router.put("/admin/leaderboard-timers/{site}")
async def admin_update_leaderboard_timer(site: str, timer_update: LeaderboardTimerUpdate, username: str = Depends(verify_admin)):
    """Update leaderboard timer settings (admin only)"""
    site = site.lower()
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get existing settings
    existing = await get_leaderboard_settings(site)
    
    # Update fields
    update_data = timer_update.model_dump(exclude_none=True)
    
    if "period_type" in update_data:
        existing["period_type"] = update_data["period_type"]
        # Update period label
        period_labels = {"weekly": "Weekly", "bi-weekly": "Bi-Weekly", "monthly": "Monthly"}
        existing["period"] = period_labels.get(update_data["period_type"], "Monthly")
    
    if "start_date" in update_data:
        existing["start_date"] = update_data["start_date"]
    
    if "end_date" in update_data:
        existing["end_date"] = update_data["end_date"]
    
    if "is_active" in update_data:
        existing["is_active"] = update_data["is_active"]
    
    if "fetch_start" in update_data:
        existing["fetch_start"] = update_data["fetch_start"]
    
    if "fetch_end" in update_data:
        existing["fetch_end"] = update_data["fetch_end"]
    
    existing["site"] = site
    
    # Save to DB
    await db.leaderboard_settings.update_one(
        {"site": site},
        {"$set": existing},
        upsert=True
    )
    
    return {"success": True, "message": f"Timer for {site} updated", "settings": existing}


@api_router.post("/admin/leaderboard-timers/{site}/reset")
async def admin_reset_leaderboard_timer(site: str, username: str = Depends(verify_admin)):
    """Manually reset a leaderboard timer - starts new period (admin only)"""
    site = site.lower()
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get existing settings
    existing = await get_leaderboard_settings(site)
    period_type = existing.get("period_type", "monthly")
    
    # Get current end date
    old_end_str = existing.get("end_date", "")
    if old_end_str:
        old_end = datetime.fromisoformat(old_end_str.replace('Z', '+00:00'))
    else:
        old_end = datetime.now(timezone.utc)
    
    # Calculate new dates
    new_start = old_end
    new_end = calculate_next_period_end(old_end, period_type)
    
    # Update settings
    existing["start_date"] = new_start.isoformat()
    existing["end_date"] = new_end.isoformat()
    existing["site"] = site
    existing["last_reset"] = datetime.now(timezone.utc).isoformat()
    
    # For Bitfortune, also update timestamps
    if site == "bitfortune":
        existing["fetch_start"] = int(new_start.timestamp())
        existing["fetch_end"] = int(new_end.timestamp())
    
    # Save to DB
    await db.leaderboard_settings.update_one(
        {"site": site},
        {"$set": existing},
        upsert=True
    )
    
    return {
        "success": True, 
        "message": f"Timer for {site} reset. New period: {new_start.strftime('%Y-%m-%d')} to {new_end.strftime('%Y-%m-%d')}",
        "new_start": new_start.isoformat(),
        "new_end": new_end.isoformat()
    }


async def check_and_auto_reset_leaderboards():
    """Check if any leaderboard timers have ended and auto-reset them"""
    if db is None:
        return
    
    for site in ["menace", "metaspins", "bitfortune"]:
        try:
            settings = await get_leaderboard_settings(site)
            
            if not settings.get("is_active", True):
                continue
            
            end_date_str = settings.get("end_date")
            if not end_date_str:
                continue
            
            end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
            current_time = datetime.now(timezone.utc)
            
            # Check if ended
            if current_time >= end_date:
                logger.info(f"Auto-resetting leaderboard timer for {site}")
                
                period_type = settings.get("period_type", "monthly")
                new_start = end_date
                new_end = calculate_next_period_end(end_date, period_type)
                
                # Update settings
                settings["start_date"] = new_start.isoformat()
                settings["end_date"] = new_end.isoformat()
                settings["last_reset"] = current_time.isoformat()
                settings["site"] = site
                
                # For Bitfortune, also update timestamps
                if site == "bitfortune":
                    settings["fetch_start"] = int(new_start.timestamp())
                    settings["fetch_end"] = int(new_end.timestamp())
                
                await db.leaderboard_settings.update_one(
                    {"site": site},
                    {"$set": settings},
                    upsert=True
                )
                
                logger.info(f"Leaderboard {site} auto-reset: {new_start.strftime('%Y-%m-%d')} to {new_end.strftime('%Y-%m-%d')}")
                
        except Exception as e:
            logger.error(f"Error checking/resetting leaderboard {site}: {e}")


# Background task to check leaderboard timers periodically
@app.on_event("startup")
async def start_timer_checker():
    """Start background task to check leaderboard timers"""
    import asyncio
    
    async def timer_check_loop():
        while True:
            await asyncio.sleep(3600)  # Check every hour
            await check_and_auto_reset_leaderboards()
    
    asyncio.create_task(timer_check_loop())
    logger.info("Leaderboard timer checker started (runs every hour)")


@api_router.get("/admin/challenges")
async def admin_get_challenges(username: str = Depends(verify_admin)):
    """Get all challenges (admin only)"""
    if db is None:
        return {"success": True, "challenges": []}
    try:
        challenges = await db.challenges.find({}, {"_id": 0}).to_list(100)
        return {"success": True, "challenges": challenges}
    except Exception as e:
        logger.error(f"Failed to get challenges: {e}")
        return {"success": True, "challenges": []}

@api_router.post("/admin/challenges")
async def admin_create_challenge(challenge: ChallengeCreate, username: str = Depends(verify_admin)):
    """Create a new challenge (admin only)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available. Please configure MongoDB on Vercel.")
    
    try:
        challenge_dict = challenge.model_dump()
        challenge_dict["id"] = str(uuid.uuid4())
        challenge_dict["created_at"] = datetime.now(timezone.utc).isoformat()
        
        await db.challenges.insert_one(challenge_dict)
        
        # Remove MongoDB _id before returning
        challenge_dict.pop("_id", None)
        
        return {"success": True, "message": "Challenge created", "challenge": challenge_dict}
    except Exception as e:
        logger.error(f"Failed to create challenge: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create challenge: {str(e)}")

@api_router.put("/admin/challenges/{challenge_id}")
async def admin_update_challenge(challenge_id: str, challenge: ChallengeUpdate, username: str = Depends(verify_admin)):
    """Update a challenge (admin only)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available. Please configure MongoDB on Vercel.")
    
    update_data = challenge.model_dump(exclude_none=True)
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    try:
        result = await db.challenges.update_one(
            {"id": challenge_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Challenge not found")
        
        updated = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
        return {"success": True, "message": "Challenge updated", "challenge": updated}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update challenge: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update challenge: {str(e)}")

@api_router.delete("/admin/challenges/{challenge_id}")
async def admin_delete_challenge(challenge_id: str, username: str = Depends(verify_admin)):
    """Delete a challenge (admin only)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available. Please configure MongoDB on Vercel.")
    
    try:
        result = await db.challenges.delete_one({"id": challenge_id})
        
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Challenge not found")
        
        return {"success": True, "message": "Challenge deleted"}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete challenge: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete challenge: {str(e)}")


# ==================== KICK OAUTH ENDPOINTS ====================

@api_router.get("/auth/kick/login")
async def kick_login(request: Request):
    """Initiate Kick OAuth login"""
    state = secrets.token_urlsafe(32)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    pkce_store[state] = code_verifier
    
    params = {
        "client_id": KICK_CLIENT_ID,
        "redirect_uri": KICK_REDIRECT_URI,
        "response_type": "code",
        "scope": "user:read events:subscribe chat:write",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"https://id.kick.com/oauth/authorize?{urllib.parse.urlencode(params)}"
    return {"auth_url": auth_url}

@api_router.get("/auth/callback/kick")
async def kick_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Handle Kick OAuth callback - for both user login and bot authorization"""
    
    # Check if this is a bot authorization (state starts with "bot_")
    is_bot_auth = state and state.startswith("bot_")
    
    if error:
        logger.error(f"OAuth error: {error}")
        if is_bot_auth:
            return RedirectResponse(url=f"/admin/dashboard.html?bot_error={error}")
        return RedirectResponse(url="/?error=auth_failed")
    
    if not code or not state:
        if is_bot_auth:
            return RedirectResponse(url="/admin/dashboard.html?bot_error=missing_params")
        return RedirectResponse(url="/?error=missing_params")
    
    code_verifier = pkce_store.pop(state, None)
    if not code_verifier:
        if is_bot_auth:
            return RedirectResponse(url="/admin/dashboard.html?bot_error=invalid_state")
        return RedirectResponse(url="/?error=invalid_state")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            token_response = await http_client.post(
                "https://id.kick.com/oauth/token",
                data={
                    "grant_type": "authorization_code",
                    "client_id": KICK_CLIENT_ID,
                    "client_secret": KICK_CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": KICK_REDIRECT_URI,
                    "code_verifier": code_verifier
                }
            )
            
            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_response.text}")
                if is_bot_auth:
                    return RedirectResponse(url="/admin/dashboard.html?bot_error=token_failed")
                return RedirectResponse(url="/?error=token_failed")
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            
            user_response = await http_client.get(
                "https://api.kick.com/public/v1/users",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code != 200:
                logger.error(f"User fetch failed: {user_response.text}")
                if is_bot_auth:
                    return RedirectResponse(url="/admin/dashboard.html?bot_error=user_fetch_failed")
                return RedirectResponse(url="/?error=user_fetch_failed")
            
            kick_user = user_response.json()
            logger.info(f"Kick user response: {kick_user}")
            
            # Handle different response structures from Kick API
            # Could be: direct object, list, or nested in "data"
            if isinstance(kick_user, list) and len(kick_user) > 0:
                kick_user = kick_user[0]
            elif isinstance(kick_user, dict):
                if "data" in kick_user:
                    kick_user = kick_user["data"]
                    if isinstance(kick_user, list) and len(kick_user) > 0:
                        kick_user = kick_user[0]
                elif "user" in kick_user:
                    kick_user = kick_user["user"]
            
            # If this is bot authorization, save tokens to settings and subscribe to events
            if is_bot_auth:
                kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug") or "Unknown"
                kick_user_id = kick_user.get("user_id") or kick_user.get("id") or kick_user.get("userId")
                
                if db is not None:
                    await db.settings.update_one(
                        {"type": "bot_tokens"},
                        {"$set": {
                            "type": "bot_tokens",
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "username": kick_username,
                            "user_id": kick_user_id,
                            "authorized_at": datetime.now(timezone.utc).isoformat()
                        }},
                        upsert=True
                    )
                
                # Subscribe to chat.message.sent events
                try:
                    sub_response = await http_client.post(
                        "https://api.kick.com/public/v1/events/subscriptions",
                        headers={
                            "Authorization": f"Bearer {access_token}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "events": [
                                {"name": "chat.message.sent", "version": 1},
                                {"name": "channel.followed", "version": 1}
                            ],
                            "method": "webhook"
                        }
                    )
                    logger.info(f"Event subscription response: {sub_response.status_code} - {sub_response.text}")
                except Exception as sub_error:
                    logger.error(f"Event subscription error: {sub_error}")
                
                logger.info(f"Bot authorized successfully by {kick_username}")
                return RedirectResponse(url=f"/admin/dashboard.html?bot_success=true&bot_user={kick_username}")
            
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        if is_bot_auth:
            return RedirectResponse(url="/admin/dashboard.html?bot_error=oauth_error")
        return RedirectResponse(url="/?error=oauth_error")
    
    client_ip = request.client.host
    
    if db is not None:
        # Try multiple field names for compatibility
        kick_id = str(kick_user.get("id") or kick_user.get("user_id") or kick_user.get("userId") or "")
        kick_username = kick_user.get("username") or kick_user.get("name") or kick_user.get("slug") or "User"
        avatar = kick_user.get("profile_pic") or kick_user.get("avatar") or kick_user.get("profile_picture") or ""
        
        logger.info(f"Parsed user - ID: {kick_id}, Username: {kick_username}, Avatar: {avatar}")
        
        existing_user = await db.users.find_one({"kick_id": kick_id})
        
        if existing_user:
            await db.users.update_one({"kick_id": kick_id}, {"$set": {
                "kick_username": kick_username,
                "avatar": avatar,
                "last_login": datetime.now(timezone.utc).isoformat(),
                "access_token": access_token,
                "refresh_token": refresh_token
            }})
            user_id = existing_user["id"]
            is_admin = existing_user.get("is_admin", False)
        else:
            user_id = str(uuid.uuid4())
            new_user = {
                "id": user_id,
                "kick_id": kick_id,
                "kick_username": kick_username,
                "avatar": avatar,
                "discord_username": None,
                "points_balance": 0,
                "total_earned": 0,
                "total_spent": 0,
                "registered_at": datetime.now(timezone.utc).isoformat(),
                "last_login": datetime.now(timezone.utc).isoformat(),
                "ip_addresses": [client_ip],
                "is_banned": False,
                "can_redeem": True,
                "is_admin": False,
                "access_token": access_token,
                "refresh_token": refresh_token
            }
            await db.users.insert_one(new_user)
            is_admin = False
    else:
        user_id = str(uuid.uuid4())
        kick_username = kick_user.get("username", "Unknown")
        is_admin = False
    
    jwt_token = create_jwt_token(user_id, kick_username, is_admin)
    
    response = RedirectResponse(url="/shop.html")
    response.set_cookie(key="auth_token", value=jwt_token, httponly=True, secure=True, samesite="lax", max_age=7*24*60*60)
    return response

@api_router.get("/auth/me")
async def get_me(request: Request):
    """Get current user info"""
    try:
        user = await get_current_user(request)
        if user:
            safe_user = {k: v for k, v in user.items() if k not in ["access_token", "refresh_token", "_id"]}
            return {"success": True, "user": safe_user}
    except HTTPException:
        pass
    return {"success": False, "user": None}

@api_router.post("/auth/logout")
async def logout(response: Response):
    """Logout user"""
    resp = JSONResponse({"success": True, "message": "Logged out"})
    resp.delete_cookie("auth_token")
    return resp

# ==================== USER ENDPOINTS ====================

@api_router.get("/users/redemptions")
async def get_user_redemptions(request: Request):
    """Get user's redemption history"""
    user = await get_current_user(request)
    if db is None:
        return {"success": True, "redemptions": []}
    
    redemptions = await db.redemptions.find(
        {"user_id": user["id"]},
        {"_id": 0}
    ).sort("created_at", -1).to_list(50)
    
    return {"success": True, "redemptions": redemptions}

# ==================== SHOP ENDPOINTS ====================

@api_router.get("/shop/items")
async def get_shop_items(active_only: bool = True):
    """Get all shop items"""
    if db is None:
        return {"success": True, "items": []}
    query = {"is_active": True} if active_only else {}
    items = await db.shop_items.find(query, {"_id": 0}).to_list(100)
    return {"success": True, "items": items}

@api_router.post("/shop/redeem")
async def redeem_item(redemption: RedemptionCreate, request: Request):
    """Redeem a shop item"""
    user = await get_current_user(request)
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    if not user.get("can_redeem", True):
        raise HTTPException(status_code=403, detail="You are not allowed to redeem items")
    
    item = await db.shop_items.find_one({"id": redemption.item_id}, {"_id": 0})
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    
    if not item.get("is_active"):
        raise HTTPException(status_code=400, detail="Item is not available")
    
    if item.get("stock", -1) != -1 and item.get("stock", 0) <= 0:
        raise HTTPException(status_code=400, detail="Item out of stock")
    
    if user.get("points_balance", 0) < item["price_points"]:
        raise HTTPException(status_code=400, detail="Insufficient points")
    
    # Save discord username
    if redemption.discord_username:
        await db.users.update_one({"id": user["id"]}, {"$set": {"discord_username": redemption.discord_username}})
    
    # Deduct points
    new_balance = user["points_balance"] - item["price_points"]
    await db.users.update_one({"id": user["id"]}, {"$set": {"points_balance": new_balance}, "$inc": {"total_spent": item["price_points"]}})
    
    # Update stock
    if item.get("stock", -1) != -1:
        await db.shop_items.update_one({"id": item["id"]}, {"$inc": {"stock": -1, "total_claims": 1}})
    else:
        await db.shop_items.update_one({"id": item["id"]}, {"$inc": {"total_claims": 1}})
    
    # Create redemption record
    redemption_id = str(uuid.uuid4())
    redemption_record = {
        "id": redemption_id,
        "user_id": user["id"],
        "item_id": item["id"],
        "item_name": item["name"],
        "points_spent": item["price_points"],
        "status": "pending",
        "kick_username": user["kick_username"],
        "discord_username": redemption.discord_username,
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.redemptions.insert_one(redemption_record)
    
    return {"success": True, "message": "Item redeemed! Create a ticket on Discord.", "redemption_id": redemption_id, "new_balance": new_balance}

# ==================== POINTS ENDPOINTS ====================

@api_router.get("/points/balance")
async def get_points_balance(request: Request):
    """Get user's current points balance"""
    user = await get_current_user(request)
    return {
        "success": True,
        "balance": user.get("points_balance", 0),
        "total_earned": user.get("total_earned", 0),
        "total_spent": user.get("total_spent", 0)
    }

# ==================== ADMIN SHOP ENDPOINTS ====================

@api_router.get("/admin/shop/items")
async def admin_get_shop_items(username: str = Depends(verify_admin)):
    """Get all shop items (admin)"""
    if db is None:
        return {"success": True, "items": []}
    items = await db.shop_items.find({}, {"_id": 0}).to_list(100)
    return {"success": True, "items": items}

@api_router.post("/admin/shop/items")
async def admin_create_shop_item(item: ShopItemCreate, username: str = Depends(verify_admin)):
    """Create shop item (admin)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    item_dict = item.model_dump()
    item_dict["id"] = str(uuid.uuid4())
    item_dict["total_claims"] = 0
    item_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.shop_items.insert_one(item_dict)
    item_dict.pop("_id", None)
    return {"success": True, "item": item_dict}

@api_router.put("/admin/shop/items/{item_id}")
async def admin_update_shop_item(item_id: str, update: ShopItemUpdate, username: str = Depends(verify_admin)):
    """Update shop item (admin)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.shop_items.update_one({"id": item_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    
    updated = await db.shop_items.find_one({"id": item_id}, {"_id": 0})
    return {"success": True, "item": updated}

@api_router.delete("/admin/shop/items/{item_id}")
async def admin_delete_shop_item(item_id: str, username: str = Depends(verify_admin)):
    """Delete shop item (admin)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.shop_items.delete_one({"id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    
    return {"success": True, "message": "Item deleted"}

# ==================== ADMIN REDEMPTIONS ====================

@api_router.get("/admin/redemptions")
async def admin_get_redemptions(status: Optional[str] = None, username: str = Depends(verify_admin)):
    """Get all redemptions (admin)"""
    if db is None:
        return {"success": True, "redemptions": [], "counts": {"pending": 0, "approved": 0, "rejected": 0}}
    
    query = {"status": status} if status else {}
    redemptions = await db.redemptions.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    pending = await db.redemptions.count_documents({"status": "pending"})
    approved = await db.redemptions.count_documents({"status": "approved"})
    rejected = await db.redemptions.count_documents({"status": "rejected"})
    
    return {"success": True, "redemptions": redemptions, "counts": {"pending": pending, "approved": approved, "rejected": rejected}}

@api_router.put("/admin/redemptions/{redemption_id}")
async def admin_update_redemption(redemption_id: str, update: RedemptionStatusUpdate, username: str = Depends(verify_admin)):
    """Approve or reject redemption (admin)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    redemption = await db.redemptions.find_one({"id": redemption_id}, {"_id": 0})
    if not redemption:
        raise HTTPException(status_code=404, detail="Redemption not found")
    
    if redemption["status"] != "pending":
        raise HTTPException(status_code=400, detail="Redemption already processed")
    
    # If rejected, refund points
    if update.status == "rejected":
        user = await db.users.find_one({"id": redemption["user_id"]}, {"_id": 0})
        if user:
            new_balance = user["points_balance"] + redemption["points_spent"]
            await db.users.update_one({"id": user["id"]}, {"$set": {"points_balance": new_balance}, "$inc": {"total_spent": -redemption["points_spent"]}})
    
    await db.redemptions.update_one({"id": redemption_id}, {"$set": {"status": update.status, "admin_notes": update.admin_notes, "handled_at": datetime.now(timezone.utc).isoformat()}})
    
    updated = await db.redemptions.find_one({"id": redemption_id}, {"_id": 0})
    return {"success": True, "redemption": updated}

# ==================== ADMIN ALT-ACCOUNTS ====================

@api_router.get("/admin/alt-accounts")
async def admin_get_alt_accounts(username: str = Depends(verify_admin)):
    """Get potential alt accounts grouped by IP address"""
    if db is None:
        return {"success": True, "alt_accounts": []}
    
    try:
        # Aggregate users by IP addresses, find IPs with multiple users
        pipeline = [
            {"$unwind": "$ip_addresses"},
            {"$group": {
                "_id": "$ip_addresses",
                "users": {"$push": {
                    "id": "$id",
                    "kick_username": "$kick_username",
                    "discord_username": "$discord_username",
                    "points_balance": "$points_balance",
                    "registered_at": "$registered_at",
                    "is_banned": "$is_banned"
                }},
                "count": {"$sum": 1}
            }},
            {"$match": {"count": {"$gt": 1}}},  # Only IPs with more than 1 user
            {"$sort": {"count": -1}}
        ]
        
        results = await db.users.aggregate(pipeline).to_list(100)
        
        alt_accounts = []
        for result in results:
            alt_accounts.append({
                "ip_address": result["_id"],
                "user_count": result["count"],
                "users": result["users"]
            })
        
        return {"success": True, "alt_accounts": alt_accounts, "total_groups": len(alt_accounts)}
    except Exception as e:
        logger.error(f"Failed to get alt accounts: {e}")
        return {"success": True, "alt_accounts": [], "total_groups": 0}


# ==================== ADMIN USERS ====================

@api_router.get("/admin/users")
async def admin_get_users(search: Optional[str] = None, username: str = Depends(verify_admin)):
    """Get all users (admin)"""
    if db is None:
        return {"success": True, "users": []}
    
    query = {}
    if search:
        query["$or"] = [{"kick_username": {"$regex": search, "$options": "i"}}, {"discord_username": {"$regex": search, "$options": "i"}}]
    
    users = await db.users.find(query, {"_id": 0, "access_token": 0, "refresh_token": 0}).sort("registered_at", -1).to_list(100)
    return {"success": True, "users": users}

@api_router.put("/admin/users/{user_id}")
async def admin_update_user(user_id: str, update: AdminUserUpdate, username: str = Depends(verify_admin)):
    """Update user (admin)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.users.update_one({"id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "user": updated}


# ==================== ADMIN BAN MANAGEMENT ====================

@api_router.post("/admin/users/{user_id}/ban")
async def admin_ban_user(user_id: str, username: str = Depends(verify_admin)):
    """Ban a user"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.users.update_one(
        {"id": user_id}, 
        {"$set": {"is_banned": True, "banned_at": datetime.now(timezone.utc).isoformat()}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User banned successfully", "user": updated}


@api_router.post("/admin/users/{user_id}/unban")
async def admin_unban_user(user_id: str, username: str = Depends(verify_admin)):
    """Unban a user"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.users.update_one(
        {"id": user_id}, 
        {"$set": {"is_banned": False}, "$unset": {"banned_at": ""}}
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User unbanned successfully", "user": updated}


# ==================== ADMIN POINTS MANAGEMENT ====================

class PointsAdjustment(BaseModel):
    amount: int
    reason: Optional[str] = None

@api_router.post("/admin/users/{user_id}/adjust-points")
async def admin_adjust_points(user_id: str, adjustment: PointsAdjustment, username: str = Depends(verify_admin)):
    """Adjust user points (add or subtract)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_balance = user.get("points_balance", 0)
    new_balance = current_balance + adjustment.amount
    
    # Prevent negative balance
    if new_balance < 0:
        raise HTTPException(status_code=400, detail="Cannot reduce balance below 0")
    
    # Update balance and log the adjustment
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"points_balance": new_balance}}
    )
    
    # Log the adjustment
    adjustment_log = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "admin": username,
        "amount": adjustment.amount,
        "reason": adjustment.reason or "Manual adjustment",
        "previous_balance": current_balance,
        "new_balance": new_balance,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    await db.point_adjustments.insert_one(adjustment_log)
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {
        "success": True, 
        "message": f"Points adjusted by {adjustment.amount:+d}",
        "user": updated,
        "adjustment": {k: v for k, v in adjustment_log.items() if k != "_id"}
    }


@api_router.get("/admin/point-adjustments")
async def admin_get_point_adjustments(user_id: Optional[str] = None, username: str = Depends(verify_admin)):
    """Get point adjustment history"""
    if db is None:
        return {"success": True, "adjustments": []}
    
    query = {}
    if user_id:
        query["user_id"] = user_id
    
    adjustments = await db.point_adjustments.find(query, {"_id": 0}).sort("timestamp", -1).to_list(100)
    return {"success": True, "adjustments": adjustments}


# ==================== EARNING RATES SETTINGS ====================

@api_router.get("/admin/earning-rates")
async def admin_get_earning_rates(username: str = Depends(verify_admin)):
    """Get current earning rates configuration"""
    if db is None:
        # Return defaults
        return {
            "success": True,
            "rates": {
                "chat_message_points": int(os.environ.get('POINTS_PER_MESSAGE', '1')),
                "cooldown_seconds": 30,
                "daily_cap": 1000
            }
        }
    
    rates = await db.settings.find_one({"type": "earning_rates"}, {"_id": 0})
    if not rates:
        rates = {
            "type": "earning_rates",
            "chat_message_points": int(os.environ.get('POINTS_PER_MESSAGE', '1')),
            "cooldown_seconds": 30,
            "daily_cap": 1000
        }
        await db.settings.insert_one(rates)
    
    return {"success": True, "rates": {k: v for k, v in rates.items() if k != "type"}}


@api_router.put("/admin/earning-rates")
async def admin_update_earning_rates(update: EarningRatesUpdate, username: str = Depends(verify_admin)):
    """Update earning rates configuration"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    await db.settings.update_one(
        {"type": "earning_rates"},
        {"$set": update_data},
        upsert=True
    )
    
    rates = await db.settings.find_one({"type": "earning_rates"}, {"_id": 0})
    return {"success": True, "message": "Earning rates updated", "rates": {k: v for k, v in rates.items() if k != "type"}}


# ==================== BOT OAUTH & STATUS ====================

@api_router.get("/admin/bot-status")
async def admin_get_bot_status(username: str = Depends(verify_admin)):
    """Get Kick bot status and configuration"""
    if db is None:
        return {"success": True, "bot": {"status": "not_configured"}}
    
    # Check if bot tokens exist
    bot_tokens = await db.settings.find_one({"type": "bot_tokens"}, {"_id": 0})
    is_authorized = bot_tokens is not None and bot_tokens.get("access_token")
    
    bot_config = {
        "target_channel": os.environ.get('KICK_CHANNEL', 'mrbetsit'),
        "points_per_message": int(os.environ.get('POINTS_PER_MESSAGE', '1')),
        "status": "authorized" if is_authorized else "not_authorized",
        "authorized_user": bot_tokens.get("username") if bot_tokens else None,
        "commands": ["!points", "!tip @user amount", "!leaderboard", "!lb"]
    }
    return {"success": True, "bot": bot_config}


@api_router.get("/admin/bot/authorize")
async def admin_bot_authorize(username: str = Depends(verify_admin)):
    """Generate OAuth URL to authorize the bot"""
    # Generate state and code verifier for PKCE
    # Use 'bot_' prefix to identify this as bot authorization
    state = "bot_" + secrets.token_urlsafe(32)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store state for verification - use pkce_store with special marker
    pkce_store[state] = code_verifier
    
    # Build authorization URL - use the SAME redirect URI that's registered
    client_id = os.environ.get('KICK_CLIENT_ID')
    redirect_uri = os.environ.get('KICK_REDIRECT_URI')  # Use the registered one
    
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "user:read channel:read chat:write events:subscribe",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"https://id.kick.com/oauth/authorize?{urllib.parse.urlencode(params)}"
    
    return {"success": True, "auth_url": auth_url}


@api_router.post("/admin/bot/revoke")
async def admin_bot_revoke(username: str = Depends(verify_admin)):
    """Revoke bot authorization"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    await db.settings.delete_one({"type": "bot_tokens"})
    return {"success": True, "message": "Bot authorization revoked"}


# ============================================
# KICK WEBHOOK & CHAT BOT INTEGRATION
# Official Kick API webhooks for chat events
# ============================================

# In-memory cooldown tracking for point earning
message_cooldowns = {}
COOLDOWN_SECONDS = 30
POINTS_PER_MESSAGE = int(os.environ.get('POINTS_PER_MESSAGE', '1'))
KICK_CHANNEL = os.environ.get('KICK_CHANNEL', 'mrbetsit')


async def get_bot_access_token():
    """Get the bot's access token from database"""
    if db is None:
        return None
    try:
        settings = await db.settings.find_one({"type": "bot_tokens"})
        if settings and settings.get("access_token"):
            return settings.get("access_token")
    except Exception as e:
        logger.error(f"Error getting bot token: {e}")
    return None


async def send_kick_chat_message(message: str, broadcaster_user_id: int = None):
    """Send a chat message via Kick API"""
    access_token = await get_bot_access_token()
    if not access_token:
        logger.error("No bot access token available")
        return False
    
    try:
        async with httpx.AsyncClient() as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Send as user type with broadcaster_user_id
            # The token owner sends the message to their own channel
            payload = {
                "content": message,
                "type": "user"
            }
            
            # Get the bot's user_id from settings to use as broadcaster
            if db is not None:
                bot_settings = await db.settings.find_one({"type": "bot_tokens"})
                if bot_settings and bot_settings.get("user_id"):
                    payload["broadcaster_user_id"] = bot_settings.get("user_id")
            
            response = await client.post(
                "https://api.kick.com/public/v1/chat",
                headers=headers,
                json=payload
            )
            
            if response.status_code == 200:
                logger.info(f"Sent chat message: {message}")
                return True
            else:
                logger.error(f"Failed to send chat: {response.status_code} - {response.text}")
                return False
                
    except Exception as e:
        logger.error(f"Error sending chat message: {e}")
        return False


def can_earn_points(user_id: int) -> bool:
    """Check if user can earn points (cooldown check)"""
    now = datetime.now(timezone.utc)
    if user_id in message_cooldowns:
        last_earned = message_cooldowns[user_id]
        if (now - last_earned).total_seconds() < COOLDOWN_SECONDS:
            return False
    return True


def update_cooldown(user_id: int):
    """Update user's cooldown timestamp"""
    message_cooldowns[user_id] = datetime.now(timezone.utc)


async def award_points_for_chat(username: str, user_id: int):
    """Award points to a user for chatting"""
    if db is None:
        return False
    
    if not can_earn_points(user_id):
        return False
    
    try:
        # Find user by kick username or kick_user_id
        user = await db.users.find_one({
            "$or": [
                {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
                {"kick_user_id": str(user_id)}
            ]
        })
        
        if not user:
            return False
        
        if user.get('is_banned', False):
            return False
        
        # Award points
        result = await db.users.update_one(
            {"_id": user["_id"]},
            {"$inc": {"points_balance": POINTS_PER_MESSAGE}}
        )
        
        if result.modified_count > 0:
            update_cooldown(user_id)
            logger.info(f"Awarded {POINTS_PER_MESSAGE} point(s) to {username}")
            return True
            
    except Exception as e:
        logger.error(f"Error awarding points: {e}")
    
    return False


async def handle_points_command(username: str):
    """Handle !points command"""
    if db is None:
        return "Service temporarily unavailable"
    
    user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
        {"_id": 0, "points_balance": 1}
    )
    
    if user:
        balance = user.get('points_balance', 0)
        return f"@{username} You have {balance:,.0f} points!"
    else:
        return f"@{username} You haven't registered yet! Visit the website to login with Kick."


async def handle_leaderboard_command():
    """Handle !leaderboard command"""
    if db is None:
        return "Service temporarily unavailable"
    
    cursor = db.users.find(
        {"is_banned": {"$ne": True}, "points_balance": {"$gt": 0}},
        {"_id": 0, "kick_username": 1, "points_balance": 1}
    ).sort("points_balance", -1).limit(5)
    
    users = await cursor.to_list(length=5)
    
    if not users:
        return "No users on the leaderboard yet!"
    
    medals = ["1st", "2nd", "3rd", "4th", "5th"]
    parts = []
    for i, user in enumerate(users):
        username = user.get('kick_username', 'Unknown')
        points = user.get('points_balance', 0)
        parts.append(f"{medals[i]}: {username} ({points:,.0f})")
    
    return "Leaderboard: " + " | ".join(parts)


async def handle_tip_command(sender: str, content: str):
    """Handle !tip @user amount command"""
    # Only channel owner can tip
    if sender.lower() != KICK_CHANNEL.lower():
        return f"@{sender} Only the channel owner can use !tip"
    
    parts = content.split()
    if len(parts) < 3:
        return f"@{sender} Usage: !tip @username amount"
    
    target = parts[1].lstrip('@')
    try:
        amount = int(parts[2])
    except ValueError:
        return f"@{sender} Invalid amount"
    
    if amount <= 0:
        return f"@{sender} Amount must be positive!"
    
    if db is None:
        return "Service temporarily unavailable"
    
    # Find target user
    target_user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"_id": 0, "kick_username": 1}
    )
    
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    # Add points
    result = await db.users.update_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"$inc": {"points_balance": amount}}
    )
    
    if result.modified_count > 0:
        return f"@{sender} gave {amount:,} points to @{target}!"
    else:
        return f"@{sender} Failed to tip. Please try again."


async def handle_addpoints_command(sender: str, content: str):
    """Handle !addpoints @user amount command (owner only)"""
    if sender.lower() != KICK_CHANNEL.lower():
        return f"@{sender} Only the channel owner can use !addpoints"
    
    parts = content.split()
    if len(parts) < 3:
        return f"@{sender} Usage: !addpoints @username amount"
    
    target = parts[1].lstrip('@')
    try:
        amount = int(parts[2])
    except ValueError:
        return f"@{sender} Invalid amount"
    
    if amount <= 0:
        return f"@{sender} Amount must be positive!"
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}}
    )
    
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"$inc": {"points_balance": amount}}
    )
    
    if result.modified_count > 0:
        return f"@{sender} Added {amount:,} points to @{target}!"
    else:
        return f"@{sender} Failed to add points."


async def handle_removepoints_command(sender: str, content: str):
    """Handle !removepoints @user amount command (owner only)"""
    if sender.lower() != KICK_CHANNEL.lower():
        return f"@{sender} Only the channel owner can use !removepoints"
    
    parts = content.split()
    if len(parts) < 3:
        return f"@{sender} Usage: !removepoints @username amount"
    
    target = parts[1].lstrip('@')
    try:
        amount = int(parts[2])
    except ValueError:
        return f"@{sender} Invalid amount"
    
    if amount <= 0:
        return f"@{sender} Amount must be positive!"
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"_id": 0, "points_balance": 1}
    )
    
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    current_balance = target_user.get('points_balance', 0)
    new_balance = max(0, current_balance - amount)  # Don't go below 0
    
    result = await db.users.update_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"$set": {"points_balance": new_balance}}
    )
    
    if result.modified_count > 0:
        removed = current_balance - new_balance
        return f"@{sender} Removed {removed:,} points from @{target}. New balance: {new_balance:,}"
    else:
        return f"@{sender} Failed to remove points."


async def handle_setpoints_command(sender: str, content: str):
    """Handle !setpoints @user amount command (owner only)"""
    if sender.lower() != KICK_CHANNEL.lower():
        return f"@{sender} Only the channel owner can use !setpoints"
    
    parts = content.split()
    if len(parts) < 3:
        return f"@{sender} Usage: !setpoints @username amount"
    
    target = parts[1].lstrip('@')
    try:
        amount = int(parts[2])
    except ValueError:
        return f"@{sender} Invalid amount"
    
    if amount < 0:
        return f"@{sender} Amount cannot be negative!"
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}}
    )
    
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"$set": {"points_balance": amount}}
    )
    
    if result.modified_count > 0:
        return f"@{sender} Set @{target}'s points to {amount:,}!"
    else:
        return f"@{sender} Failed to set points."


async def handle_ban_command(sender: str, content: str):
    """Handle !ban @user command (owner only)"""
    if sender.lower() != KICK_CHANNEL.lower():
        return f"@{sender} Only the channel owner can use !ban"
    
    parts = content.split()
    if len(parts) < 2:
        return f"@{sender} Usage: !ban @username"
    
    target = parts[1].lstrip('@')
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}}
    )
    
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"$set": {"is_banned": True}}
    )
    
    if result.modified_count > 0:
        return f"@{sender} Banned @{target} from earning points!"
    else:
        return f"@{sender} Failed to ban user."


async def handle_unban_command(sender: str, content: str):
    """Handle !unban @user command (owner only)"""
    if sender.lower() != KICK_CHANNEL.lower():
        return f"@{sender} Only the channel owner can use !unban"
    
    parts = content.split()
    if len(parts) < 2:
        return f"@{sender} Usage: !unban @username"
    
    target = parts[1].lstrip('@')
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}}
    )
    
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one(
        {"kick_username": {"$regex": f"^{target}$", "$options": "i"}},
        {"$set": {"is_banned": False}}
    )
    
    if result.modified_count > 0:
        return f"@{sender} Unbanned @{target}. They can earn points again!"
    else:
        return f"@{sender} Failed to unban user."


async def handle_rank_command(username: str):
    """Handle !rank command - shows user's rank on leaderboard"""
    if db is None:
        return "Service temporarily unavailable"
    
    # Find the user
    user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
        {"_id": 0, "points_balance": 1, "kick_username": 1}
    )
    
    if not user:
        return f"@{username} You haven't registered yet! Visit the website to login with Kick."
    
    user_points = user.get('points_balance', 0)
    
    # Count how many users have more points
    higher_count = await db.users.count_documents({
        "is_banned": {"$ne": True},
        "points_balance": {"$gt": user_points}
    })
    
    rank = higher_count + 1
    
    # Get total users with points
    total_users = await db.users.count_documents({
        "is_banned": {"$ne": True},
        "points_balance": {"$gt": 0}
    })
    
    return f"@{username} You are rank #{rank} out of {total_users} users with {user_points:,} points!"


@api_router.post("/webhook/kick")
async def kick_webhook(request: Request):
    """
    Webhook endpoint for Kick events
    Handles chat.message.sent and other events
    """
    try:
        # Get event type from headers
        event_type = request.headers.get("Kick-Event-Type", "")
        event_version = request.headers.get("Kick-Event-Version", "1")
        
        # Parse body
        body = await request.json()
        
        logger.info(f"Received Kick webhook: {event_type}")
        
        if event_type == "chat.message.sent":
            # Extract message data
            sender = body.get("sender", {})
            sender_username = sender.get("username", "")
            sender_user_id = sender.get("user_id", 0)
            content = body.get("content", "")
            
            logger.info(f"Chat message from {sender_username}: {content}")
            
            # Check for commands
            content_lower = content.lower().strip()
            response_message = None
            
            if content_lower == "!points":
                response_message = await handle_points_command(sender_username)
            elif content_lower in ["!leaderboard", "!lb"]:
                response_message = await handle_leaderboard_command()
            elif content_lower.startswith("!tip "):
                response_message = await handle_tip_command(sender_username, content)
            elif content_lower.startswith("!addpoints "):
                response_message = await handle_addpoints_command(sender_username, content)
            elif content_lower.startswith("!removepoints "):
                response_message = await handle_removepoints_command(sender_username, content)
            elif content_lower.startswith("!setpoints "):
                response_message = await handle_setpoints_command(sender_username, content)
            elif content_lower.startswith("!ban "):
                response_message = await handle_ban_command(sender_username, content)
            elif content_lower.startswith("!unban "):
                response_message = await handle_unban_command(sender_username, content)
            elif content_lower == "!rank":
                response_message = await handle_rank_command(sender_username)
            elif content_lower == "!commands" or content_lower == "!help":
                response_message = "Commands: !points | !rank | !leaderboard | Owner: !tip !addpoints !removepoints !setpoints !ban !unban"
            else:
                # Regular message - award points
                await award_points_for_chat(sender_username, sender_user_id)
            
            # Send response if we have one
            if response_message:
                await send_kick_chat_message(response_message)
        
        elif event_type == "channel.followed":
            follower = body.get("follower", {})
            logger.info(f"New follower: {follower.get('username')}")
        
        return {"status": "ok"}
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error", "message": str(e)}


@api_router.get("/webhook/kick")
async def kick_webhook_verify():
    """Verification endpoint for Kick webhooks"""
    return {"status": "ok", "message": "Webhook endpoint active"}


# Legacy Botrix endpoints (keeping for backward compatibility)
@api_router.get("/bot/points")
async def botrix_points(user: str):
    """Botrix endpoint for !points command"""
    response = await handle_points_command(user)
    return Response(content=response, media_type="text/plain")


@api_router.get("/bot/leaderboard")
async def botrix_leaderboard():
    """Botrix endpoint for !leaderboard command"""
    response = await handle_leaderboard_command()
    return Response(content=response, media_type="text/plain")


@api_router.get("/bot/commands")
async def botrix_commands():
    """Botrix endpoint for !commands help"""
    return Response(content="Commands: !points | !leaderboard | !tip @user amount", media_type="text/plain")


# Include the router in the main app
app.include_router(api_router)

# Static file serving for frontend - served under /api/site/ prefix
STATIC_DIR = ROOT_DIR / "static"

# Serve static files (CSS, JS, images) under /api prefix to work with Emergent routing
if STATIC_DIR.exists():
    app.mount("/api/css", StaticFiles(directory=str(STATIC_DIR / "css")), name="css")
    app.mount("/api/js", StaticFiles(directory=str(STATIC_DIR / "js")), name="js")
    app.mount("/api/image", StaticFiles(directory=str(STATIC_DIR / "image")), name="image")
    app.mount("/api/admin-panel", StaticFiles(directory=str(STATIC_DIR / "admin"), html=True), name="admin")
    
    # Serve root static files (logos, etc)
    @app.get("/api/boxlogo2.png")
    async def serve_boxlogo():
        return FileResponse(STATIC_DIR / "boxlogo2.png")
    
    @app.get("/api/new-logo.png")
    async def serve_newlogo():
        return FileResponse(STATIC_DIR / "new-logo.png")
    
    # Serve HTML pages under /api/site/
    @app.get("/api/site", response_class=HTMLResponse)
    async def serve_index():
        return FileResponse(STATIC_DIR / "index.html")
    
    @app.get("/api/site/", response_class=HTMLResponse)
    async def serve_index_slash():
        return FileResponse(STATIC_DIR / "index.html")
    
    @app.get("/api/site/shop", response_class=HTMLResponse)
    async def serve_shop():
        return FileResponse(STATIC_DIR / "shop.html")
    
    @app.get("/api/site/leaderboards", response_class=HTMLResponse)
    async def serve_leaderboards():
        return FileResponse(STATIC_DIR / "leaderboards.html")
    
    @app.get("/api/site/challenges", response_class=HTMLResponse)
    async def serve_challenges():
        return FileResponse(STATIC_DIR / "challenges.html")

@app.on_event("shutdown")
async def shutdown_db_client():
    if client:
        client.close()
