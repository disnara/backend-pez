from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid
import secrets
from datetime import datetime, timezone, timedelta
import httpx
import hashlib
import hmac
import binascii
import jwt
import urllib.parse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', '')
db_name = os.environ.get('DB_NAME', 'pezrewards')
client = None
db = None

try:
    if mongo_url:
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
KICK_ADMINS = [x.strip().lower() for x in os.environ.get('KICK_ADMINS', 'pezslaps').split(',')]
JWT_SECRET = os.environ.get('JWT_SECRET', 'pezrewards_super_secret_key_2026')
# Default earning rates (can be overridden via admin panel)
DEFAULT_POINTS_PER_MESSAGE = int(os.environ.get('POINTS_PER_MESSAGE', '1'))
DEFAULT_COOLDOWN_SECONDS = int(os.environ.get('COOLDOWN_SECONDS', '30'))

async def get_earning_rates():
    """Get earning rates from database or defaults"""
    if db is not None:
        settings = await db.settings.find_one({"type": "earning_rates"})
        if settings:
            return {
                "points_per_message": settings.get("points_per_message", DEFAULT_POINTS_PER_MESSAGE),
                "cooldown_seconds": settings.get("cooldown_seconds", DEFAULT_COOLDOWN_SECONDS)
            }
    return {
        "points_per_message": DEFAULT_POINTS_PER_MESSAGE,
        "cooldown_seconds": DEFAULT_COOLDOWN_SECONDS
    }

# ==================== TOKEN REFRESH HELPER ====================

async def refresh_kick_token(token_type: str = "channel_tokens"):
    """
    Refresh Kick OAuth token using refresh_token.
    token_type: "channel_tokens" or "bot_tokens"
    Returns new access_token or None if refresh failed.
    """
    if db is None:
        logger.error("Database not available for token refresh")
        return None
    
    tokens = await db.settings.find_one({"type": token_type})
    if not tokens or not tokens.get("refresh_token"):
        logger.error(f"No refresh token found for {token_type}")
        return None
    
    refresh_token = tokens.get("refresh_token")
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            token_response = await client.post(
                "https://id.kick.com/oauth/token",
                data={
                    "grant_type": "refresh_token",
                    "client_id": KICK_CLIENT_ID,
                    "client_secret": KICK_CLIENT_SECRET,
                    "refresh_token": refresh_token
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            logger.info(f"Token refresh response for {token_type}: {token_response.status_code}")
            
            if token_response.status_code == 200:
                token_data = token_response.json()
                new_access_token = token_data.get("access_token")
                new_refresh_token = token_data.get("refresh_token", refresh_token)
                expires_in = token_data.get("expires_in", 3600)
                
                # Update tokens in database
                await db.settings.update_one(
                    {"type": token_type},
                    {"$set": {
                        "access_token": new_access_token,
                        "refresh_token": new_refresh_token,
                        "expires_in": expires_in,
                        "refreshed_at": datetime.now(timezone.utc).isoformat()
                    }}
                )
                
                logger.info(f"Successfully refreshed {token_type}")
                return new_access_token
            else:
                logger.error(f"Token refresh failed: {token_response.status_code} - {token_response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error refreshing token: {e}")
        return None

async def get_valid_channel_token():
    """
    Get a valid channel access token, refreshing if necessary.
    Returns (access_token, user_id) or (None, None) if failed.
    """
    if db is None:
        return None, None
    
    channel_tokens = await db.settings.find_one({"type": "channel_tokens"})
    if not channel_tokens:
        return None, None
    
    access_token = channel_tokens.get("access_token")
    user_id = channel_tokens.get("user_id")
    
    # Try to use current token first by making a test request
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            test_response = await client.get(
                "https://api.kick.com/public/v1/users",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if test_response.status_code == 200:
                # Token is still valid
                return access_token, user_id
            elif test_response.status_code == 401:
                # Token expired, try to refresh
                logger.info("Channel token expired, attempting refresh...")
                new_token = await refresh_kick_token("channel_tokens")
                if new_token:
                    return new_token, user_id
                else:
                    return None, user_id
            else:
                logger.warning(f"Unexpected response testing token: {test_response.status_code}")
                return access_token, user_id
                
    except Exception as e:
        logger.error(f"Error testing token: {e}")
        # Return existing token, let the actual request handle the error
        return access_token, user_id

async def get_valid_bot_token():
    """
    Get a valid bot access token, refreshing if necessary.
    Returns (access_token, user_id) or (None, None) if failed.
    """
    if db is None:
        return None, None
    
    bot_tokens = await db.settings.find_one({"type": "bot_tokens"})
    if not bot_tokens:
        return None, None
    
    access_token = bot_tokens.get("access_token")
    user_id = bot_tokens.get("user_id")
    
    # Try to use current token first
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            test_response = await client.get(
                "https://api.kick.com/public/v1/users",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if test_response.status_code == 200:
                return access_token, user_id
            elif test_response.status_code == 401:
                logger.info("Bot token expired, attempting refresh...")
                new_token = await refresh_kick_token("bot_tokens")
                if new_token:
                    return new_token, user_id
                else:
                    return None, user_id
            else:
                return access_token, user_id
                
    except Exception as e:
        logger.error(f"Error testing bot token: {e}")
        return access_token, user_id

# Create the main app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global exception handler
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

# Admin credentials (move to env vars in production!)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'pezrewards')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'pezrewardadmin123')

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

class KenoBetRequest(BaseModel):
    bet_amount: float
    selected_numbers: List[int]
    risk: str = "low"

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
    can_play_games: Optional[bool] = None

class EarningRatesUpdate(BaseModel):
    chat_message_points: Optional[int] = None
    daily_cap: Optional[int] = None
    cooldown_seconds: Optional[int] = None

class LeaderboardTimerUpdate(BaseModel):
    period_type: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    is_active: Optional[bool] = None
    fetch_start: Optional[int] = None
    fetch_end: Optional[int] = None

class PointsAdjustment(BaseModel):
    amount: int
    reason: Optional[str] = None

class KickCommandCreate(BaseModel):
    command: str
    description: str
    response: str
    is_enabled: bool = True
    cooldown_seconds: int = 0
    admin_only: bool = False

class KickCommandUpdate(BaseModel):
    command: Optional[str] = None
    description: Optional[str] = None
    response: Optional[str] = None
    is_enabled: Optional[bool] = None
    cooldown_seconds: Optional[int] = None
    admin_only: Optional[bool] = None


# ==================== AUDIT LOG HELPER ====================

async def create_audit_log(
    action: str,
    admin_username: str,
    target_type: str,  # "user", "game", "shop_item", "challenge", "redemption", "settings", "system"
    target_id: Optional[str] = None,
    target_name: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None
):
    """Create an audit log entry for admin actions"""
    if db is None:
        return None
    
    log_entry = {
        "id": str(uuid.uuid4()),
        "action": action,
        "admin_username": admin_username,
        "target_type": target_type,
        "target_id": target_id,
        "target_name": target_name,
        "details": details or {},
        "ip_address": ip_address,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    await db.audit_logs.insert_one(log_entry)
    return log_entry


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

# Frontend URL for redirects
FRONTEND_URL = os.environ.get('FRONTEND_URL', 'https://pezrewards.com')
ADMIN_URL = os.environ.get('ADMIN_URL', 'https://admin.pezrewards.com')

# PKCE helper functions for MongoDB storage
async def store_pkce(state: str, code_verifier: str):
    """Store PKCE code verifier in MongoDB for serverless compatibility"""
    if db is not None:
        await db.pkce_store.update_one(
            {"state": state},
            {"$set": {
                "state": state,
                "code_verifier": code_verifier,
                "created_at": datetime.now(timezone.utc)
            }},
            upsert=True
        )
        # Clean up old entries (older than 10 minutes)
        await db.pkce_store.delete_many({
            "created_at": {"$lt": datetime.now(timezone.utc) - timedelta(minutes=10)}
        })

async def get_pkce(state: str) -> str:
    """Retrieve and delete PKCE code verifier from MongoDB"""
    if db is not None:
        doc = await db.pkce_store.find_one_and_delete({"state": state})
        if doc:
            return doc.get("code_verifier")
    return None


# Default leaderboard settings
DEFAULT_LEADERBOARD_SETTINGS = {
    "menace": {
        "prize_pool": "$1,500",
        "period": "Bi-Weekly",
        "period_type": "bi-weekly",
        "register_link": "https://menace.com/?r=pez",
        "logo": "image/menace.png",
        "prizes": {
            "1": "$600", "2": "$300", "3": "$200", "4": "$150", "5": "$100",
            "6": "$60", "7": "$40", "8": "$30", "9": "$15", "10": "$5"
        },
        "start_date": "2026-02-07T00:00:00+00:00",
        "end_date": "2026-02-21T00:00:00+00:00",
        "needs_date_filter": True,
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
        "needs_date_filter": False,
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
        "needs_date_filter": True,
        "is_active": True
    }
}

async def get_leaderboard_settings(site: str):
    if db is not None:
        try:
            settings = await db.leaderboard_settings.find_one({"site": site}, {"_id": 0})
            if settings:
                return settings
        except Exception as e:
            logger.warning(f"Failed to get settings from DB: {e}")
    return DEFAULT_LEADERBOARD_SETTINGS.get(site, {})


# ==================== API ROUTES ====================

@api_router.get("/")
async def root():
    return {"message": "PezRewards API", "status": "running"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "database": "connected" if db is not None else "not_connected"}


# ==================== LEADERBOARD SETTINGS ====================

@api_router.get("/settings/{site}")
async def get_site_settings(site: str):
    settings = await get_leaderboard_settings(site.lower())
    if not settings:
        raise HTTPException(status_code=404, detail=f"Settings for site '{site}' not found")
    return {"success": True, "site": site, "settings": settings}

@api_router.get("/settings")
async def get_all_settings():
    all_settings = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        all_settings[site] = await get_leaderboard_settings(site)
    return {"success": True, "settings": all_settings}


# ==================== LEADERBOARD ENDPOINTS ====================

@api_router.get("/leaderboard/metaspins")
async def get_metaspins_leaderboard():
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
                return {"success": True, "site": "metaspins", "data": formatted_users}
            return {"success": False, "site": "metaspins", "data": []}
    except Exception as e:
        logger.error(f"Metaspins API error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/leaderboard/menace")
async def get_menace_leaderboard():
    try:
        settings = await get_leaderboard_settings("menace")
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
            url = "https://api-prod.gaze.bet/api/leaderboard/LSNCGAYMCPRJ/fb7d008f-a6e5-4d00-81f9-2e4afd9c5b7a"
            params = {"dateStart": start_date, "dateEnd": end_date, "limit": 20}
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
                return {"success": True, "site": "menace", "data": formatted_users, "period": {"start": start_date, "end": end_date}}
            return {"success": False, "site": "menace", "data": []}
    except Exception as e:
        logger.error(f"Menace API error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

BITFORTUNE_API_KEY = "082a6a65-4da1-425c-9b44-cf609e988672"

@api_router.get("/leaderboard/bitfortune")
async def get_bitfortune_leaderboard():
    try:
        fetch_start = 1769472000
        fetch_end = 1772150400
        
        try:
            settings = await get_leaderboard_settings("bitfortune")
            if settings.get("fetch_start"):
                fetch_start = settings.get("fetch_start")
            if settings.get("fetch_end"):
                fetch_end = settings.get("fetch_end")
        except:
            pass
        
        async with httpx.AsyncClient(timeout=30.0) as http_client:
            url = "https://platformv2.bitfortune.com/api/v1/external/affiliates/leaderboard"
            params = {"api_key": BITFORTUNE_API_KEY, "from": fetch_start, "to": fetch_end}
            response = await http_client.get(url, params=params)
            response.raise_for_status()
            api_response = response.json()
            
            if isinstance(api_response, list):
                sorted_users = sorted(api_response, key=lambda x: x.get("total_wager_usd", 0), reverse=True)
                formatted_users = []
                for idx, user in enumerate(sorted_users[:20]):
                    formatted_users.append({
                        "rank": idx + 1,
                        "username": user.get("user_name", "Unknown"),
                        "wagered": user.get("total_wager_usd", 0),
                        "avatar": ""
                    })
                return {"success": True, "site": "bitfortune", "data": formatted_users}
            return {"success": True, "site": "bitfortune", "data": []}
    except Exception as e:
        logger.error(f"Bitfortune API error: {str(e)}")
        return {"success": False, "site": "bitfortune", "data": [], "error": str(e)}


# ==================== TIMER ENDPOINTS ====================

DEFAULT_END_TIMES = {
    "metaspins": datetime(2026, 3, 1, 0, 0, 0, tzinfo=timezone.utc),
    "menace": datetime(2026, 2, 21, 0, 0, 0, tzinfo=timezone.utc),
    "bitfortune": datetime(2026, 2, 27, 0, 0, 0, tzinfo=timezone.utc),
}

async def get_leaderboard_end_time(site: str):
    try:
        settings = await get_leaderboard_settings(site)
        end_date_str = settings.get("end_date")
        if end_date_str:
            return datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
    except:
        pass
    return DEFAULT_END_TIMES.get(site)

@api_router.get("/timer/{site}")
async def get_timer(site: str):
    try:
        site = site.lower()
        end_time = await get_leaderboard_end_time(site)
        
        if not end_time:
            raise HTTPException(status_code=404, detail=f"Timer for site '{site}' not found")
        
        current_time = datetime.now(timezone.utc)
        time_remaining = end_time - current_time
        
        if time_remaining.total_seconds() <= 0:
            return {"success": True, "site": site, "ended": True, "days": 0, "hours": 0, "minutes": 0, "seconds": 0, "total_seconds": 0}
        
        days = time_remaining.days
        hours, remainder = divmod(time_remaining.seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return {
            "success": True, "site": site, "ended": False,
            "days": days, "hours": hours, "minutes": minutes, "seconds": seconds,
            "total_seconds": int(time_remaining.total_seconds()), "end_time": end_time.isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/timers")
async def get_all_timers():
    try:
        current_time = datetime.now(timezone.utc)
        timers = {}
        
        for site in ["menace", "metaspins", "bitfortune"]:
            end_time = await get_leaderboard_end_time(site)
            if not end_time:
                continue
            
            time_remaining = end_time - current_time
            
            if time_remaining.total_seconds() <= 0:
                timers[site] = {"ended": True, "days": 0, "hours": 0, "minutes": 0, "seconds": 0, "total_seconds": 0}
            else:
                days = time_remaining.days
                hours, remainder = divmod(time_remaining.seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                timers[site] = {
                    "ended": False, "days": days, "hours": hours, "minutes": minutes, "seconds": seconds,
                    "total_seconds": int(time_remaining.total_seconds()), "end_time": end_time.isoformat()
                }
        
        return {"success": True, "current_time": current_time.isoformat(), "timers": timers}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== CHALLENGES ENDPOINTS ====================

@api_router.get("/challenges")
async def get_challenges():
    if db is None:
        return {"success": True, "challenges": []}
    try:
        challenges = await db.challenges.find({}, {"_id": 0}).to_list(100)
        return {"success": True, "challenges": challenges}
    except:
        return {"success": True, "challenges": []}

@api_router.get("/challenges/active")
async def get_active_challenges():
    if db is None:
        return {"success": True, "challenges": []}
    try:
        challenges = await db.challenges.find({"is_active": True}, {"_id": 0}).to_list(100)
        return {"success": True, "challenges": challenges}
    except:
        return {"success": True, "challenges": []}


# ==================== KICK OAUTH ENDPOINTS ====================

@api_router.get("/auth/kick/login")
async def kick_login(request: Request):
    state = secrets.token_urlsafe(32)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store in MongoDB for serverless compatibility
    await store_pkce(state, code_verifier)
    
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
async def kick_callback(request: Request, code: str = None, state: str = None, error: str = None, error_description: str = None):
    is_bot_auth = state and state.startswith("bot_")
    is_channel_auth = state and state.startswith("channel_")
    is_admin_auth = is_bot_auth or is_channel_auth
    
    # Log the callback for debugging
    logger.info(f"Kick callback received - code: {bool(code)}, state: {bool(state)}, error: {error}, error_desc: {error_description}")
    
    if error:
        if is_admin_auth:
            return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?auth_error={error}")
        return RedirectResponse(url=f"{FRONTEND_URL}/?error={error}&desc={error_description or 'unknown'}")
    
    if not code or not state:
        if is_admin_auth:
            return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?auth_error=missing_params")
        return RedirectResponse(url=f"{FRONTEND_URL}/?error=missing_params")
    
    # Retrieve from MongoDB
    code_verifier = await get_pkce(state)
    logger.info(f"PKCE lookup - state: {state[:10]}..., found: {bool(code_verifier)}")
    
    if not code_verifier:
        if is_admin_auth:
            return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?auth_error=invalid_state")
        return RedirectResponse(url=f"{FRONTEND_URL}/?error=invalid_state_pkce_not_found")
    
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
                if is_admin_auth:
                    return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?auth_error=token_failed")
                return RedirectResponse(url=f"{FRONTEND_URL}/?error=token_failed")
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            refresh_token = tokens.get("refresh_token")
            
            user_response = await http_client.get(
                "https://api.kick.com/public/v1/users",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            if user_response.status_code != 200:
                if is_admin_auth:
                    return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?auth_error=user_fetch_failed")
                return RedirectResponse(url=f"{FRONTEND_URL}/?error=user_fetch_failed")
            
            kick_user = user_response.json()
            logger.info(f"Kick user response: {kick_user}")  # Debug logging
            
            if isinstance(kick_user, list) and len(kick_user) > 0:
                kick_user = kick_user[0]
            elif isinstance(kick_user, dict):
                if "data" in kick_user:
                    kick_user = kick_user["data"]
                    if isinstance(kick_user, list) and len(kick_user) > 0:
                        kick_user = kick_user[0]
                elif "user" in kick_user:
                    kick_user = kick_user["user"]
            
            logger.info(f"Parsed kick_user: {kick_user}")  # Debug logging
            
            kick_username = kick_user.get("username") or kick_user.get("name") or "Unknown"
            kick_user_id = kick_user.get("user_id") or kick_user.get("id")
            
            # Handle Channel Authorization (for receiving events)
            if is_channel_auth:
                if db is not None:
                    await db.settings.update_one(
                        {"type": "channel_tokens"},
                        {"$set": {
                            "type": "channel_tokens",
                            "access_token": access_token,
                            "refresh_token": refresh_token,
                            "username": kick_username,
                            "user_id": kick_user_id,
                            "authorized_at": datetime.now(timezone.utc).isoformat()
                        }},
                        upsert=True
                    )
                return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?channel_success=true&channel_user={kick_username}")
            
            # Handle Bot Authorization (for sending messages)
            if is_bot_auth:
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
                return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?bot_success=true&bot_user={kick_username}")
            
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        if is_admin_auth:
            return RedirectResponse(url=f"{ADMIN_URL}/dashboard.html?auth_error=oauth_error")
        return RedirectResponse(url=f"{FRONTEND_URL}/?error=oauth_error")
    
    client_ip = request.client.host if request.client else "unknown"
    
    if db is not None:
        kick_id = str(kick_user.get("id") or kick_user.get("user_id") or "")
        kick_username = kick_user.get("username") or kick_user.get("name") or "User"
        
        # Try multiple possible field names for profile picture
        avatar = (
            kick_user.get("profilepic") or 
            kick_user.get("profile_pic") or 
            kick_user.get("profile_picture") or
            kick_user.get("profilePicture") or
            kick_user.get("avatar") or
            kick_user.get("image") or
            ""
        )
        
        # Check if avatar might be nested in a profile or images object
        if not avatar:
            profile = kick_user.get("profile") or {}
            if isinstance(profile, dict):
                avatar = profile.get("profile_pic") or profile.get("profilepic") or profile.get("avatar") or ""
        
        if not avatar:
            images = kick_user.get("images") or {}
            if isinstance(images, dict):
                avatar = images.get("avatar") or images.get("profile") or ""
        
        logger.info(f"Extracted avatar URL: {avatar}")  # Debug logging
        
        existing_user = await db.users.find_one({"kick_id": kick_id})
        
        if existing_user:
            # Update existing user - also add kick_user_id if missing
            await db.users.update_one({"kick_id": kick_id}, {"$set": {
                "kick_username": kick_username,
                "kick_user_id": str(kick_user_id),  # Ensure kick_user_id is set
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
                "kick_user_id": str(kick_user_id),  # Added for chat point lookup
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
    
    # Pass token in URL for cross-domain compatibility, frontend will store it
    response = RedirectResponse(url=f"{FRONTEND_URL}/index.html?token={jwt_token}")
    response.set_cookie(key="auth_token", value=jwt_token, httponly=True, secure=True, samesite="none", max_age=7*24*60*60)
    return response

@api_router.get("/auth/me")
async def get_me(request: Request):
    try:
        user = await get_current_user(request)
        if user:
            safe_user = {k: v for k, v in user.items() if k not in ["access_token", "refresh_token", "_id"]}
            return {"success": True, "user": safe_user}
    except:
        pass
    return {"success": False, "user": None}

@api_router.post("/auth/logout")
async def logout(response: Response):
    resp = JSONResponse({"success": True, "message": "Logged out"})
    resp.delete_cookie("auth_token")
    return resp


# ==================== FINGERPRINT ENDPOINTS ====================

class FingerprintData(BaseModel):
    hash: str
    components: dict
    collected_at: Optional[str] = None

@api_router.post("/fingerprint")
async def store_fingerprint(request: Request, fingerprint: FingerprintData):
    """Store browser fingerprint for alt account detection"""
    user = await get_current_user(request)
    if db is None:
        return {"success": False, "error": "Database not available"}
    
    try:
        # Check if this fingerprint already exists for this user
        existing = await db.users.find_one({
            "id": user["id"],
            "fingerprints.hash": fingerprint.hash
        })
        
        if existing:
            # Update last_seen for this fingerprint
            await db.users.update_one(
                {"id": user["id"], "fingerprints.hash": fingerprint.hash},
                {"$set": {
                    "fingerprints.$.last_seen": datetime.now(timezone.utc).isoformat()
                },
                "$inc": {"fingerprints.$.times_seen": 1}}
            )
        else:
            # Add new fingerprint
            fingerprint_doc = {
                "hash": fingerprint.hash,
                "components": fingerprint.components,
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "last_seen": datetime.now(timezone.utc).isoformat(),
                "times_seen": 1
            }
            await db.users.update_one(
                {"id": user["id"]},
                {"$push": {"fingerprints": fingerprint_doc}}
            )
        
        return {"success": True}
    except Exception as e:
        logger.error(f"Error storing fingerprint: {e}")
        return {"success": False, "error": str(e)}


# ==================== USER ENDPOINTS ====================

@api_router.get("/users/redemptions")
async def get_user_redemptions(request: Request):
    user = await get_current_user(request)
    if db is None:
        return {"success": True, "redemptions": []}
    
    redemptions = await db.redemptions.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).to_list(50)
    return {"success": True, "redemptions": redemptions}


# ==================== SHOP ENDPOINTS ====================

@api_router.get("/shop/items")
async def get_shop_items(active_only: bool = True):
    if db is None:
        return {"success": True, "items": []}
    query = {"is_active": True} if active_only else {}
    items = await db.shop_items.find(query, {"_id": 0}).to_list(100)
    return {"success": True, "items": items}

@api_router.post("/shop/redeem")
async def redeem_item(redemption: RedemptionCreate, request: Request):
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
    
    if redemption.discord_username:
        await db.users.update_one({"id": user["id"]}, {"$set": {"discord_username": redemption.discord_username}})
    
    new_balance = user["points_balance"] - item["price_points"]
    await db.users.update_one({"id": user["id"]}, {"$set": {"points_balance": new_balance}, "$inc": {"total_spent": item["price_points"]}})
    
    if item.get("stock", -1) != -1:
        await db.shop_items.update_one({"id": item["id"]}, {"$inc": {"stock": -1, "total_claims": 1}})
    else:
        await db.shop_items.update_one({"id": item["id"]}, {"$inc": {"total_claims": 1}})
    
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
    
    return {"success": True, "message": "Item redeemed!", "redemption_id": redemption_id, "new_balance": new_balance}


# ==================== POINTS ENDPOINTS ====================

@api_router.get("/points/balance")
async def get_points_balance(request: Request):
    user = await get_current_user(request)
    return {
        "success": True,
        "balance": user.get("points_balance", 0),
        "total_earned": user.get("total_earned", 0),
        "total_spent": user.get("total_spent", 0)
    }


# ==================== ADMIN ENDPOINTS ====================

@api_router.post("/admin/login")
async def admin_login(credentials: dict, request: Request):
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    
    client_ip = request.client.host if request.client else "unknown"
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        await create_audit_log(
            action="admin_login",
            admin_username=username,
            target_type="system",
            details={"status": "success"},
            ip_address=client_ip
        )
        return {"success": True, "message": "Login successful"}
    
    await create_audit_log(
        action="admin_login_failed",
        admin_username=username or "unknown",
        target_type="system",
        details={"status": "failed", "attempted_username": username},
        ip_address=client_ip
    )
    raise HTTPException(status_code=401, detail="Invalid credentials")

@api_router.get("/admin/settings")
async def admin_get_all_settings(username: str = Depends(verify_admin)):
    all_settings = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        all_settings[site] = await get_leaderboard_settings(site)
    return {"success": True, "settings": all_settings}

@api_router.put("/admin/settings/{site}")
async def admin_update_settings(site: str, settings: LeaderboardSettingsUpdate, request: Request, username: str = Depends(verify_admin)):
    site = site.lower()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await get_leaderboard_settings(site)
    update_data = settings.model_dump(exclude_none=True)
    if update_data:
        existing.update(update_data)
        existing["site"] = site
        await db.leaderboard_settings.update_one({"site": site}, {"$set": existing}, upsert=True)
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="update_leaderboard_settings",
        admin_username=username,
        target_type="settings",
        target_id=site,
        target_name=f"{site} leaderboard",
        details={"updated_fields": list(update_data.keys()), "new_values": update_data},
        ip_address=client_ip
    )
    
    return {"success": True, "message": f"Settings for {site} updated", "settings": existing}


# ==================== ADMIN AUDIT LOGS ====================

@api_router.get("/admin/audit-logs")
async def admin_get_audit_logs(
    action: Optional[str] = None,
    admin_username: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    username: str = Depends(verify_admin)
):
    """Get audit logs with filters"""
    if db is None:
        return {"success": True, "logs": [], "total": 0}
    
    query = {}
    
    if action:
        query["action"] = {"$regex": action, "$options": "i"}
    if admin_username:
        query["admin_username"] = {"$regex": admin_username, "$options": "i"}
    if target_type:
        query["target_type"] = target_type
    if target_id:
        query["target_id"] = target_id
    if start_date:
        query["timestamp"] = {"$gte": start_date}
    if end_date:
        if "timestamp" in query:
            query["timestamp"]["$lte"] = end_date
        else:
            query["timestamp"] = {"$lte": end_date}
    
    total = await db.audit_logs.count_documents(query)
    logs = await db.audit_logs.find(query, {"_id": 0}).sort("timestamp", -1).skip(offset).limit(limit).to_list(length=limit)
    
    return {
        "success": True,
        "logs": logs,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@api_router.get("/admin/audit-logs/actions")
async def admin_get_audit_log_actions(username: str = Depends(verify_admin)):
    """Get list of all unique actions in audit logs"""
    if db is None:
        return {"success": True, "actions": []}
    
    actions = await db.audit_logs.distinct("action")
    return {"success": True, "actions": sorted(actions)}

@api_router.get("/admin/audit-logs/stats")
async def admin_get_audit_log_stats(username: str = Depends(verify_admin)):
    """Get audit log statistics"""
    if db is None:
        return {"success": True, "stats": {}}
    
    # Total logs
    total = await db.audit_logs.count_documents({})
    
    # Logs by action type
    by_action_pipeline = [
        {"$group": {"_id": "$action", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 20}
    ]
    by_action = await db.audit_logs.aggregate(by_action_pipeline).to_list(length=20)
    
    # Logs by admin
    by_admin_pipeline = [
        {"$group": {"_id": "$admin_username", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 10}
    ]
    by_admin = await db.audit_logs.aggregate(by_admin_pipeline).to_list(length=10)
    
    # Logs by target type
    by_target_pipeline = [
        {"$group": {"_id": "$target_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    by_target = await db.audit_logs.aggregate(by_target_pipeline).to_list(length=10)
    
    # Recent activity (last 24 hours)
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    recent_count = await db.audit_logs.count_documents({"timestamp": {"$gte": yesterday}})
    
    return {
        "success": True,
        "stats": {
            "total_logs": total,
            "last_24h": recent_count,
            "by_action": {item["_id"]: item["count"] for item in by_action},
            "by_admin": {item["_id"]: item["count"] for item in by_admin},
            "by_target_type": {item["_id"]: item["count"] for item in by_target}
        }
    }

@api_router.get("/admin/audit-logs/user/{user_id}")
async def admin_get_user_audit_logs(user_id: str, limit: int = 50, username: str = Depends(verify_admin)):
    """Get all audit logs related to a specific user"""
    if db is None:
        return {"success": True, "logs": []}
    
    logs = await db.audit_logs.find(
        {"target_id": user_id, "target_type": "user"},
        {"_id": 0}
    ).sort("timestamp", -1).limit(limit).to_list(length=limit)
    
    return {"success": True, "logs": logs}


# ==================== ADMIN CHALLENGES ====================

@api_router.get("/admin/challenges")
async def admin_get_challenges(username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "challenges": []}
    challenges = await db.challenges.find({}, {"_id": 0}).to_list(100)
    return {"success": True, "challenges": challenges}

@api_router.post("/admin/challenges")
async def admin_create_challenge(challenge: ChallengeCreate, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    challenge_dict = challenge.model_dump()
    challenge_dict["id"] = str(uuid.uuid4())
    challenge_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.challenges.insert_one(challenge_dict)
    challenge_dict.pop("_id", None)
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="create_challenge",
        admin_username=username,
        target_type="challenge",
        target_id=challenge_dict["id"],
        target_name=challenge_dict.get("game_name"),
        details={"site": challenge_dict.get("site"), "reward": challenge_dict.get("reward")},
        ip_address=client_ip
    )
    
    return {"success": True, "message": "Challenge created", "challenge": challenge_dict}

@api_router.put("/admin/challenges/{challenge_id}")
async def admin_update_challenge(challenge_id: str, challenge: ChallengeUpdate, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    update_data = challenge.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    # Get existing challenge for audit log
    existing = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
    
    result = await db.challenges.update_one({"id": challenge_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    updated = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="update_challenge",
        admin_username=username,
        target_type="challenge",
        target_id=challenge_id,
        target_name=updated.get("game_name") if updated else None,
        details={"updated_fields": list(update_data.keys()), "changes": update_data},
        ip_address=client_ip
    )
    
    return {"success": True, "message": "Challenge updated", "challenge": updated}

@api_router.delete("/admin/challenges/{challenge_id}")
async def admin_delete_challenge(challenge_id: str, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get challenge info before deleting
    challenge = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
    
    result = await db.challenges.delete_one({"id": challenge_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="delete_challenge",
        admin_username=username,
        target_type="challenge",
        target_id=challenge_id,
        target_name=challenge.get("game_name") if challenge else None,
        details={"deleted_challenge": challenge},
        ip_address=client_ip
    )
    
    return {"success": True, "message": "Challenge deleted"}


# ==================== ADMIN SHOP ====================

@api_router.get("/admin/shop/items")
async def admin_get_shop_items(username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "items": []}
    items = await db.shop_items.find({}, {"_id": 0}).to_list(100)
    return {"success": True, "items": items}

@api_router.post("/admin/shop/items")
async def admin_create_shop_item(item: ShopItemCreate, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    item_dict = item.model_dump()
    item_dict["id"] = str(uuid.uuid4())
    item_dict["total_claims"] = 0
    item_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.shop_items.insert_one(item_dict)
    item_dict.pop("_id", None)
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="create_shop_item",
        admin_username=username,
        target_type="shop_item",
        target_id=item_dict["id"],
        target_name=item_dict.get("name"),
        details={"price_points": item_dict.get("price_points"), "category": item_dict.get("category")},
        ip_address=client_ip
    )
    
    return {"success": True, "item": item_dict}

@api_router.put("/admin/shop/items/{item_id}")
async def admin_update_shop_item(item_id: str, update: ShopItemUpdate, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.shop_items.update_one({"id": item_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    
    updated = await db.shop_items.find_one({"id": item_id}, {"_id": 0})
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="update_shop_item",
        admin_username=username,
        target_type="shop_item",
        target_id=item_id,
        target_name=updated.get("name") if updated else None,
        details={"updated_fields": list(update_data.keys()), "changes": update_data},
        ip_address=client_ip
    )
    
    return {"success": True, "item": updated}

@api_router.delete("/admin/shop/items/{item_id}")
async def admin_delete_shop_item(item_id: str, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get item info before deleting
    item = await db.shop_items.find_one({"id": item_id}, {"_id": 0})
    
    result = await db.shop_items.delete_one({"id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="delete_shop_item",
        admin_username=username,
        target_type="shop_item",
        target_id=item_id,
        target_name=item.get("name") if item else None,
        details={"deleted_item": item},
        ip_address=client_ip
    )
    
    return {"success": True, "message": "Item deleted"}


# ==================== ADMIN REDEMPTIONS ====================

@api_router.get("/admin/redemptions")
async def admin_get_redemptions(status: Optional[str] = None, username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "redemptions": [], "counts": {"pending": 0, "approved": 0, "rejected": 0}}
    
    query = {"status": status} if status else {}
    redemptions = await db.redemptions.find(query, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    pending = await db.redemptions.count_documents({"status": "pending"})
    approved = await db.redemptions.count_documents({"status": "approved"})
    rejected = await db.redemptions.count_documents({"status": "rejected"})
    
    return {"success": True, "redemptions": redemptions, "counts": {"pending": pending, "approved": approved, "rejected": rejected}}

@api_router.put("/admin/redemptions/{redemption_id}")
async def admin_update_redemption(redemption_id: str, update: RedemptionStatusUpdate, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    redemption = await db.redemptions.find_one({"id": redemption_id}, {"_id": 0})
    if not redemption:
        raise HTTPException(status_code=404, detail="Redemption not found")
    
    if redemption["status"] != "pending":
        raise HTTPException(status_code=400, detail="Redemption already processed")
    
    if update.status == "rejected":
        user = await db.users.find_one({"id": redemption["user_id"]}, {"_id": 0})
        if user:
            new_balance = user["points_balance"] + redemption["points_spent"]
            await db.users.update_one({"id": user["id"]}, {"$set": {"points_balance": new_balance}})
    
    await db.redemptions.update_one({"id": redemption_id}, {"$set": {"status": update.status, "admin_notes": update.admin_notes, "handled_at": datetime.now(timezone.utc).isoformat(), "handled_by": username}})
    
    updated = await db.redemptions.find_one({"id": redemption_id}, {"_id": 0})
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action=f"redemption_{update.status}",
        admin_username=username,
        target_type="redemption",
        target_id=redemption_id,
        target_name=redemption.get("item_name"),
        details={
            "user_id": redemption.get("user_id"),
            "kick_username": redemption.get("kick_username"),
            "item_name": redemption.get("item_name"),
            "points_spent": redemption.get("points_spent"),
            "admin_notes": update.admin_notes,
            "new_status": update.status
        },
        ip_address=client_ip
    )
    
    return {"success": True, "redemption": updated}


# ==================== ADMIN USERS ====================

@api_router.get("/admin/users")
async def admin_get_users(search: Optional[str] = None, username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "users": []}
    
    query = {}
    if search:
        query["$or"] = [{"kick_username": {"$regex": search, "$options": "i"}}, {"discord_username": {"$regex": search, "$options": "i"}}]
    
    users = await db.users.find(query, {"_id": 0, "access_token": 0, "refresh_token": 0}).sort("registered_at", -1).to_list(100)
    return {"success": True, "users": users}

@api_router.put("/admin/users/{user_id}")
async def admin_update_user(user_id: str, update: AdminUserUpdate, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get user before update
    user_before = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1})
    
    update_data = update.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.users.update_one({"id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="update_user",
        admin_username=username,
        target_type="user",
        target_id=user_id,
        target_name=user_before.get("kick_username") if user_before else None,
        details={"updated_fields": list(update_data.keys()), "changes": update_data},
        ip_address=client_ip
    )
    
    return {"success": True, "user": updated}

@api_router.post("/admin/users/{user_id}/ban")
async def admin_ban_user(user_id: str, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1})
    
    result = await db.users.update_one({"id": user_id}, {"$set": {"is_banned": True, "banned_at": datetime.now(timezone.utc).isoformat(), "banned_by": username}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="ban_user",
        admin_username=username,
        target_type="user",
        target_id=user_id,
        target_name=user.get("kick_username") if user else None,
        details={"action": "full_ban"},
        ip_address=client_ip
    )
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User banned", "user": updated}

@api_router.post("/admin/users/{user_id}/unban")
async def admin_unban_user(user_id: str, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1})
    
    result = await db.users.update_one({"id": user_id}, {"$set": {"is_banned": False}, "$unset": {"banned_at": "", "banned_by": ""}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="unban_user",
        admin_username=username,
        target_type="user",
        target_id=user_id,
        target_name=user.get("kick_username") if user else None,
        details={"action": "unban"},
        ip_address=client_ip
    )
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User unbanned", "user": updated}

@api_router.post("/admin/users/{user_id}/adjust-points")
async def admin_adjust_points(user_id: str, adjustment: PointsAdjustment, request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    current_balance = user.get("points_balance", 0)
    new_balance = current_balance + adjustment.amount
    
    if new_balance < 0:
        raise HTTPException(status_code=400, detail="Cannot reduce balance below 0")
    
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    
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
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="adjust_points",
        admin_username=username,
        target_type="user",
        target_id=user_id,
        target_name=user.get("kick_username"),
        details={
            "amount": adjustment.amount,
            "reason": adjustment.reason or "Manual adjustment",
            "previous_balance": current_balance,
            "new_balance": new_balance
        },
        ip_address=client_ip
    )
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": f"Points adjusted by {adjustment.amount:+d}", "user": updated}


# ==================== ADMIN BOT ====================

@api_router.get("/admin/bot-status")
async def admin_get_bot_status(username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "bot": {"status": "not_configured"}}
    
    # Get channel tokens (for receiving events)
    channel_tokens = await db.settings.find_one({"type": "channel_tokens"}, {"_id": 0})
    channel_authorized = channel_tokens is not None and channel_tokens.get("access_token")
    
    # Get bot tokens (for sending messages)
    bot_tokens = await db.settings.find_one({"type": "bot_tokens"}, {"_id": 0})
    bot_authorized = bot_tokens is not None and bot_tokens.get("access_token")
    
    rates = await get_earning_rates()
    
    bot_config = {
        "target_channel": KICK_CHANNEL,
        "points_per_message": rates.get("points_per_message", 1),
        "status": "fully_configured" if (channel_authorized and bot_authorized) else ("partially_configured" if (channel_authorized or bot_authorized) else "not_authorized"),
        "channel_account": channel_tokens.get("username") if channel_tokens else None,
        "bot_account": bot_tokens.get("username") if bot_tokens else None,
        "commands": ["!points", "!rank", "!leaderboard", "!tip", "!addpoints", "!removepoints", "!setpoints", "!ban", "!unban"]
    }
    return {"success": True, "bot": bot_config}

@api_router.get("/admin/channel/authorize")
async def admin_channel_authorize(username: str = Depends(verify_admin)):
    """Authorize channel account (for receiving chat events)"""
    state = "channel_" + secrets.token_urlsafe(32)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    await store_pkce(state, code_verifier)
    
    params = {
        "client_id": KICK_CLIENT_ID,
        "redirect_uri": KICK_REDIRECT_URI,
        "response_type": "code",
        "scope": "user:read channel:read events:subscribe",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"https://id.kick.com/oauth/authorize?{urllib.parse.urlencode(params)}"
    return {"success": True, "auth_url": auth_url}

@api_router.get("/admin/bot/authorize")
async def admin_bot_authorize(username: str = Depends(verify_admin)):
    """Authorize bot account (for sending chat messages)"""
    state = "bot_" + secrets.token_urlsafe(32)
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    # Store in MongoDB for serverless compatibility
    await store_pkce(state, code_verifier)
    
    params = {
        "client_id": KICK_CLIENT_ID,
        "redirect_uri": KICK_REDIRECT_URI,
        "response_type": "code",
        "scope": "user:read chat:write",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"https://id.kick.com/oauth/authorize?{urllib.parse.urlencode(params)}"
    return {"success": True, "auth_url": auth_url}

@api_router.post("/admin/bot/revoke")
async def admin_bot_revoke(username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    await db.settings.delete_one({"type": "bot_tokens"})
    return {"success": True, "message": "Bot authorization revoked"}

@api_router.post("/admin/channel/revoke")
async def admin_channel_revoke(username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    await db.settings.delete_one({"type": "channel_tokens"})
    return {"success": True, "message": "Channel authorization revoked"}

@api_router.post("/admin/bot/subscribe-events")
async def admin_bot_subscribe_events(username: str = Depends(verify_admin)):
    """Subscribe to chat events using channel token with automatic token refresh"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get valid channel token (with automatic refresh if expired)
    access_token, broadcaster_id = await get_valid_channel_token()
    
    if not access_token:
        raise HTTPException(
            status_code=400, 
            detail="Channel token expired and refresh failed. Please re-authorize the channel account."
        )
    
    webhook_url = "https://backend-pez.vercel.app/api/webhook/kick"
    token_was_refreshed = False
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            # First check current subscriptions
            check_response = await client.get(
                "https://api.kick.com/public/v1/events/subscriptions",
                headers=headers
            )
            logger.info(f"Current subscriptions: {check_response.status_code} - {check_response.text}")
            
            # If 401, try refreshing token
            if check_response.status_code == 401:
                logger.info("Token rejected, attempting refresh...")
                new_token = await refresh_kick_token("channel_tokens")
                if new_token:
                    access_token = new_token
                    headers["Authorization"] = f"Bearer {access_token}"
                    token_was_refreshed = True
                    # Retry the request
                    check_response = await client.get(
                        "https://api.kick.com/public/v1/events/subscriptions",
                        headers=headers
                    )
                else:
                    raise HTTPException(
                        status_code=401, 
                        detail="Channel token expired and refresh failed. Please re-authorize the channel account."
                    )
            
            current_subs = check_response.json() if check_response.status_code == 200 else {}
            
            # Subscribe to chat events with broadcaster ID
            payload = {
                "events": [
                    {"name": "chat.message.sent", "version": 1}
                ],
                "method": "webhook"
            }
            
            # Add broadcaster_user_id if available
            if broadcaster_id:
                payload["broadcaster_user_id"] = int(broadcaster_id)
            
            logger.info(f"Subscribing with payload: {payload}")
            
            response = await client.post(
                "https://api.kick.com/public/v1/events/subscriptions",
                headers=headers,
                json=payload
            )
            
            logger.info(f"Subscribe response: {response.status_code} - {response.text}")
            
            # If still 401 after refresh attempt, need re-authorization
            if response.status_code == 401:
                raise HTTPException(
                    status_code=401,
                    detail="Authorization failed. Please re-authorize the channel account from the admin panel."
                )
            
            return {
                "success": response.status_code in [200, 201],
                "message": "Subscription request sent" + (" (token was refreshed)" if token_was_refreshed else ""),
                "webhook_url": webhook_url,
                "broadcaster_id": broadcaster_id,
                "subscribe_status": response.status_code,
                "subscribe_response": response.json() if response.text else {},
                "current_subscriptions": current_subs,
                "token_refreshed": token_was_refreshed
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error subscribing to events: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/admin/channel/refresh-token")
async def admin_channel_refresh_token(username: str = Depends(verify_admin)):
    """Manually refresh channel token"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    new_token = await refresh_kick_token("channel_tokens")
    if new_token:
        return {"success": True, "message": "Channel token refreshed successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to refresh token. Please re-authorize the channel.")

@api_router.post("/admin/bot/refresh-token")
async def admin_bot_refresh_token(username: str = Depends(verify_admin)):
    """Manually refresh bot token"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    new_token = await refresh_kick_token("bot_tokens")
    if new_token:
        return {"success": True, "message": "Bot token refreshed successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to refresh token. Please re-authorize the bot.")


# ==================== KICK COMMANDS CONFIGURATION ====================

DEFAULT_KICK_COMMANDS = [
    {"command": "!points", "description": "Check your point balance", "response": "SYSTEM", "is_enabled": True, "cooldown_seconds": 5, "admin_only": False, "is_system": True},
    {"command": "!rank", "description": "Check your rank", "response": "SYSTEM", "is_enabled": True, "cooldown_seconds": 5, "admin_only": False, "is_system": True},
    {"command": "!leaderboard", "description": "Show top point earners", "response": "SYSTEM", "is_enabled": True, "cooldown_seconds": 10, "admin_only": False, "is_system": True},
    {"command": "!tip", "description": "Give points to another user", "response": "SYSTEM", "is_enabled": True, "cooldown_seconds": 5, "admin_only": False, "is_system": True},
    {"command": "!site", "description": "Show rewards site link", "response": "🎁 Check out our rewards site! 👉 https://pezrewards.com/", "is_enabled": True, "cooldown_seconds": 30, "admin_only": False, "is_system": False},
    {"command": "!menace", "description": "Menace casino promo", "response": "🎰 MENACE $1500 BI-WEEKLY LEADERBOARD! Double Rank-Up Rewards, VIP Transfers, Lossback, Fast Payouts - all live right now. https://menace.com/?r=pez", "is_enabled": True, "cooldown_seconds": 30, "admin_only": False, "is_system": False},
    {"command": "!meta", "description": "Metaspins casino promo", "response": "🔥$3,200 USD Monthly Leaderboard! DOUBLE Rank-Up Rewards, up to 120% Rakeback, Monthly Deposit Comps! 🎉 Sign up & Support now 👉 https://metaspins.com/?ref=pezslaps", "is_enabled": True, "cooldown_seconds": 30, "admin_only": False, "is_system": False},
    {"command": "!bit", "description": "Bitfortune casino promo", "response": "10K LEADERBOARD 🏁 | 20K WEEKLY RACE 🏆 | VIP Transfers 💎 | DOUBLE Rank-Up Rewards 🚀 https://join.bitfortune.com/pezslaps", "is_enabled": True, "cooldown_seconds": 30, "admin_only": False, "is_system": False},
    {"command": "!discord", "description": "Discord invite link", "response": "💬 Join the Discord to stay up to date, connect with the community, and enter giveaways! 🎁 👉 https://discord.gg/TRThDgz77W", "is_enabled": True, "cooldown_seconds": 30, "admin_only": False, "is_system": False},
]

async def ensure_default_commands():
    """Seed default commands if kick_commands collection is empty"""
    if db is None:
        return
    
    count = await db.kick_commands.count_documents({})
    if count == 0:
        for cmd in DEFAULT_KICK_COMMANDS:
            cmd["created_at"] = datetime.utcnow().isoformat()
            cmd["updated_at"] = datetime.utcnow().isoformat()
        await db.kick_commands.insert_many(DEFAULT_KICK_COMMANDS)
        logger.info("Seeded default kick commands")

@api_router.get("/admin/kick-commands")
async def admin_get_kick_commands(username: str = Depends(verify_admin)):
    """Get all kick commands"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    await ensure_default_commands()
    
    commands = await db.kick_commands.find({}, {"_id": 0}).sort("command", 1).to_list(100)
    return {"success": True, "commands": commands}

@api_router.post("/admin/kick-commands")
async def admin_create_kick_command(cmd: KickCommandCreate, username: str = Depends(verify_admin)):
    """Create a new kick command"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Check if command already exists
    existing = await db.kick_commands.find_one({"command": cmd.command.lower()})
    if existing:
        raise HTTPException(status_code=400, detail=f"Command {cmd.command} already exists")
    
    # Ensure command starts with !
    command_name = cmd.command.lower()
    if not command_name.startswith("!"):
        command_name = "!" + command_name
    
    new_command = {
        "command": command_name,
        "description": cmd.description,
        "response": cmd.response,
        "is_enabled": cmd.is_enabled,
        "cooldown_seconds": cmd.cooldown_seconds,
        "admin_only": cmd.admin_only,
        "is_system": False,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }
    
    await db.kick_commands.insert_one(new_command)
    
    await create_audit_log(
        action="kick_command_created",
        admin_username=username,
        target_type="kick_command",
        target_name=command_name,
        details={"command": command_name}
    )
    
    return {"success": True, "command": {k: v for k, v in new_command.items() if k != "_id"}}

@api_router.put("/admin/kick-commands/{command_name}")
async def admin_update_kick_command(command_name: str, cmd: KickCommandUpdate, username: str = Depends(verify_admin)):
    """Update a kick command"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # URL decode the command name
    command_name = urllib.parse.unquote(command_name)
    
    existing = await db.kick_commands.find_one({"command": command_name})
    if not existing:
        raise HTTPException(status_code=404, detail=f"Command {command_name} not found")
    
    update_data = {"updated_at": datetime.utcnow().isoformat()}
    
    if cmd.description is not None:
        update_data["description"] = cmd.description
    if cmd.response is not None:
        update_data["response"] = cmd.response
    if cmd.is_enabled is not None:
        update_data["is_enabled"] = cmd.is_enabled
    if cmd.cooldown_seconds is not None:
        update_data["cooldown_seconds"] = cmd.cooldown_seconds
    if cmd.admin_only is not None:
        update_data["admin_only"] = cmd.admin_only
    
    await db.kick_commands.update_one({"command": command_name}, {"$set": update_data})
    
    await create_audit_log(
        action="kick_command_updated",
        admin_username=username,
        target_type="kick_command",
        target_name=command_name,
        details={"command": command_name, "changes": update_data}
    )
    
    updated = await db.kick_commands.find_one({"command": command_name}, {"_id": 0})
    return {"success": True, "command": updated}

@api_router.delete("/admin/kick-commands/{command_name}")
async def admin_delete_kick_command(command_name: str, username: str = Depends(verify_admin)):
    """Delete a kick command (only custom commands can be deleted)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # URL decode the command name
    command_name = urllib.parse.unquote(command_name)
    
    existing = await db.kick_commands.find_one({"command": command_name})
    if not existing:
        raise HTTPException(status_code=404, detail=f"Command {command_name} not found")
    
    if existing.get("is_system", False):
        raise HTTPException(status_code=400, detail="Cannot delete system commands. You can only disable them.")
    
    await db.kick_commands.delete_one({"command": command_name})
    
    await create_audit_log(
        action="kick_command_deleted",
        admin_username=username,
        target_type="kick_command",
        target_name=command_name,
        details={"command": command_name}
    )
    
    return {"success": True, "message": f"Command {command_name} deleted"}

async def get_command_response(command: str) -> Optional[str]:
    """Get command response from database"""
    if db is None:
        return None
    
    cmd = await db.kick_commands.find_one({"command": command.lower(), "is_enabled": True})
    if cmd and cmd.get("response") != "SYSTEM":
        return cmd.get("response")
    return None


# ==================== EARNING RATES ====================

@api_router.get("/admin/earning-rates")
async def admin_get_earning_rates(username: str = Depends(verify_admin)):
    rates = await get_earning_rates()
    return {"success": True, "rates": rates}

@api_router.post("/admin/earning-rates")
async def admin_update_earning_rates(request: Request, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    body = await request.json()
    
    update_data = {
        "type": "earning_rates",
        "points_per_message": int(body.get("points_per_message", DEFAULT_POINTS_PER_MESSAGE)),
        "cooldown_seconds": int(body.get("cooldown_seconds", DEFAULT_COOLDOWN_SECONDS))
    }
    
    await db.settings.update_one(
        {"type": "earning_rates"},
        {"$set": update_data},
        upsert=True
    )
    
    return {"success": True, "message": "Earning rates updated", "rates": update_data}


# ==================== ALT ACCOUNTS ====================

@api_router.get("/admin/alt-accounts")
async def admin_get_alt_accounts(username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "alt_groups": []}
    
    try:
        # Find users with same IP addresses
        pipeline = [
            {"$unwind": "$ip_addresses"},
            {"$group": {
                "_id": "$ip_addresses",
                "users": {"$push": {"id": "$id", "kick_username": "$kick_username", "points_balance": "$points_balance"}},
                "count": {"$sum": 1}
            }},
            {"$match": {"count": {"$gt": 1}}},
            {"$project": {"_id": 0, "ip": "$_id", "users": 1, "count": 1}}
        ]
        alt_groups = await db.users.aggregate(pipeline).to_list(100)
        return {"success": True, "alt_groups": alt_groups}
    except Exception as e:
        logger.error(f"Error getting alt accounts: {e}")
        return {"success": True, "alt_groups": []}


@api_router.get("/admin/alt-accounts-v2")
async def admin_get_alt_accounts_v2(username: str = Depends(verify_admin)):
    """
    Advanced alt account detection using browser fingerprints + IP.
    Returns matches with confidence scores.
    """
    if db is None:
        return {"success": True, "alt_groups": [], "stats": {}}
    
    try:
        # Get all users with fingerprints
        users = await db.users.find(
            {"fingerprints": {"$exists": True, "$ne": []}},
            {"_id": 0, "id": 1, "kick_username": 1, "points_balance": 1, 
             "fingerprints": 1, "ip_addresses": 1, "registered_at": 1, "last_login": 1}
        ).to_list(1000)
        
        # Build fingerprint to users mapping
        fingerprint_map = {}  # hash -> [users]
        ip_map = {}  # ip -> [users]
        
        for user in users:
            # Map fingerprints
            for fp in user.get("fingerprints", []):
                fp_hash = fp.get("hash")
                if fp_hash:
                    if fp_hash not in fingerprint_map:
                        fingerprint_map[fp_hash] = []
                    fingerprint_map[fp_hash].append({
                        "id": user["id"],
                        "kick_username": user.get("kick_username"),
                        "points_balance": user.get("points_balance", 0),
                        "fingerprint_data": fp,
                        "registered_at": user.get("registered_at"),
                        "last_login": user.get("last_login")
                    })
            
            # Map IPs
            for ip in user.get("ip_addresses", []):
                if ip:
                    if ip not in ip_map:
                        ip_map[ip] = []
                    ip_map[ip].append(user["id"])
        
        # Find alt groups (same fingerprint = same device)
        alt_groups = []
        processed_pairs = set()
        
        for fp_hash, fp_users in fingerprint_map.items():
            if len(fp_users) > 1:
                # Found users with same fingerprint
                user_ids = tuple(sorted([u["id"] for u in fp_users]))
                if user_ids in processed_pairs:
                    continue
                processed_pairs.add(user_ids)
                
                # Calculate confidence score
                confidence = 90  # Base: same fingerprint
                
                # Check if also same IP
                user_ips = []
                for u in fp_users:
                    user_obj = next((usr for usr in users if usr["id"] == u["id"]), None)
                    if user_obj:
                        user_ips.extend(user_obj.get("ip_addresses", []))
                
                # Boost confidence if IPs overlap
                ip_overlap = len(set(user_ips)) < len(user_ips)
                if ip_overlap:
                    confidence = 98
                
                total_points = sum(u.get("points_balance", 0) for u in fp_users)
                
                alt_groups.append({
                    "fingerprint_hash": fp_hash,
                    "confidence": confidence,
                    "match_type": "fingerprint" + ("+ip" if ip_overlap else ""),
                    "users": fp_users,
                    "user_count": len(fp_users),
                    "total_points": total_points,
                    "ip_overlap": ip_overlap
                })
        
        # Also check IP-only matches (lower confidence)
        for ip, ip_user_ids in ip_map.items():
            if len(ip_user_ids) > 1:
                user_ids = tuple(sorted(ip_user_ids))
                if user_ids in processed_pairs:
                    continue
                
                # Check if these users DON'T have matching fingerprints (IP-only match)
                ip_users = [u for u in users if u["id"] in ip_user_ids]
                all_fps = []
                for u in ip_users:
                    all_fps.extend([fp.get("hash") for fp in u.get("fingerprints", [])])
                
                # If fingerprints are different, it's IP-only match
                if len(set(all_fps)) == len(all_fps) or not all_fps:
                    processed_pairs.add(user_ids)
                    total_points = sum(u.get("points_balance", 0) for u in ip_users)
                    
                    alt_groups.append({
                        "ip_address": ip[:10] + "..." if len(ip) > 10 else ip,  # Partial IP for privacy
                        "confidence": 40,  # Lower confidence for IP-only
                        "match_type": "ip_only",
                        "users": [{
                            "id": u["id"],
                            "kick_username": u.get("kick_username"),
                            "points_balance": u.get("points_balance", 0)
                        } for u in ip_users],
                        "user_count": len(ip_users),
                        "total_points": total_points,
                        "note": "Same IP but different devices - could be shared network"
                    })
        
        # Sort by confidence (highest first)
        alt_groups.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        
        return {
            "success": True,
            "alt_groups": alt_groups,
            "stats": {
                "total_users_scanned": len(users),
                "users_with_fingerprints": len([u for u in users if u.get("fingerprints")]),
                "high_confidence_matches": len([g for g in alt_groups if g.get("confidence", 0) >= 90]),
                "medium_confidence_matches": len([g for g in alt_groups if 50 <= g.get("confidence", 0) < 90]),
                "low_confidence_matches": len([g for g in alt_groups if g.get("confidence", 0) < 50])
            }
        }
    except Exception as e:
        logger.error(f"Error in alt detection v2: {e}")
        return {"success": True, "alt_groups": [], "error": str(e)}


@api_router.post("/admin/link-alt-accounts")
async def admin_link_alt_accounts(data: dict, username: str = Depends(verify_admin)):
    """Mark accounts as known alts (allowed/family)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user_ids = data.get("user_ids", [])
    link_type = data.get("link_type", "allowed")  # allowed, family, same_person
    
    if len(user_ids) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 user IDs")
    
    link_id = str(uuid.uuid4())
    
    # Update all users with the link
    await db.users.update_many(
        {"id": {"$in": user_ids}},
        {"$set": {"alt_link": {"link_id": link_id, "link_type": link_type, "linked_at": datetime.now(timezone.utc).isoformat()}}}
    )
    
    return {"success": True, "link_id": link_id, "users_linked": len(user_ids)}


@api_router.post("/admin/merge-alt-accounts")
async def admin_merge_alt_accounts(data: dict, username: str = Depends(verify_admin)):
    """Merge alt accounts into primary (combine points, delete alts)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    primary_id = data.get("primary_id")
    alt_ids = data.get("alt_ids", [])
    
    if not primary_id or not alt_ids:
        raise HTTPException(status_code=400, detail="Need primary_id and alt_ids")
    
    # Get all accounts
    all_ids = [primary_id] + alt_ids
    users = await db.users.find({"id": {"$in": all_ids}}).to_list(100)
    
    if len(users) != len(all_ids):
        raise HTTPException(status_code=400, detail="Some users not found")
    
    # Calculate totals
    total_points = sum(u.get("points_balance", 0) for u in users)
    total_earned = sum(u.get("total_earned", 0) for u in users)
    
    # Merge fingerprints and IPs from alts into primary
    all_fingerprints = []
    all_ips = []
    for u in users:
        all_fingerprints.extend(u.get("fingerprints", []))
        all_ips.extend(u.get("ip_addresses", []))
    
    # Deduplicate
    unique_ips = list(set(all_ips))
    seen_hashes = set()
    unique_fps = []
    for fp in all_fingerprints:
        if fp.get("hash") not in seen_hashes:
            seen_hashes.add(fp.get("hash"))
            unique_fps.append(fp)
    
    # Update primary
    await db.users.update_one(
        {"id": primary_id},
        {"$set": {
            "points_balance": total_points,
            "total_earned": total_earned,
            "fingerprints": unique_fps,
            "ip_addresses": unique_ips,
            "merged_alts": alt_ids,
            "merged_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    # Delete alts
    delete_result = await db.users.delete_many({"id": {"$in": alt_ids}})
    
    return {
        "success": True,
        "primary_id": primary_id,
        "alts_merged": len(alt_ids),
        "alts_deleted": delete_result.deleted_count,
        "new_points_balance": total_points,
        "new_total_earned": total_earned
    }


# ==================== DATABASE DIAGNOSTICS ====================

@api_router.get("/admin/diagnose-user/{kick_username}")
async def admin_diagnose_user(kick_username: str, username: str = Depends(verify_admin)):
    """
    Diagnose points mismatch for a user.
    Finds ALL records matching this username to detect duplicates.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Find ALL users matching this username (case-insensitive)
    cursor = db.users.find(
        {"kick_username": {"$regex": f"^{kick_username}$", "$options": "i"}},
        {"_id": 0, "id": 1, "kick_id": 1, "kick_user_id": 1, "kick_username": 1, 
         "points_balance": 1, "total_earned": 1, "registered_at": 1, "last_login": 1}
    )
    users = await cursor.to_list(length=100)
    
    return {
        "success": True,
        "search_username": kick_username,
        "records_found": len(users),
        "is_duplicate": len(users) > 1,
        "users": users,
        "diagnosis": "DUPLICATE USERS FOUND - Need to merge!" if len(users) > 1 else "Single user record OK"
    }

@api_router.post("/admin/merge-duplicate-users/{kick_username}")
async def admin_merge_duplicate_users(kick_username: str, username: str = Depends(verify_admin)):
    """
    Merge duplicate user records into one.
    Keeps the record with the highest points and adds points from others.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Find ALL users matching this username
    cursor = db.users.find(
        {"kick_username": {"$regex": f"^{kick_username}$", "$options": "i"}},
        {"_id": 1, "id": 1, "kick_id": 1, "kick_user_id": 1, "kick_username": 1, 
         "points_balance": 1, "total_earned": 1, "registered_at": 1}
    )
    users = await cursor.to_list(length=100)
    
    if len(users) <= 1:
        return {"success": True, "message": "No duplicates found for this user", "records": len(users)}
    
    # Sort by points_balance descending - keep the one with most points as primary
    users.sort(key=lambda x: x.get("points_balance", 0), reverse=True)
    primary = users[0]
    duplicates = users[1:]
    
    # Calculate total points from all records
    total_points = sum(u.get("points_balance", 0) for u in users)
    total_earned = sum(u.get("total_earned", 0) for u in users)
    
    # Update primary record with combined points
    await db.users.update_one(
        {"_id": primary["_id"]},
        {"$set": {
            "points_balance": total_points,
            "total_earned": total_earned,
            "kick_user_id": primary.get("kick_id") or primary.get("kick_user_id")  # Ensure kick_user_id is set
        }}
    )
    
    # Delete duplicate records
    duplicate_ids = [u["_id"] for u in duplicates]
    delete_result = await db.users.delete_many({"_id": {"$in": duplicate_ids}})
    
    return {
        "success": True,
        "message": f"Merged {len(users)} records into 1",
        "primary_user_id": primary.get("id"),
        "duplicates_deleted": delete_result.deleted_count,
        "new_total_points": total_points,
        "new_total_earned": total_earned
    }

@api_router.get("/admin/find-all-duplicates")
async def admin_find_all_duplicates(username: str = Depends(verify_admin)):
    """
    Find ALL users with duplicate records in the database.
    Returns list of usernames that have more than one record.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Aggregation to find duplicate usernames
    pipeline = [
        {"$group": {
            "_id": {"$toLower": "$kick_username"},
            "count": {"$sum": 1},
            "total_points": {"$sum": "$points_balance"},
            "records": {"$push": {
                "id": "$id",
                "kick_username": "$kick_username",
                "points_balance": "$points_balance",
                "kick_id": "$kick_id",
                "kick_user_id": "$kick_user_id"
            }}
        }},
        {"$match": {"count": {"$gt": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    duplicates = await db.users.aggregate(pipeline).to_list(length=500)
    
    return {
        "success": True,
        "total_users_with_duplicates": len(duplicates),
        "duplicates": duplicates,
        "action": "Use /admin/merge-duplicate-users/{username} to fix each one, or /admin/merge-all-duplicates to fix all at once"
    }

@api_router.delete("/admin/cleanup-null-users")
async def admin_cleanup_null_users(username: str = Depends(verify_admin)):
    """
    Delete all user records with null/empty usernames (junk data from failed logins).
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Delete users with null or empty kick_username
    result = await db.users.delete_many({
        "$or": [
            {"kick_username": None},
            {"kick_username": ""},
            {"kick_username": {"$exists": False}}
        ]
    })
    
    return {
        "success": True,
        "message": f"Cleaned up {result.deleted_count} junk records",
        "deleted_count": result.deleted_count
    }

@api_router.post("/admin/merge-all-duplicates")
async def admin_merge_all_duplicates(username: str = Depends(verify_admin)):
    """
    Automatically merge ALL duplicate user records.
    For each duplicate set, keeps highest points record and combines all points.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Find all duplicates
    pipeline = [
        {"$group": {
            "_id": {"$toLower": "$kick_username"},
            "count": {"$sum": 1},
            "records": {"$push": {
                "_id": "$_id",
                "id": "$id",
                "kick_id": "$kick_id",
                "points_balance": "$points_balance",
                "total_earned": "$total_earned"
            }}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]
    
    duplicates = await db.users.aggregate(pipeline).to_list(length=500)
    
    merged_count = 0
    deleted_count = 0
    
    for dup in duplicates:
        records = dup["records"]
        # Sort by points descending
        records.sort(key=lambda x: x.get("points_balance", 0), reverse=True)
        primary = records[0]
        others = records[1:]
        
        # Calculate totals
        total_points = sum(r.get("points_balance", 0) for r in records)
        total_earned = sum(r.get("total_earned", 0) for r in records)
        
        # Update primary
        await db.users.update_one(
            {"_id": primary["_id"]},
            {"$set": {
                "points_balance": total_points,
                "total_earned": total_earned,
                "kick_user_id": primary.get("kick_id")
            }}
        )
        
        # Delete others
        other_ids = [r["_id"] for r in others]
        result = await db.users.delete_many({"_id": {"$in": other_ids}})
        
        merged_count += 1
        deleted_count += result.deleted_count
    
    return {
        "success": True,
        "message": f"Merged {merged_count} duplicate user sets, deleted {deleted_count} extra records",
        "users_merged": merged_count,
        "records_deleted": deleted_count
    }


# ==================== DATABASE MIGRATION ====================

@api_router.post("/admin/migrate-kick-user-ids")
async def admin_migrate_kick_user_ids(username: str = Depends(verify_admin)):
    """
    One-time migration to add kick_user_id to existing users.
    This fixes the points mismatch between !points command and website.
    Users need to re-login after this migration to populate their kick_user_id.
    """
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Find users missing kick_user_id
    missing_count = await db.users.count_documents({"kick_user_id": {"$exists": False}})
    
    # For users with kick_id, copy it to kick_user_id (they're the same value)
    result = await db.users.update_many(
        {"kick_user_id": {"$exists": False}, "kick_id": {"$exists": True}},
        [{"$set": {"kick_user_id": "$kick_id"}}]
    )
    
    return {
        "success": True,
        "message": f"Migration complete. Updated {result.modified_count} users.",
        "users_missing_before": missing_count,
        "users_updated": result.modified_count,
        "note": "Users who haven't logged in since migration will get kick_user_id on next login"
    }


# ==================== LEADERBOARD TIMERS ADMIN ====================

def calculate_next_period_end(current_end: datetime, period_type: str) -> datetime:
    if period_type == "weekly":
        return current_end + timedelta(days=7)
    elif period_type == "bi-weekly":
        return current_end + timedelta(days=14)
    elif period_type == "monthly":
        if current_end.month == 12:
            return current_end.replace(year=current_end.year + 1, month=1)
        else:
            try:
                return current_end.replace(month=current_end.month + 1)
            except ValueError:
                next_month = current_end.month + 1
                if next_month > 12:
                    next_month = 1
                    year = current_end.year + 1
                else:
                    year = current_end.year
                if next_month in [4, 6, 9, 11]:
                    day = min(current_end.day, 30)
                elif next_month == 2:
                    day = min(current_end.day, 28)
                else:
                    day = current_end.day
                return current_end.replace(year=year, month=next_month, day=day)
    return current_end + timedelta(days=30)

@api_router.get("/admin/leaderboard-timers")
async def admin_get_leaderboard_timers(username: str = Depends(verify_admin)):
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

@api_router.put("/admin/leaderboard-timers/{site}")
async def admin_update_leaderboard_timer(site: str, timer_update: LeaderboardTimerUpdate, username: str = Depends(verify_admin)):
    site = site.lower()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await get_leaderboard_settings(site)
    update_data = timer_update.model_dump(exclude_none=True)
    
    if "period_type" in update_data:
        existing["period_type"] = update_data["period_type"]
        period_labels = {"weekly": "Weekly", "bi-weekly": "Bi-Weekly", "monthly": "Monthly"}
        existing["period"] = period_labels.get(update_data["period_type"], "Monthly")
    
    for key in ["start_date", "end_date", "is_active", "fetch_start", "fetch_end"]:
        if key in update_data:
            existing[key] = update_data[key]
    
    existing["site"] = site
    await db.leaderboard_settings.update_one({"site": site}, {"$set": existing}, upsert=True)
    
    return {"success": True, "message": f"Timer for {site} updated", "settings": existing}

@api_router.post("/admin/leaderboard-timers/{site}/reset")
async def admin_reset_leaderboard_timer(site: str, username: str = Depends(verify_admin)):
    site = site.lower()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await get_leaderboard_settings(site)
    period_type = existing.get("period_type", "monthly")
    
    old_end_str = existing.get("end_date", "")
    if old_end_str:
        old_end = datetime.fromisoformat(old_end_str.replace('Z', '+00:00'))
    else:
        old_end = datetime.now(timezone.utc)
    
    new_start = old_end
    new_end = calculate_next_period_end(old_end, period_type)
    
    existing["start_date"] = new_start.isoformat()
    existing["end_date"] = new_end.isoformat()
    existing["site"] = site
    existing["last_reset"] = datetime.now(timezone.utc).isoformat()
    
    if site == "bitfortune":
        existing["fetch_start"] = int(new_start.timestamp())
        existing["fetch_end"] = int(new_end.timestamp())
    
    await db.leaderboard_settings.update_one({"site": site}, {"$set": existing}, upsert=True)
    
    return {
        "success": True,
        "message": f"Timer for {site} reset. New period: {new_start.strftime('%Y-%m-%d')} to {new_end.strftime('%Y-%m-%d')}",
        "new_start": new_start.isoformat(),
        "new_end": new_end.isoformat()
    }


# ==================== KICK WEBHOOK ====================

message_cooldowns = {}

async def get_bot_access_token():
    if db is None:
        return None
    try:
        settings = await db.settings.find_one({"type": "bot_tokens"})
        if settings and settings.get("access_token"):
            return settings.get("access_token")
    except:
        pass
    return None

async def send_kick_chat_message(message: str):
    """Send chat message using bot token with automatic refresh"""
    access_token, bot_user_id = await get_valid_bot_token()
    if not access_token:
        logger.error("No valid bot access token found")
        return False
    
    try:
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
            
            # Get the CHANNEL's broadcaster ID (where to send the message)
            broadcaster_id = None
            if db is not None:
                # First try channel_tokens (the channel we're monitoring)
                channel_settings = await db.settings.find_one({"type": "channel_tokens"})
                if channel_settings:
                    broadcaster_id = channel_settings.get("user_id")
                
                # Fallback to bot_tokens if no channel_tokens
                if not broadcaster_id:
                    broadcaster_id = bot_user_id
            
            if not broadcaster_id:
                logger.error("No broadcaster_id found for chat message")
                return False
            
            payload = {
                "content": message,
                "type": "user",
                "broadcaster_user_id": int(broadcaster_id)
            }
            
            logger.info(f"Sending chat message to broadcaster {broadcaster_id}: {message[:50]}...")
            response = await client.post("https://api.kick.com/public/v1/chat", headers=headers, json=payload)
            
            # If 401, try refreshing token and retry
            if response.status_code == 401:
                logger.info("Bot token expired during send, refreshing...")
                new_token = await refresh_kick_token("bot_tokens")
                if new_token:
                    headers["Authorization"] = f"Bearer {new_token}"
                    response = await client.post("https://api.kick.com/public/v1/chat", headers=headers, json=payload)
            
            logger.info(f"Chat API response: {response.status_code} - {response.text[:200] if response.text else 'empty'}")
            return response.status_code in [200, 201]
    except Exception as e:
        logger.error(f"Error sending chat message: {e}")
        return False

async def can_earn_points(user_id: int) -> bool:
    rates = await get_earning_rates()
    cooldown_seconds = rates.get("cooldown_seconds", 30)
    
    now = datetime.now(timezone.utc)
    if user_id in message_cooldowns:
        last_earned = message_cooldowns[user_id]
        if (now - last_earned).total_seconds() < cooldown_seconds:
            return False
    return True

def update_cooldown(user_id: int):
    message_cooldowns[user_id] = datetime.now(timezone.utc)

async def award_points_for_chat(username: str, user_id: int):
    if db is None:
        return False
    
    if not await can_earn_points(user_id):
        return False
    
    try:
        rates = await get_earning_rates()
        points_per_message = rates.get("points_per_message", 1)
        
        user = await db.users.find_one({
            "$or": [
                {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
                {"kick_user_id": str(user_id)}
            ]
        })
        
        if not user or user.get('is_banned', False):
            return False
        
        result = await db.users.update_one({"_id": user["_id"]}, {"$inc": {"points_balance": points_per_message}})
        
        if result.modified_count > 0:
            update_cooldown(user_id)
            return True
    except:
        pass
    return False

async def handle_points_command(username: str):
    if db is None:
        return "Service temporarily unavailable"
    
    user = await db.users.find_one({"kick_username": {"$regex": f"^{username}$", "$options": "i"}}, {"_id": 0, "points_balance": 1})
    
    if user:
        balance = user.get('points_balance', 0)
        return f"@{username} You have {balance:,.0f} points!"
    return f"@{username} You haven't registered yet! Visit the website to login with Kick."

async def handle_leaderboard_command():
    if db is None:
        return "Service temporarily unavailable"
    
    cursor = db.users.find({"is_banned": {"$ne": True}, "points_balance": {"$gt": 0}}, {"_id": 0, "kick_username": 1, "points_balance": 1}).sort("points_balance", -1).limit(5)
    users = await cursor.to_list(length=5)
    
    if not users:
        return "No users on the leaderboard yet!"
    
    medals = ["1st", "2nd", "3rd", "4th", "5th"]
    parts = [f"{medals[i]}: {user.get('kick_username', 'Unknown')} ({user.get('points_balance', 0):,.0f})" for i, user in enumerate(users)]
    return "Leaderboard: " + " | ".join(parts)

async def handle_rank_command(username: str):
    if db is None:
        return "Service temporarily unavailable"
    
    user = await db.users.find_one({"kick_username": {"$regex": f"^{username}$", "$options": "i"}}, {"_id": 0, "points_balance": 1})
    
    if not user:
        return f"@{username} You haven't registered yet!"
    
    user_points = user.get('points_balance', 0)
    higher_count = await db.users.count_documents({"is_banned": {"$ne": True}, "points_balance": {"$gt": user_points}})
    rank = higher_count + 1
    total_users = await db.users.count_documents({"is_banned": {"$ne": True}, "points_balance": {"$gt": 0}})
    
    return f"@{username} You are rank #{rank} out of {total_users} users with {user_points:,} points!"

async def handle_tip_command(sender: str, content: str):
    if sender.lower() not in KICK_ADMINS:
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
    
    target_user = await db.users.find_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}})
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"$inc": {"points_balance": amount}})
    
    if result.modified_count > 0:
        return f"@{sender} gave {amount:,} points to @{target}!"
    return f"@{sender} Failed to tip."

async def handle_addpoints_command(sender: str, content: str):
    if sender.lower() not in KICK_ADMINS:
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
    
    target_user = await db.users.find_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}})
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"$inc": {"points_balance": amount}})
    
    if result.modified_count > 0:
        return f"@{sender} Added {amount:,} points to @{target}!"
    return f"@{sender} Failed to add points."

async def handle_removepoints_command(sender: str, content: str):
    if sender.lower() not in KICK_ADMINS:
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
    
    target_user = await db.users.find_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"_id": 0, "points_balance": 1})
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    current_balance = target_user.get('points_balance', 0)
    new_balance = max(0, current_balance - amount)
    
    result = await db.users.update_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"$set": {"points_balance": new_balance}})
    
    if result.modified_count > 0:
        removed = current_balance - new_balance
        return f"@{sender} Removed {removed:,} points from @{target}. New balance: {new_balance:,}"
    return f"@{sender} Failed to remove points."

async def handle_setpoints_command(sender: str, content: str):
    if sender.lower() not in KICK_ADMINS:
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
    
    target_user = await db.users.find_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}})
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"$set": {"points_balance": amount}})
    
    if result.modified_count > 0:
        return f"@{sender} Set @{target}'s points to {amount:,}!"
    return f"@{sender} Failed to set points."

async def handle_ban_command(sender: str, content: str):
    if sender.lower() not in KICK_ADMINS:
        return f"@{sender} Only the channel owner can use !ban"
    
    parts = content.split()
    if len(parts) < 2:
        return f"@{sender} Usage: !ban @username"
    
    target = parts[1].lstrip('@')
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}})
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"$set": {"is_banned": True}})
    
    if result.modified_count > 0:
        return f"@{sender} Banned @{target} from earning points!"
    return f"@{sender} Failed to ban user."

async def handle_unban_command(sender: str, content: str):
    if sender.lower() not in KICK_ADMINS:
        return f"@{sender} Only the channel owner can use !unban"
    
    parts = content.split()
    if len(parts) < 2:
        return f"@{sender} Usage: !unban @username"
    
    target = parts[1].lstrip('@')
    
    if db is None:
        return "Service temporarily unavailable"
    
    target_user = await db.users.find_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}})
    if not target_user:
        return f"@{sender} User @{target} not found."
    
    result = await db.users.update_one({"kick_username": {"$regex": f"^{target}$", "$options": "i"}}, {"$set": {"is_banned": False}})
    
    if result.modified_count > 0:
        return f"@{sender} Unbanned @{target}. They can earn points again!"
    return f"@{sender} Failed to unban user."

@api_router.post("/webhook/kick")
async def kick_webhook(request: Request):
    try:
        event_type = request.headers.get("Kick-Event-Type", "")
        body = await request.json()
        
        logger.info(f"Received Kick webhook: {event_type} - Body: {str(body)[:500]}")
        
        if event_type == "chat.message.sent":
            sender = body.get("sender", {})
            sender_username = sender.get("username", "")
            sender_user_id = sender.get("user_id", 0)
            content = body.get("content", "")
            
            logger.info(f"Chat message from {sender_username}: {content}")
            
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
            elif content_lower in ["!commands"]:
                # Build commands list from enabled commands in database
                if db is not None:
                    cmds = await db.kick_commands.find({"is_enabled": True}, {"command": 1, "_id": 0}).to_list(50)
                    cmd_list = " | ".join([c["command"] for c in cmds])
                    response_message = f"Commands: {cmd_list}"
                else:
                    response_message = "Commands: !points | !rank | !leaderboard | !site | !menace | !meta | !bit | !discord"
            else:
                # Check for custom commands from database
                custom_response = await get_command_response(content_lower)
                if custom_response:
                    response_message = custom_response
                else:
                    await award_points_for_chat(sender_username, sender_user_id)
            
            if response_message:
                logger.info(f"Sending response: {response_message}")
                result = await send_kick_chat_message(response_message)
                logger.info(f"Message send result: {result}")
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error", "message": str(e)}

@api_router.get("/webhook/kick")
async def kick_webhook_verify():
    return {"status": "ok", "message": "Webhook endpoint active"}



# ============================================
# PROVABLY FAIR CASINO GAMES SYSTEM
# ============================================

# Game Constants
GAME_HOUSE_EDGE = 0.01  # 1% house edge
MAX_BET_AMOUNT = 100000  # Maximum bet amount

class GameTypeEnum(str, Enum):
    dice = "dice"
    limbo = "limbo"
    mines = "mines"
    blackjack = "blackjack"

# Pydantic Models for Games
class InitSeedsRequest(BaseModel):
    client_seed: Optional[str] = None

class DiceBetRequest(BaseModel):
    bet_amount: float = Field(..., gt=0, le=MAX_BET_AMOUNT)
    target: float = Field(..., ge=1, le=98)
    roll_over: bool = True

class LimboBetRequest(BaseModel):
    bet_amount: float = Field(..., gt=0, le=MAX_BET_AMOUNT)
    target_multiplier: float = Field(..., ge=1.01, le=1000000)

class MinesStartRequest(BaseModel):
    bet_amount: float = Field(..., gt=0, le=MAX_BET_AMOUNT)
    num_mines: int = Field(..., ge=1, le=24)

class MinesRevealRequest(BaseModel):
    session_id: str
    tile_index: int = Field(..., ge=0, le=24)

class MinesCashoutRequest(BaseModel):
    session_id: str

class BlackjackStartRequest(BaseModel):
    bet_amount: float = Field(..., gt=0, le=MAX_BET_AMOUNT)

class BlackjackActionRequest(BaseModel):
    session_id: str
    action: str  # hit, stand, double

class VerifyGameRequest(BaseModel):
    server_seed: str
    server_seed_hashed: str
    client_seed: str
    nonce: int
    game_type: GameTypeEnum
    game_params: Optional[dict] = {}

class WheelBetRequest(BaseModel):
    bet_amount: float = Field(..., gt=0, le=MAX_BET_AMOUNT)
    risk: str = Field(...)
    segments: int = Field(...)

# ============================================
# PROVABLY FAIR CORE FUNCTIONS
# ============================================

def generate_server_seed() -> str:
    """Generate a cryptographically secure 32-byte server seed"""
    return binascii.hexlify(secrets.token_bytes(32)).decode('utf-8')

def hash_server_seed(server_seed: str) -> str:
    """Hash server seed with SHA-256 (shown to player before game)"""
    return hashlib.sha256(server_seed.encode()).hexdigest()

def generate_hmac_result(server_seed: str, client_seed: str, nonce: int) -> str:
    """Generate HMAC-SHA512 hash from seeds and nonce"""
    message = f"{client_seed}:{nonce}".encode()
    return hmac.new(server_seed.encode(), message, hashlib.sha512).hexdigest()

def hmac_to_float(hmac_hex: str, offset: int = 0) -> float:
    """Convert HMAC bytes to float [0, 1) for game outcomes"""
    hex_slice = hmac_hex[offset*2:(offset+4)*2]
    value = int(hex_slice, 16)
    return value / (16 ** 8)

def calculate_dice_result(server_seed: str, client_seed: str, nonce: int) -> float:
    """Calculate dice roll result (0.00 - 99.99)"""
    hmac_hex = generate_hmac_result(server_seed, client_seed, nonce)
    float_value = hmac_to_float(hmac_hex)
    return round(float_value * 100, 2)

def calculate_limbo_result(server_seed: str, client_seed: str, nonce: int) -> float:
    """Calculate limbo multiplier (1.00 - 1000000x)"""
    hmac_hex = generate_hmac_result(server_seed, client_seed, nonce)
    float_value = hmac_to_float(hmac_hex)
    
    if float_value == 0:
        return 1000000.00
    
    multiplier = (1 - GAME_HOUSE_EDGE) / float_value
    multiplier = min(multiplier, 1000000.0)
    multiplier = max(multiplier, 1.0)
    
    return round(multiplier, 2)

def calculate_mines_grid(server_seed: str, client_seed: str, nonce: int, num_mines: int, grid_size: int = 25) -> list:
    """Calculate mine positions for mines game"""
    hmac_hex = generate_hmac_result(server_seed, client_seed, nonce)
    positions = list(range(grid_size))
    
    for i in range(grid_size - 1, 0, -1):
        byte_offset = (grid_size - 1 - i) * 4
        if byte_offset + 8 > len(hmac_hex):
            extended_hmac = generate_hmac_result(server_seed, f"{client_seed}:ext", nonce)
            hmac_hex += extended_hmac
        
        hex_slice = hmac_hex[byte_offset:byte_offset+8]
        j = int(hex_slice, 16) % (i + 1)
        positions[i], positions[j] = positions[j], positions[i]
    
    return sorted(positions[:num_mines])

def calculate_blackjack_deck(server_seed: str, client_seed: str, nonce: int) -> list:
    """Generate shuffled deck for blackjack"""
    hmac_hex = generate_hmac_result(server_seed, client_seed, nonce)
    
    suits = ['hearts', 'diamonds', 'clubs', 'spades']
    values = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K']
    
    deck = []
    for suit in suits:
        for value in values:
            deck.append({'suit': suit, 'value': value})
    
    for i in range(51, 0, -1):
        byte_offset = (51 - i) * 4
        if byte_offset + 8 > len(hmac_hex):
            extended_hmac = generate_hmac_result(server_seed, f"{client_seed}:deck", nonce)
            hmac_hex += extended_hmac
        
        hex_slice = hmac_hex[byte_offset:byte_offset+8]
        j = int(hex_slice, 16) % (i + 1)
        deck[i], deck[j] = deck[j], deck[i]
    
    return deck

def get_card_value(card: dict) -> int:
    """Get blackjack value of a card"""
    value = card['value']
    if value in ['J', 'Q', 'K']:
        return 10
    if value == 'A':
        return 11
    return int(value)

def calculate_hand_value(cards: list) -> int:
    """Calculate blackjack hand value, handling aces"""
    total = sum(get_card_value(card) for card in cards)
    aces = sum(1 for card in cards if card['value'] == 'A')
    
    while total > 21 and aces > 0:
        total -= 10
        aces -= 1
    
    return total

def calculate_dice_multiplier(win_chance: float) -> float:
    """Calculate payout multiplier for dice based on win chance"""
    if win_chance <= 0 or win_chance >= 100:
        return 0
    multiplier = (100 * (1 - GAME_HOUSE_EDGE)) / win_chance
    return round(multiplier, 4)

def calculate_mines_multiplier(revealed: int, num_mines: int, grid_size: int = 25) -> float:
    """Calculate current multiplier for mines game"""
    if revealed == 0:
        return 1.0
    
    safe_tiles = grid_size - num_mines
    multiplier = 1.0
    
    for i in range(revealed):
        remaining_safe = safe_tiles - i
        remaining_total = grid_size - i
        if remaining_safe <= 0:
            return 0
        prob = remaining_safe / remaining_total
        multiplier *= (1 / prob) * (1 - GAME_HOUSE_EDGE)
    
    return round(multiplier, 4)

# Wheel game segment configurations (1% house edge)
WHEEL_CONFIGS = {
    10: {
        "low": [0, 1.2, 1.2, 1.2, 1.2, 1.2, 1.5, 1.5, 1.5, 2],
        "medium": [0, 0, 0, 1.5, 1.5, 1.5, 1.5, 2, 2, 3],
        "high": [0, 0, 0, 0, 0, 2, 2, 5, 5, 10]
    },
    20: {
        "low": [0, 0, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.5, 1.5, 1.5, 1.5, 1.5, 2, 2, 3],
        "medium": [0, 0, 0, 0, 0, 0, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 2, 2, 2, 2, 3, 3, 5, 5],
        "high": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2, 3, 3, 3, 5, 5, 10]
    },
    50: {
        "low": [0, 0, 0, 0, 0, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.2, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 2, 2, 2, 3],
        "medium": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 1.5, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 5, 5, 5, 5, 10],
        "high": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 24]
    }
}

def calculate_wheel_result(server_seed: str, client_seed: str, nonce: int, segments: int) -> int:
    """Calculate which segment the wheel lands on (0 to segments-1)"""
    hmac_hex = generate_hmac_result(server_seed, client_seed, nonce)
    float_value = hmac_to_float(hmac_hex)
    return int(float_value * segments)

def get_wheel_multiplier(segment_index: int, segments: int, risk: str) -> float:
    """Get the multiplier for a specific wheel segment"""
    config = WHEEL_CONFIGS.get(segments, WHEEL_CONFIGS[10])
    multipliers = config.get(risk, config["low"])
    return multipliers[segment_index % len(multipliers)]

def calculate_keno_draw(server_seed: str, client_seed: str, nonce: int, total_numbers: int = 40, draw_count: int = 10) -> List[int]:
    """Calculate which numbers are drawn in Keno"""
    drawn = []
    available = list(range(1, total_numbers + 1))
    
    for i in range(draw_count):
        hmac_hex = generate_hmac_result(server_seed, client_seed, nonce * 100 + i)
        float_value = hmac_to_float(hmac_hex)
        index = int(float_value * len(available))
        drawn.append(available.pop(index))
    
    return sorted(drawn)

# Keno payout tables (Stake-style accurate multipliers)
KENO_PAYOUTS = {
    "low": {
        1: {0: 0, 1: 2.5},
        2: {0: 0, 1: 1, 2: 4},
        3: {0: 0, 1: 0, 2: 1.5, 3: 5.2},
        4: {0: 0, 1: 0, 2: 0.5, 3: 2, 4: 9},
        5: {0: 0, 1: 0, 2: 0, 3: 1.5, 4: 4, 5: 14},
        6: {0: 0, 1: 0, 2: 0, 3: 1, 4: 2.5, 5: 7, 6: 20},
        7: {0: 0, 1: 0, 2: 0, 3: 0.5, 4: 2, 5: 4, 6: 10, 7: 35},
        8: {0: 0, 1: 0, 2: 0, 3: 0, 4: 1.5, 5: 3, 6: 6, 7: 15, 8: 50},
        9: {0: 0, 1: 0, 2: 0, 3: 0, 4: 1, 5: 2, 6: 4, 7: 10, 8: 30, 9: 75},
        10: {0: 0, 1: 0, 2: 0, 3: 0, 4: 0.5, 5: 1.5, 6: 3, 7: 7, 8: 20, 9: 50, 10: 100}
    },
    "medium": {
        1: {0: 0, 1: 3.8},
        2: {0: 0, 1: 0, 2: 9},
        3: {0: 0, 1: 0, 2: 1, 3: 25},
        4: {0: 0, 1: 0, 2: 0, 3: 3, 4: 50},
        5: {0: 0, 1: 0, 2: 0, 3: 2, 4: 10, 5: 80},
        6: {0: 0, 1: 0, 2: 0, 3: 1, 4: 5, 5: 25, 6: 130},
        7: {0: 0, 1: 0, 2: 0, 3: 0.5, 4: 3, 5: 12, 6: 50, 7: 200},
        8: {0: 0, 1: 0, 2: 0, 3: 0, 4: 2, 5: 7, 6: 25, 7: 100, 8: 400},
        9: {0: 0, 1: 0, 2: 0, 3: 0, 4: 1, 5: 4, 6: 15, 7: 50, 8: 200, 9: 700},
        10: {0: 0, 1: 0, 2: 0, 3: 0, 4: 0.5, 5: 3, 6: 10, 7: 30, 8: 100, 9: 400, 10: 1000}
    },
    "high": {
        1: {0: 0, 1: 3.96},
        2: {0: 0, 1: 0, 2: 17},
        3: {0: 0, 1: 0, 2: 0, 3: 80},
        4: {0: 0, 1: 0, 2: 0, 3: 2, 4: 250},
        5: {0: 0, 1: 0, 2: 0, 3: 0, 4: 12, 5: 500},
        6: {0: 0, 1: 0, 2: 0, 3: 0, 4: 5, 5: 50, 6: 1000},
        7: {0: 0, 1: 0, 2: 0, 3: 0, 4: 2, 5: 20, 6: 200, 7: 2000},
        8: {0: 0, 1: 0, 2: 0, 3: 0, 4: 1, 5: 10, 6: 80, 7: 500, 8: 5000},
        9: {0: 0, 1: 0, 2: 0, 3: 0, 4: 0.5, 5: 5, 6: 40, 7: 250, 8: 2000, 9: 10000},
        10: {0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 3, 6: 20, 7: 100, 8: 1000, 9: 8000, 10: 100000}
    }
}

def verify_game_result(server_seed: str, server_seed_hashed: str, client_seed: str, nonce: int, game_type: str, game_params: dict) -> Dict[str, Any]:
    """Verify a game result is fair"""
    calculated_hash = hash_server_seed(server_seed)
    hash_valid = calculated_hash == server_seed_hashed
    
    if game_type == "dice":
        result = calculate_dice_result(server_seed, client_seed, nonce)
    elif game_type == "limbo":
        result = calculate_limbo_result(server_seed, client_seed, nonce)
    elif game_type == "mines":
        result = calculate_mines_grid(server_seed, client_seed, nonce, game_params.get('num_mines', 3))
    elif game_type == "blackjack":
        result = calculate_blackjack_deck(server_seed, client_seed, nonce)
    elif game_type == "wheel":
        segments = game_params.get('segments', 10)
        risk = game_params.get('risk', 'low')
        segment_index = calculate_wheel_result(server_seed, client_seed, nonce, segments)
        result = {"segment_index": segment_index, "multiplier": get_wheel_multiplier(segment_index, segments, risk)}
    else:
        result = None
    
    return {
        'hash_valid': hash_valid,
        'calculated_hash': calculated_hash,
        'provided_hash': server_seed_hashed,
        'recalculated_result': result,
        'hmac': generate_hmac_result(server_seed, client_seed, nonce)
    }

# ============================================
# GAME SEED MANAGEMENT ENDPOINTS
# ============================================

async def get_or_create_seeds(user_id: str, client_seed: Optional[str] = None):
    """Helper function to get existing seeds or create new ones automatically"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await db.user_seeds.find_one({"user_id": user_id})
    
    if existing:
        return existing
    
    # Auto-create seeds if they don't exist
    server_seed = generate_server_seed()
    next_server_seed = generate_server_seed()
    auto_client_seed = client_seed or f"pez_{user_id}_{int(datetime.now().timestamp())}"
    
    seed_doc = {
        "user_id": user_id,
        "server_seed": server_seed,
        "server_seed_hashed": hash_server_seed(server_seed),
        "next_server_seed": next_server_seed,
        "next_server_seed_hashed": hash_server_seed(next_server_seed),
        "client_seed": auto_client_seed,
        "nonce": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.user_seeds.insert_one(seed_doc)
    logger.info(f"Auto-initialized seeds for user {user_id}")
    return seed_doc

@api_router.post("/games/seeds/init")
async def initialize_seeds(request_data: InitSeedsRequest, request: Request):
    """Initialize or get user's provably fair seeds"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await db.user_seeds.find_one({"user_id": user_id})
    
    if existing:
        return {
            "success": True,
            "server_seed_hashed": existing['server_seed_hashed'],
            "next_server_seed_hashed": existing['next_server_seed_hashed'],
            "client_seed": existing['client_seed'],
            "nonce": existing['nonce']
        }
    
    server_seed = generate_server_seed()
    next_server_seed = generate_server_seed()
    client_seed = request_data.client_seed or f"pez_{user_id}_{int(datetime.now().timestamp())}"
    
    seed_doc = {
        "user_id": user_id,
        "server_seed": server_seed,
        "server_seed_hashed": hash_server_seed(server_seed),
        "next_server_seed": next_server_seed,
        "next_server_seed_hashed": hash_server_seed(next_server_seed),
        "client_seed": client_seed,
        "nonce": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.user_seeds.insert_one(seed_doc)
    
    return {
        "success": True,
        "server_seed_hashed": seed_doc['server_seed_hashed'],
        "next_server_seed_hashed": seed_doc['next_server_seed_hashed'],
        "client_seed": seed_doc['client_seed'],
        "nonce": seed_doc['nonce']
    }

@api_router.post("/games/seeds/rotate")
async def rotate_seeds(request_data: InitSeedsRequest, request: Request):
    """Rotate seeds - reveals old server seed, generates new one"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await db.user_seeds.find_one({"user_id": user_id})
    if not existing:
        raise HTTPException(status_code=400, detail="No seeds found. Call /games/seeds/init first")
    
    old_server_seed = existing['server_seed']
    old_server_seed_hashed = existing['server_seed_hashed']
    
    new_next_server_seed = generate_server_seed()
    new_client_seed = request_data.client_seed or existing['client_seed']
    
    await db.user_seeds.update_one(
        {"user_id": user_id},
        {"$set": {
            "server_seed": existing['next_server_seed'],
            "server_seed_hashed": existing['next_server_seed_hashed'],
            "next_server_seed": new_next_server_seed,
            "next_server_seed_hashed": hash_server_seed(new_next_server_seed),
            "client_seed": new_client_seed,
            "nonce": 0,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    return {
        "success": True,
        "revealed_server_seed": old_server_seed,
        "revealed_server_seed_hashed": old_server_seed_hashed,
        "new_server_seed_hashed": existing['next_server_seed_hashed'],
        "next_server_seed_hashed": hash_server_seed(new_next_server_seed),
        "client_seed": new_client_seed,
        "nonce": 0
    }

@api_router.put("/games/seeds/client")
async def update_client_seed(request_data: InitSeedsRequest, request: Request):
    """Update client seed"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    if not request_data.client_seed:
        raise HTTPException(status_code=400, detail="client_seed is required")
    
    result = await db.user_seeds.update_one(
        {"user_id": user_id},
        {"$set": {"client_seed": request_data.client_seed, "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=400, detail="No seeds found")
    
    return {"success": True, "client_seed": request_data.client_seed}

# ============================================
# DICE GAME ENDPOINT
# ============================================

@api_router.post("/games/dice/bet")
async def play_dice(request_data: DiceBetRequest, request: Request):
    """Place a dice bet"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Check balance and game ban status
    db_user = await db.users.find_one({"id": user_id})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if db_user.get('can_play_games') == False:
        raise HTTPException(status_code=403, detail="You are banned from playing games")
    if db_user.get('points_balance', 0) < request_data.bet_amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Get user seeds (auto-create if not exist)
    seeds = await get_or_create_seeds(user_id)
    
    # Pre-calculate result
    roll_result = calculate_dice_result(seeds['server_seed'], seeds['client_seed'], seeds['nonce'])
    
    # Calculate win chance and multiplier
    if request_data.roll_over:
        win_chance = 99.99 - request_data.target
        won = roll_result > request_data.target
    else:
        win_chance = request_data.target
        won = roll_result < request_data.target
    
    multiplier = calculate_dice_multiplier(win_chance)
    payout = request_data.bet_amount * multiplier if won else 0
    profit = payout - request_data.bet_amount
    
    # Update balance atomically
    new_balance = db_user['points_balance'] - request_data.bet_amount + payout
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    
    # Increment nonce
    await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
    
    # Save to history
    history_doc = {
        "user_id": user_id,
        "kick_username": db_user.get("kick_username", "Unknown"),
        "game_type": "dice",
        "bet_amount": request_data.bet_amount,
        "multiplier": multiplier if won else 0,
        "payout": payout,
        "profit": profit,
        "server_seed": seeds['server_seed'],
        "server_seed_hashed": seeds['server_seed_hashed'],
        "client_seed": seeds['client_seed'],
        "nonce": seeds['nonce'],
        "game_data": {
            "target": request_data.target,
            "roll_over": request_data.roll_over,
            "roll_result": roll_result,
            "win_chance": win_chance,
            "won": won
        },
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_history.insert_one(history_doc)
    
    return {
        "success": True,
        "result": {
            "roll": roll_result,
            "target": request_data.target,
            "roll_over": request_data.roll_over,
            "won": won,
            "multiplier": multiplier,
            "payout": payout,
            "profit": profit,
            "new_balance": new_balance
        },
        "fairness": {
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce']
        }
    }

# ============================================
# WHEEL GAME ENDPOINT
# ============================================

@api_router.post("/games/wheel/spin")
async def play_wheel(request_data: WheelBetRequest, request: Request):
    """Spin the wheel"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Validate inputs
    if request_data.risk not in ["low", "medium", "high"]:
        raise HTTPException(status_code=400, detail="Invalid risk level")
    if request_data.segments not in [10, 20, 50]:
        raise HTTPException(status_code=400, detail="Invalid segment count")
    
    db_user = await db.users.find_one({"id": user_id})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if db_user.get('can_play_games') == False:
        raise HTTPException(status_code=403, detail="You are banned from playing games")
    if db_user.get('points_balance', 0) < request_data.bet_amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    seeds = await get_or_create_seeds(user_id)
    
    # Calculate result
    segment_index = calculate_wheel_result(seeds['server_seed'], seeds['client_seed'], seeds['nonce'], request_data.segments)
    multiplier = get_wheel_multiplier(segment_index, request_data.segments, request_data.risk)
    
    won = multiplier > 0
    payout = request_data.bet_amount * multiplier if won else 0
    profit = payout - request_data.bet_amount
    
    new_balance = db_user['points_balance'] - request_data.bet_amount + payout
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
    
    # Get all multipliers for the wheel display
    config = WHEEL_CONFIGS.get(request_data.segments, WHEEL_CONFIGS[10])
    wheel_multipliers = config.get(request_data.risk, config["low"])
    
    history_doc = {
        "user_id": user_id,
        "kick_username": db_user.get("kick_username", "Unknown"),
        "game_type": "wheel",
        "bet_amount": request_data.bet_amount,
        "multiplier": multiplier,
        "payout": payout,
        "profit": profit,
        "server_seed": seeds['server_seed'],
        "server_seed_hashed": seeds['server_seed_hashed'],
        "client_seed": seeds['client_seed'],
        "nonce": seeds['nonce'],
        "game_data": {
            "segments": request_data.segments,
            "risk": request_data.risk,
            "segment_index": segment_index,
            "won": won
        },
        "status": "completed",
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_history.insert_one(history_doc)
    
    return {
        "success": True,
        "result": {
            "segment_index": segment_index,
            "multiplier": multiplier,
            "won": won,
            "payout": payout,
            "profit": profit,
            "new_balance": new_balance,
            "wheel_multipliers": wheel_multipliers
        },
        "fairness": {
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce']
        }
    }

@api_router.get("/games/wheel/config")
async def get_wheel_config():
    """Get wheel configuration for all risk levels and segments"""
    return {
        "success": True,
        "configs": WHEEL_CONFIGS
    }

# ============================================
# LIMBO GAME ENDPOINT
# ============================================

@api_router.post("/games/limbo/bet")
async def play_limbo(request_data: LimboBetRequest, request: Request):
    """Place a limbo bet"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    db_user = await db.users.find_one({"id": user_id})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if db_user.get('can_play_games') == False:
        raise HTTPException(status_code=403, detail="You are banned from playing games")
    if db_user.get('points_balance', 0) < request_data.bet_amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    seeds = await get_or_create_seeds(user_id)
    
    result_multiplier = calculate_limbo_result(seeds['server_seed'], seeds['client_seed'], seeds['nonce'])
    
    won = result_multiplier >= request_data.target_multiplier
    payout = request_data.bet_amount * request_data.target_multiplier if won else 0
    profit = payout - request_data.bet_amount
    
    new_balance = db_user['points_balance'] - request_data.bet_amount + payout
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
    
    history_doc = {
        "user_id": user_id,
        "kick_username": db_user.get("kick_username", "Unknown"),
        "game_type": "limbo",
        "bet_amount": request_data.bet_amount,
        "multiplier": request_data.target_multiplier if won else 0,
        "payout": payout,
        "profit": profit,
        "server_seed": seeds['server_seed'],
        "server_seed_hashed": seeds['server_seed_hashed'],
        "client_seed": seeds['client_seed'],
        "nonce": seeds['nonce'],
        "game_data": {
            "target_multiplier": request_data.target_multiplier,
            "result_multiplier": result_multiplier,
            "won": won
        },
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_history.insert_one(history_doc)
    
    return {
        "success": True,
        "result": {
            "result_multiplier": result_multiplier,
            "target_multiplier": request_data.target_multiplier,
            "won": won,
            "payout": payout,
            "profit": profit,
            "new_balance": new_balance
        },
        "fairness": {
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce']
        }
    }

# ============================================
# KENO GAME ENDPOINT
# ============================================

@api_router.post("/games/keno/bet")
async def play_keno(request_data: KenoBetRequest, request: Request):
    """Place a Keno bet"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Validate input
    if not request_data.selected_numbers or len(request_data.selected_numbers) < 1 or len(request_data.selected_numbers) > 10:
        raise HTTPException(status_code=400, detail="Select between 1 and 10 numbers")
    
    if any(n < 1 or n > 40 for n in request_data.selected_numbers):
        raise HTTPException(status_code=400, detail="Numbers must be between 1 and 40")
    
    if len(request_data.selected_numbers) != len(set(request_data.selected_numbers)):
        raise HTTPException(status_code=400, detail="Duplicate numbers not allowed")
    
    if request_data.risk not in ["low", "medium", "high"]:
        raise HTTPException(status_code=400, detail="Invalid risk level")
    
    db_user = await db.users.find_one({"id": user_id})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if db_user.get('can_play_games') == False:
        raise HTTPException(status_code=403, detail="You are banned from playing games")
    if db_user.get('points_balance', 0) < request_data.bet_amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    seeds = await get_or_create_seeds(user_id)
    
    # Calculate drawn numbers
    drawn_numbers = calculate_keno_draw(seeds['server_seed'], seeds['client_seed'], seeds['nonce'])
    
    # Calculate hits
    hits = len(set(request_data.selected_numbers) & set(drawn_numbers))
    picks = len(request_data.selected_numbers)
    
    # Get payout multiplier
    payout_table = KENO_PAYOUTS.get(request_data.risk, KENO_PAYOUTS["low"])
    multiplier = payout_table.get(picks, {}).get(hits, 0)
    
    payout = request_data.bet_amount * multiplier
    profit = payout - request_data.bet_amount
    won = payout > 0
    
    new_balance = db_user['points_balance'] - request_data.bet_amount + payout
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
    
    history_doc = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "kick_username": db_user.get("kick_username", "Unknown"),
        "game_type": "keno",
        "bet_amount": request_data.bet_amount,
        "multiplier": multiplier,
        "payout": payout,
        "profit": profit,
        "won": won,
        "server_seed": seeds['server_seed'],
        "server_seed_hashed": seeds['server_seed_hashed'],
        "client_seed": seeds['client_seed'],
        "nonce": seeds['nonce'],
        "game_data": {
            "selected_numbers": request_data.selected_numbers,
            "drawn_numbers": drawn_numbers,
            "hits": hits,
            "risk": request_data.risk
        },
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_history.insert_one(history_doc)
    
    return {
        "success": True,
        "drawn_numbers": drawn_numbers,
        "hits": hits,
        "multiplier": multiplier,
        "payout": payout,
        "profit": profit,
        "won": won,
        "new_balance": new_balance,
        "fairness": {
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce']
        }
    }

# ============================================
# MINES GAME ENDPOINTS
# ============================================

@api_router.post("/games/mines/start")
async def start_mines(request_data: MinesStartRequest, request: Request):
    """Start a new mines game"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    db_user = await db.users.find_one({"id": user_id})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if db_user.get('can_play_games') == False:
        raise HTTPException(status_code=403, detail="You are banned from playing games")
    if db_user.get('points_balance', 0) < request_data.bet_amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    # Check no active mines game
    active_game = await db.game_sessions.find_one({"user_id": user_id, "game_type": "mines", "status": "in_progress"})
    if active_game:
        raise HTTPException(status_code=400, detail="You have an active mines game")
    
    seeds = await get_or_create_seeds(user_id)
    
    mine_positions = calculate_mines_grid(seeds['server_seed'], seeds['client_seed'], seeds['nonce'], request_data.num_mines)
    
    new_balance = db_user['points_balance'] - request_data.bet_amount
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    
    session_id = str(uuid.uuid4())
    session_doc = {
        "session_id": session_id,
        "user_id": user_id,
        "kick_username": db_user.get("kick_username", "Unknown"),
        "game_type": "mines",
        "bet_amount": request_data.bet_amount,
        "server_seed": seeds['server_seed'],
        "server_seed_hashed": seeds['server_seed_hashed'],
        "client_seed": seeds['client_seed'],
        "nonce": seeds['nonce'],
        "pre_calculated_result": mine_positions,
        "game_state": {"num_mines": request_data.num_mines, "revealed_tiles": [], "safe_tiles_count": 25 - request_data.num_mines},
        "status": "in_progress",
        "multiplier": 1.0,
        "payout": 0,
        "profit": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None
    }
    await db.game_sessions.insert_one(session_doc)
    await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
    
    return {
        "success": True,
        "session_id": session_id,
        "num_mines": request_data.num_mines,
        "bet_amount": request_data.bet_amount,
        "new_balance": new_balance,
        "current_multiplier": 1.0,
        "fairness": {
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce']
        }
    }

@api_router.post("/games/mines/reveal")
async def reveal_mines_tile(request_data: MinesRevealRequest, request: Request):
    """Reveal a tile in mines game"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    session = await db.game_sessions.find_one({"session_id": request_data.session_id, "user_id": user_id, "status": "in_progress"})
    if not session:
        raise HTTPException(status_code=400, detail="No active game session found")
    
    tile_index = request_data.tile_index
    mine_positions = session['pre_calculated_result']
    revealed = session['game_state']['revealed_tiles']
    
    if tile_index in revealed:
        raise HTTPException(status_code=400, detail="Tile already revealed")
    
    is_mine = tile_index in mine_positions
    
    if is_mine:
        await db.game_sessions.update_one(
            {"session_id": request_data.session_id},
            {"$set": {
                "status": "completed",
                "game_state.revealed_tiles": revealed + [tile_index],
                "multiplier": 0,
                "payout": 0,
                "profit": -session['bet_amount'],
                "completed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        
        history_doc = {
            "user_id": user_id,
            "kick_username": session.get("kick_username", "Unknown"),
            "game_type": "mines",
            "bet_amount": session['bet_amount'],
            "multiplier": 0,
            "payout": 0,
            "profit": -session['bet_amount'],
            "server_seed": session['server_seed'],
            "server_seed_hashed": session['server_seed_hashed'],
            "client_seed": session['client_seed'],
            "nonce": session['nonce'],
            "game_data": {"num_mines": session['game_state']['num_mines'], "mine_positions": mine_positions, "revealed_tiles": revealed + [tile_index], "hit_mine": True},
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.game_history.insert_one(history_doc)
        
        return {
            "success": True,
            "is_mine": True,
            "game_over": True,
            "tile_index": tile_index,
            "mine_positions": mine_positions,
            "payout": 0,
            "profit": -session['bet_amount'],
            "server_seed": session['server_seed']
        }
    
    new_revealed = revealed + [tile_index]
    num_revealed = len(new_revealed)
    num_mines = session['game_state']['num_mines']
    new_multiplier = calculate_mines_multiplier(num_revealed, num_mines)
    
    safe_tiles = 25 - num_mines
    all_revealed = num_revealed >= safe_tiles
    
    if all_revealed:
        payout = session['bet_amount'] * new_multiplier
        profit = payout - session['bet_amount']
        
        db_user = await db.users.find_one({"id": user_id})
        await db.users.update_one({"id": user_id}, {"$set": {"points_balance": db_user['points_balance'] + payout}})
        
        await db.game_sessions.update_one(
            {"session_id": request_data.session_id},
            {"$set": {
                "status": "completed",
                "game_state.revealed_tiles": new_revealed,
                "multiplier": new_multiplier,
                "payout": payout,
                "profit": profit,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        
        updated_user = await db.users.find_one({"id": user_id})
        
        return {
            "success": True,
            "is_mine": False,
            "game_over": True,
            "all_safe_revealed": True,
            "tile_index": tile_index,
            "revealed_count": num_revealed,
            "current_multiplier": new_multiplier,
            "payout": payout,
            "profit": profit,
            "new_balance": updated_user['points_balance'],
            "mine_positions": mine_positions,
            "server_seed": session['server_seed']
        }
    
    await db.game_sessions.update_one(
        {"session_id": request_data.session_id},
        {"$set": {"game_state.revealed_tiles": new_revealed, "multiplier": new_multiplier}}
    )
    
    return {
        "success": True,
        "is_mine": False,
        "game_over": False,
        "tile_index": tile_index,
        "revealed_count": num_revealed,
        "current_multiplier": new_multiplier,
        "next_multiplier": calculate_mines_multiplier(num_revealed + 1, num_mines),
        "potential_payout": session['bet_amount'] * new_multiplier
    }

@api_router.post("/games/mines/cashout")
async def cashout_mines(request_data: MinesCashoutRequest, request: Request):
    """Cash out current mines game"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    session = await db.game_sessions.find_one({"session_id": request_data.session_id, "user_id": user_id, "status": "in_progress"})
    if not session:
        raise HTTPException(status_code=400, detail="No active game session found")
    
    revealed = session['game_state']['revealed_tiles']
    if len(revealed) == 0:
        raise HTTPException(status_code=400, detail="Must reveal at least one tile")
    
    multiplier = session['multiplier']
    payout = session['bet_amount'] * multiplier
    profit = payout - session['bet_amount']
    
    db_user = await db.users.find_one({"id": user_id})
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": db_user['points_balance'] + payout}})
    
    mine_positions = session['pre_calculated_result']
    
    await db.game_sessions.update_one(
        {"session_id": request_data.session_id},
        {"$set": {"status": "cashed_out", "payout": payout, "profit": profit, "completed_at": datetime.now(timezone.utc).isoformat()}}
    )
    
    history_doc = {
        "user_id": user_id,
        "kick_username": session.get("kick_username", "Unknown"),
        "game_type": "mines",
        "bet_amount": session['bet_amount'],
        "multiplier": multiplier,
        "payout": payout,
        "profit": profit,
        "server_seed": session['server_seed'],
        "server_seed_hashed": session['server_seed_hashed'],
        "client_seed": session['client_seed'],
        "nonce": session['nonce'],
        "game_data": {"num_mines": session['game_state']['num_mines'], "mine_positions": mine_positions, "revealed_tiles": revealed, "cashed_out": True},
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    await db.game_history.insert_one(history_doc)
    
    updated_user = await db.users.find_one({"id": user_id})
    
    return {
        "success": True,
        "multiplier": multiplier,
        "payout": payout,
        "profit": profit,
        "new_balance": updated_user['points_balance'],
        "mine_positions": mine_positions,
        "server_seed": session['server_seed']
    }

# ============================================
# BLACKJACK GAME ENDPOINTS
# ============================================

@api_router.post("/games/blackjack/start")
async def start_blackjack(request_data: BlackjackStartRequest, request: Request):
    """Start a new blackjack hand"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    db_user = await db.users.find_one({"id": user_id})
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found")
    if db_user.get('can_play_games') == False:
        raise HTTPException(status_code=403, detail="You are banned from playing games")
    if db_user.get('points_balance', 0) < request_data.bet_amount:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    active_game = await db.game_sessions.find_one({"user_id": user_id, "game_type": "blackjack", "status": "in_progress"})
    if active_game:
        raise HTTPException(status_code=400, detail="You have an active blackjack hand")
    
    seeds = await get_or_create_seeds(user_id)
    
    deck = calculate_blackjack_deck(seeds['server_seed'], seeds['client_seed'], seeds['nonce'])
    
    player_hand = [deck[0], deck[2]]
    dealer_hand = [deck[1], deck[3]]
    deck_position = 4
    
    player_value = calculate_hand_value(player_hand)
    dealer_value = calculate_hand_value(dealer_hand)
    
    player_blackjack = player_value == 21 and len(player_hand) == 2
    dealer_blackjack = dealer_value == 21 and len(dealer_hand) == 2
    
    new_balance = db_user['points_balance'] - request_data.bet_amount
    await db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_balance}})
    
    session_id = str(uuid.uuid4())
    session_doc = {
        "session_id": session_id,
        "user_id": user_id,
        "kick_username": db_user.get("kick_username", "Unknown"),
        "game_type": "blackjack",
        "bet_amount": request_data.bet_amount,
        "server_seed": seeds['server_seed'],
        "server_seed_hashed": seeds['server_seed_hashed'],
        "client_seed": seeds['client_seed'],
        "nonce": seeds['nonce'],
        "pre_calculated_result": deck,
        "game_state": {"player_hand": player_hand, "dealer_hand": dealer_hand, "deck_position": deck_position, "player_value": player_value, "dealer_value": dealer_value, "doubled": False},
        "status": "in_progress",
        "multiplier": 0,
        "payout": 0,
        "profit": 0,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None
    }
    
    if player_blackjack or dealer_blackjack:
        if player_blackjack and dealer_blackjack:
            payout = request_data.bet_amount
            multiplier = 1.0
            result = "push"
        elif player_blackjack:
            payout = request_data.bet_amount * 2.5
            multiplier = 2.5
            result = "blackjack"
        else:
            payout = 0
            multiplier = 0
            result = "dealer_blackjack"
        
        profit = payout - request_data.bet_amount
        await db.users.update_one({"id": user_id}, {"$inc": {"points_balance": payout}})
        
        session_doc["status"] = "completed"
        session_doc["multiplier"] = multiplier
        session_doc["payout"] = payout
        session_doc["profit"] = profit
        session_doc["completed_at"] = datetime.now(timezone.utc).isoformat()
        
        await db.game_sessions.insert_one(session_doc)
        await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
        
        history_doc = {
            "user_id": user_id,
            "kick_username": db_user.get("kick_username", "Unknown"),
            "game_type": "blackjack",
            "bet_amount": request_data.bet_amount,
            "multiplier": multiplier,
            "payout": payout,
            "profit": profit,
            "server_seed": seeds['server_seed'],
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce'],
            "game_data": {"result": result, "player_hand": player_hand, "dealer_hand": dealer_hand, "player_value": player_value, "dealer_value": dealer_value},
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.game_history.insert_one(history_doc)
        
        updated_user = await db.users.find_one({"id": user_id})
        
        return {
            "success": True,
            "session_id": session_id,
            "game_over": True,
            "result": result,
            "player_hand": player_hand,
            "player_value": player_value,
            "dealer_hand": dealer_hand,
            "dealer_value": dealer_value,
            "multiplier": multiplier,
            "payout": payout,
            "profit": profit,
            "new_balance": updated_user['points_balance'],
            "server_seed": seeds['server_seed']
        }
    
    await db.game_sessions.insert_one(session_doc)
    await db.user_seeds.update_one({"user_id": user_id}, {"$inc": {"nonce": 1}})
    
    return {
        "success": True,
        "session_id": session_id,
        "game_over": False,
        "player_hand": player_hand,
        "player_value": player_value,
        "dealer_hand": [dealer_hand[0]],
        "dealer_visible_value": calculate_hand_value([dealer_hand[0]]),
        "new_balance": new_balance,
        "can_double": new_balance >= request_data.bet_amount,
        "fairness": {
            "server_seed_hashed": seeds['server_seed_hashed'],
            "client_seed": seeds['client_seed'],
            "nonce": seeds['nonce']
        }
    }

@api_router.post("/games/blackjack/action")
async def blackjack_action(request_data: BlackjackActionRequest, request: Request):
    """Take action in blackjack (hit, stand, double)"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    session = await db.game_sessions.find_one({"session_id": request_data.session_id, "user_id": user_id, "status": "in_progress"})
    if not session:
        raise HTTPException(status_code=400, detail="No active blackjack hand")
    
    deck = session['pre_calculated_result']
    state = session['game_state']
    player_hand = state['player_hand']
    dealer_hand = state['dealer_hand']
    deck_pos = state['deck_position']
    bet_amount = session['bet_amount']
    action = request_data.action.lower()
    
    db_user = await db.users.find_one({"id": user_id})
    
    if action == "hit":
        player_hand.append(deck[deck_pos])
        deck_pos += 1
        player_value = calculate_hand_value(player_hand)
        
        if player_value > 21:
            await db.game_sessions.update_one(
                {"session_id": request_data.session_id},
                {"$set": {"status": "completed", "game_state.player_hand": player_hand, "game_state.deck_position": deck_pos, "game_state.player_value": player_value, "multiplier": 0, "payout": 0, "profit": -bet_amount, "completed_at": datetime.now(timezone.utc).isoformat()}}
            )
            
            history_doc = {
                "user_id": user_id,
                "kick_username": session.get("kick_username", "Unknown"),
                "game_type": "blackjack",
                "bet_amount": bet_amount,
                "multiplier": 0,
                "payout": 0,
                "profit": -bet_amount,
                "server_seed": session['server_seed'],
                "server_seed_hashed": session['server_seed_hashed'],
                "client_seed": session['client_seed'],
                "nonce": session['nonce'],
                "game_data": {"result": "bust", "player_hand": player_hand, "dealer_hand": dealer_hand, "player_value": player_value, "dealer_value": calculate_hand_value(dealer_hand)},
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await db.game_history.insert_one(history_doc)
            
            return {"success": True, "game_over": True, "result": "bust", "player_hand": player_hand, "player_value": player_value, "dealer_hand": dealer_hand, "dealer_value": calculate_hand_value(dealer_hand), "payout": 0, "profit": -bet_amount, "server_seed": session['server_seed']}
        
        await db.game_sessions.update_one({"session_id": request_data.session_id}, {"$set": {"game_state.player_hand": player_hand, "game_state.deck_position": deck_pos, "game_state.player_value": player_value}})
        return {"success": True, "game_over": False, "player_hand": player_hand, "player_value": player_value, "can_double": False}
    
    elif action == "double":
        if state['doubled'] or len(player_hand) > 2:
            raise HTTPException(status_code=400, detail="Cannot double")
        
        if db_user['points_balance'] < bet_amount:
            raise HTTPException(status_code=400, detail="Insufficient balance to double")
        
        await db.users.update_one({"id": user_id}, {"$inc": {"points_balance": -bet_amount}})
        
        player_hand.append(deck[deck_pos])
        deck_pos += 1
        player_value = calculate_hand_value(player_hand)
        bet_amount *= 2
        
        await db.game_sessions.update_one({"session_id": request_data.session_id}, {"$set": {"game_state.player_hand": player_hand, "game_state.deck_position": deck_pos, "game_state.player_value": player_value, "game_state.doubled": True, "bet_amount": bet_amount}})
        
        if player_value > 21:
            await db.game_sessions.update_one({"session_id": request_data.session_id}, {"$set": {"status": "completed", "multiplier": 0, "payout": 0, "profit": -bet_amount, "completed_at": datetime.now(timezone.utc).isoformat()}})
            
            history_doc = {
                "user_id": user_id,
                "kick_username": session.get("kick_username", "Unknown"),
                "game_type": "blackjack",
                "bet_amount": bet_amount,
                "multiplier": 0,
                "payout": 0,
                "profit": -bet_amount,
                "server_seed": session['server_seed'],
                "server_seed_hashed": session['server_seed_hashed'],
                "client_seed": session['client_seed'],
                "nonce": session['nonce'],
                "game_data": {"result": "bust", "player_hand": player_hand, "dealer_hand": dealer_hand, "player_value": player_value, "dealer_value": calculate_hand_value(dealer_hand), "doubled": True},
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            await db.game_history.insert_one(history_doc)
            
            return {"success": True, "game_over": True, "result": "bust", "player_hand": player_hand, "player_value": player_value, "dealer_hand": dealer_hand, "dealer_value": calculate_hand_value(dealer_hand), "payout": 0, "profit": -bet_amount, "server_seed": session['server_seed']}
        
        action = "stand"
    
    if action == "stand":
        player_value = calculate_hand_value(player_hand)
        dealer_value = calculate_hand_value(dealer_hand)
        
        while dealer_value < 17:
            dealer_hand.append(deck[deck_pos])
            deck_pos += 1
            dealer_value = calculate_hand_value(dealer_hand)
        
        if dealer_value > 21:
            result = "dealer_bust"
            multiplier = 2.0
        elif dealer_value > player_value:
            result = "dealer_wins"
            multiplier = 0
        elif player_value > dealer_value:
            result = "player_wins"
            multiplier = 2.0
        else:
            result = "push"
            multiplier = 1.0
        
        payout = bet_amount * multiplier
        profit = payout - bet_amount
        
        if payout > 0:
            await db.users.update_one({"id": user_id}, {"$inc": {"points_balance": payout}})
        
        await db.game_sessions.update_one(
            {"session_id": request_data.session_id},
            {"$set": {"status": "completed", "game_state.dealer_hand": dealer_hand, "game_state.dealer_value": dealer_value, "game_state.deck_position": deck_pos, "multiplier": multiplier, "payout": payout, "profit": profit, "completed_at": datetime.now(timezone.utc).isoformat()}}
        )
        
        history_doc = {
            "user_id": user_id,
            "kick_username": session.get("kick_username", "Unknown"),
            "game_type": "blackjack",
            "bet_amount": bet_amount,
            "multiplier": multiplier,
            "payout": payout,
            "profit": profit,
            "server_seed": session['server_seed'],
            "server_seed_hashed": session['server_seed_hashed'],
            "client_seed": session['client_seed'],
            "nonce": session['nonce'],
            "game_data": {"result": result, "player_hand": player_hand, "dealer_hand": dealer_hand, "player_value": player_value, "dealer_value": dealer_value},
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        await db.game_history.insert_one(history_doc)
        
        updated_user = await db.users.find_one({"id": user_id})
        
        return {
            "success": True,
            "game_over": True,
            "result": result,
            "player_hand": player_hand,
            "player_value": player_value,
            "dealer_hand": dealer_hand,
            "dealer_value": dealer_value,
            "multiplier": multiplier,
            "payout": payout,
            "profit": profit,
            "new_balance": updated_user['points_balance'],
            "server_seed": session['server_seed']
        }
    
    raise HTTPException(status_code=400, detail="Invalid action")

# ============================================
# GAME HISTORY & VERIFICATION ENDPOINTS
# ============================================

@api_router.get("/games/history")
async def get_game_history(request: Request, game_type: Optional[str] = None, limit: int = 50):
    """Get user's game history"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        return {"success": True, "history": []}
    
    query = {"user_id": user_id}
    if game_type:
        query["game_type"] = game_type
    
    history = await db.game_history.find(query, {"_id": 0}).sort("created_at", -1).limit(limit).to_list(length=limit)
    
    return {"success": True, "history": history}

@api_router.post("/games/verify")
async def verify_game(request_data: VerifyGameRequest):
    """Verify a game result was fair"""
    result = verify_game_result(
        request_data.server_seed,
        request_data.server_seed_hashed,
        request_data.client_seed,
        request_data.nonce,
        request_data.game_type.value,
        request_data.game_params or {}
    )
    return {"success": True, "verification": result}

@api_router.get("/games/active")
async def get_active_games(request: Request):
    """Get user's active game sessions"""
    user = await get_current_user(request)
    user_id = str(user['id'])
    
    if db is None:
        return {"success": True, "active_games": []}
    
    active_sessions = await db.game_sessions.find({"user_id": user_id, "status": "in_progress"}, {"_id": 0, "pre_calculated_result": 0, "server_seed": 0}).to_list(length=10)
    
    return {"success": True, "active_games": active_sessions}

@api_router.get("/games/active/{game_type}")
async def get_active_game_by_type(game_type: str, request: Request):
    """
    Get user's active game session for a specific game type.
    Used to restore game state when user refreshes the page.
    """
    try:
        user = await get_current_user(request)
    except HTTPException:
        return {"success": False, "active_game": None, "error": "Not authenticated"}
    
    if db is None:
        return {"success": False, "active_game": None, "error": "Database not available"}
    
    user_id = str(user['id'])
    
    # Find active game for this user and game type
    active_game = await db.game_sessions.find_one({
        "user_id": user_id,
        "game_type": game_type,
        "status": "in_progress"
    })
    
    if not active_game:
        return {"success": True, "active_game": None}
    
    # Prepare response - hide sensitive data
    game_data = {
        "session_id": active_game["session_id"],
        "game_type": active_game["game_type"],
        "bet_amount": active_game["bet_amount"],
        "multiplier": active_game.get("multiplier", 1.0),
        "created_at": active_game.get("created_at"),
        "game_state": active_game.get("game_state", {}),
        "fairness": {
            "server_seed_hashed": active_game.get("server_seed_hashed"),
            "client_seed": active_game.get("client_seed"),
            "nonce": active_game.get("nonce")
        }
    }
    
    # For blackjack, include visible cards but hide dealer's second card
    if game_type == "blackjack":
        state = active_game.get("game_state", {})
        game_data["player_hand"] = state.get("player_hand", [])
        game_data["player_value"] = state.get("player_value", 0)
        dealer_hand = state.get("dealer_hand", [])
        if len(dealer_hand) > 0:
            game_data["dealer_hand"] = [dealer_hand[0]]
            # Calculate visible dealer value
            card = dealer_hand[0]
            card_val = card.get('value', card.get('rank', ''))
            if card_val in ['J', 'Q', 'K']:
                game_data["dealer_visible_value"] = 10
            elif card_val == 'A':
                game_data["dealer_visible_value"] = 11
            else:
                try:
                    game_data["dealer_visible_value"] = int(card_val)
                except:
                    game_data["dealer_visible_value"] = 10
        game_data["doubled"] = state.get("doubled", False)
    
    # For mines, include revealed tiles
    if game_type == "mines":
        state = active_game.get("game_state", {})
        game_data["revealed_tiles"] = state.get("revealed_tiles", [])
        game_data["num_mines"] = state.get("num_mines", 1)
        game_data["gems_found"] = len(state.get("revealed_tiles", []))
    
    return {"success": True, "active_game": game_data}

# ============================================
# ADMIN GAME ENDPOINTS
# ============================================

@api_router.get("/admin/active-games")
async def admin_get_active_games(
    game_type: Optional[str] = None,
    username: str = Depends(verify_admin)
):
    """Get all active game sessions across all users."""
    if db is None:
        return {"success": False, "active_games": [], "error": "Database not available"}
    
    query = {"status": "in_progress"}
    if game_type and game_type != "all":
        query["game_type"] = game_type
    
    active_games = await db.game_sessions.find(query).sort("created_at", -1).to_list(100)
    
    enriched_games = []
    for game in active_games:
        user = await db.users.find_one({"id": game["user_id"]}, {"_id": 0, "kick_username": 1})
        
        enriched_games.append({
            "session_id": game["session_id"],
            "user_id": game["user_id"],
            "kick_username": user.get("kick_username", "Unknown") if user else "Unknown",
            "game_type": game["game_type"],
            "bet_amount": game["bet_amount"],
            "multiplier": game.get("multiplier", 1.0),
            "potential_payout": game["bet_amount"] * game.get("multiplier", 1.0),
            "created_at": game.get("created_at"),
            "game_state": {
                "revealed_tiles": game.get("game_state", {}).get("revealed_tiles", []) if game["game_type"] == "mines" else None,
                "num_mines": game.get("game_state", {}).get("num_mines") if game["game_type"] == "mines" else None,
                "player_hand": game.get("game_state", {}).get("player_hand") if game["game_type"] == "blackjack" else None,
                "player_value": game.get("game_state", {}).get("player_value") if game["game_type"] == "blackjack" else None,
            }
        })
    
    counts = {
        "total": len(enriched_games),
        "mines": len([g for g in enriched_games if g["game_type"] == "mines"]),
        "blackjack": len([g for g in enriched_games if g["game_type"] == "blackjack"])
    }
    
    return {"success": True, "active_games": enriched_games, "counts": counts}


@api_router.post("/admin/active-games/{session_id}/end")
async def admin_end_active_game(session_id: str, username: str = Depends(verify_admin)):
    """Admin force-ends an active game. Returns bet amount to player."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    game = await db.game_sessions.find_one({"session_id": session_id, "status": "in_progress"})
    if not game:
        raise HTTPException(status_code=404, detail="Active game not found")
    
    user_id = game["user_id"]
    bet_amount = game["bet_amount"]
    
    # Refund bet
    await db.users.update_one({"id": user_id}, {"$inc": {"points_balance": bet_amount}})
    
    # Mark as cancelled
    await db.game_sessions.update_one(
        {"session_id": session_id},
        {"$set": {
            "status": "cancelled",
            "cancelled_by": "admin",
            "cancelled_reason": "Admin force-ended game",
            "payout": bet_amount,
            "profit": 0,
            "completed_at": datetime.now(timezone.utc).isoformat()
        }}
    )
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1, "points_balance": 1})
    
    return {
        "success": True,
        "message": f"Game ended. Refunded {bet_amount} points",
        "refunded_amount": bet_amount,
        "user_new_balance": user.get("points_balance", 0) if user else 0
    }


@api_router.post("/admin/active-games/end-all")
async def admin_end_all_active_games(game_type: Optional[str] = None, username: str = Depends(verify_admin)):
    """Admin force-ends all active games. Returns bets to all players."""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    query = {"status": "in_progress"}
    if game_type and game_type != "all":
        query["game_type"] = game_type
    
    active_games = await db.game_sessions.find(query).to_list(1000)
    
    if not active_games:
        return {"success": True, "message": "No active games", "ended_count": 0}
    
    ended_count = 0
    total_refunded = 0
    
    for game in active_games:
        await db.users.update_one({"id": game["user_id"]}, {"$inc": {"points_balance": game["bet_amount"]}})
        await db.game_sessions.update_one(
            {"session_id": game["session_id"]},
            {"$set": {
                "status": "cancelled",
                "cancelled_by": "admin_bulk",
                "cancelled_reason": "Admin bulk-ended all active games",
                "payout": game["bet_amount"],
                "profit": 0,
                "completed_at": datetime.now(timezone.utc).isoformat()
            }}
        )
        ended_count += 1
        total_refunded += game["bet_amount"]
    
    return {"success": True, "ended_count": ended_count, "total_refunded": total_refunded}

@api_router.get("/admin/game-history")
async def admin_get_game_history(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    game_type: Optional[str] = None,
    search: Optional[str] = None,
    username: str = Depends(verify_admin)
):
    """Get global game history with pagination and filtering"""
    if db is None:
        return {"success": True, "history": [], "page": page, "limit": limit}
    
    skip = (page - 1) * limit
    query = {}
    
    if game_type and game_type != 'all':
        query['game_type'] = game_type
    
    if search:
        query['kick_username'] = {"$regex": search, "$options": "i"}
    
    history = await db.game_history.find(query, {"_id": 0}).sort("created_at", -1).skip(skip).limit(limit).to_list(length=limit)
    total = await db.game_history.count_documents(query)
    
    return {"success": True, "history": history, "page": page, "limit": limit, "total": total}

@api_router.get("/admin/game-stats")
async def admin_get_game_stats(username: str = Depends(verify_admin)):
    """Get global game statistics"""
    if db is None:
        return {"success": True, "total_bets": 0, "total_wagered": 0, "total_payouts": 0, "by_game": {}, "top_players": [], "biggest_wins": []}
    
    overall_pipeline = [{"$group": {"_id": None, "total_bets": {"$sum": 1}, "total_wagered": {"$sum": "$bet_amount"}, "total_payouts": {"$sum": "$payout"}}}]
    overall_result = await db.game_history.aggregate(overall_pipeline).to_list(length=1)
    overall = overall_result[0] if overall_result else {"total_bets": 0, "total_wagered": 0, "total_payouts": 0}
    
    by_game_pipeline = [{"$group": {"_id": "$game_type", "bets": {"$sum": 1}, "wagered": {"$sum": "$bet_amount"}, "payouts": {"$sum": "$payout"}}}]
    by_game_result = await db.game_history.aggregate(by_game_pipeline).to_list(length=10)
    by_game = {g["_id"]: {"bets": g["bets"], "wagered": g["wagered"], "payouts": g["payouts"]} for g in by_game_result if g["_id"]}
    
    top_players_pipeline = [
        {"$group": {"_id": "$user_id", "kick_username": {"$first": "$kick_username"}, "total_bets": {"$sum": 1}, "total_wagered": {"$sum": "$bet_amount"}, "total_won": {"$sum": "$payout"}, "wins": {"$sum": {"$cond": [{"$gt": ["$profit", 0]}, 1, 0]}}}},
        {"$addFields": {"net_profit": {"$subtract": ["$total_won", "$total_wagered"]}, "win_rate": {"$multiply": [{"$divide": ["$wins", "$total_bets"]}, 100]}}},
        {"$sort": {"net_profit": -1}},
        {"$limit": 10}
    ]
    top_players = await db.game_history.aggregate(top_players_pipeline).to_list(length=10)
    
    biggest_wins = await db.game_history.find({"profit": {"$gt": 0}}, {"_id": 0}).sort("payout", -1).limit(10).to_list(length=10)
    
    return {
        "success": True,
        "total_bets": overall.get("total_bets", 0),
        "total_wagered": overall.get("total_wagered", 0),
        "total_payouts": overall.get("total_payouts", 0),
        "house_profit": overall.get("total_wagered", 0) - overall.get("total_payouts", 0),
        "by_game": by_game,
        "top_players": top_players,
        "biggest_wins": biggest_wins
    }

@api_router.get("/admin/users/{user_id}/game-stats")
async def admin_get_user_game_stats(user_id: str, username: str = Depends(verify_admin)):
    """Get game statistics for a specific user (P&L, breakdown, history)"""
    if db is None:
        return {"success": True, "total_bets": 0, "total_wagered": 0, "total_won": 0, "by_game": {}, "recent_games": []}
    
    overall_pipeline = [{"$match": {"user_id": user_id}}, {"$group": {"_id": None, "total_bets": {"$sum": 1}, "total_wagered": {"$sum": "$bet_amount"}, "total_won": {"$sum": "$payout"}}}]
    overall_result = await db.game_history.aggregate(overall_pipeline).to_list(length=1)
    overall = overall_result[0] if overall_result else {"total_bets": 0, "total_wagered": 0, "total_won": 0}
    
    by_game_pipeline = [{"$match": {"user_id": user_id}}, {"$group": {"_id": "$game_type", "bets": {"$sum": 1}, "wagered": {"$sum": "$bet_amount"}, "won": {"$sum": "$payout"}}}]
    by_game_result = await db.game_history.aggregate(by_game_pipeline).to_list(length=10)
    by_game = {g["_id"]: {"bets": g["bets"], "wagered": g["wagered"], "won": g["won"]} for g in by_game_result if g["_id"]}
    
    recent_games = await db.game_history.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).limit(50).to_list(length=50)
    
    return {
        "success": True,
        "total_bets": overall.get("total_bets", 0),
        "total_wagered": overall.get("total_wagered", 0),
        "total_won": overall.get("total_won", 0),
        "net_profit": overall.get("total_won", 0) - overall.get("total_wagered", 0),
        "by_game": by_game,
        "recent_games": recent_games
    }



# ==================== BOTRIX LEGACY ENDPOINTS ====================

@api_router.get("/bot/points")
async def botrix_points(user: str):
    response = await handle_points_command(user)
    return Response(content=response, media_type="text/plain")

@api_router.get("/bot/leaderboard")
async def botrix_leaderboard():
    response = await handle_leaderboard_command()
    return Response(content=response, media_type="text/plain")

@api_router.get("/bot/commands")
async def botrix_commands():
    return Response(content="Commands: !points | !leaderboard | !tip @user amount", media_type="text/plain")


# ==================== PUBLIC USER PROFILE ENDPOINTS ====================

@api_router.get("/users/search")
async def search_users(q: str = Query(..., min_length=1), limit: int = 20):
    """Search users by username"""
    if db is None:
        return {"success": True, "users": []}
    
    query = {"kick_username": {"$regex": q, "$options": "i"}}
    users = await db.users.find(
        query, 
        {"_id": 0, "id": 1, "kick_username": 1, "avatar": 1, "points_balance": 1, "registered_at": 1}
    ).limit(limit).to_list(length=limit)
    
    return {"success": True, "users": users, "count": len(users)}

@api_router.get("/users/{username}/profile")
async def get_user_profile(username: str):
    """Get public user profile by username"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
        {"_id": 0, "access_token": 0, "refresh_token": 0, "ip_addresses": 0, "fingerprints": 0}
    )
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get game stats
    user_id = user.get("id")
    stats_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": None,
            "total_bets": {"$sum": 1},
            "total_wagered": {"$sum": "$bet_amount"},
            "total_won": {"$sum": "$payout"}
        }}
    ]
    stats_result = await db.game_history.aggregate(stats_pipeline).to_list(length=1)
    stats = stats_result[0] if stats_result else {"total_bets": 0, "total_wagered": 0, "total_won": 0}
    
    profile = {
        "id": user.get("id"),
        "kick_username": user.get("kick_username"),
        "avatar": user.get("avatar"),
        "points_balance": user.get("points_balance", 0),
        "total_earned": user.get("total_earned", 0),
        "total_spent": user.get("total_spent", 0),
        "registered_at": user.get("registered_at"),
        "game_stats": {
            "total_bets": stats.get("total_bets", 0),
            "total_wagered": round(stats.get("total_wagered", 0), 2),
            "total_won": round(stats.get("total_won", 0), 2),
            "net_profit": round(stats.get("total_won", 0) - stats.get("total_wagered", 0), 2)
        }
    }
    
    return {"success": True, "profile": profile}

@api_router.get("/users/{username}/stats")
async def get_user_stats(username: str):
    """Get user's game statistics breakdown"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
        {"_id": 0, "id": 1}
    )
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user.get("id")
    
    # Overall stats
    overall_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": None,
            "total_bets": {"$sum": 1},
            "total_wagered": {"$sum": "$bet_amount"},
            "total_won": {"$sum": "$payout"},
            "wins": {"$sum": {"$cond": [{"$gt": ["$payout", "$bet_amount"]}, 1, 0]}},
            "losses": {"$sum": {"$cond": [{"$lte": ["$payout", "$bet_amount"]}, 1, 0]}}
        }}
    ]
    overall_result = await db.game_history.aggregate(overall_pipeline).to_list(length=1)
    overall = overall_result[0] if overall_result else {"total_bets": 0, "total_wagered": 0, "total_won": 0, "wins": 0, "losses": 0}
    
    # Stats by game type
    by_game_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": "$game_type",
            "bets": {"$sum": 1},
            "wagered": {"$sum": "$bet_amount"},
            "won": {"$sum": "$payout"},
            "wins": {"$sum": {"$cond": [{"$gt": ["$payout", "$bet_amount"]}, 1, 0]}},
            "losses": {"$sum": {"$cond": [{"$lte": ["$payout", "$bet_amount"]}, 1, 0]}}
        }}
    ]
    by_game_result = await db.game_history.aggregate(by_game_pipeline).to_list(length=10)
    by_game = {}
    for g in by_game_result:
        if g["_id"]:
            by_game[g["_id"]] = {
                "bets": g["bets"],
                "wagered": round(g["wagered"], 2),
                "won": round(g["won"], 2),
                "profit": round(g["won"] - g["wagered"], 2),
                "wins": g["wins"],
                "losses": g["losses"]
            }
    
    return {
        "success": True,
        "stats": {
            "total_bets": overall.get("total_bets", 0),
            "total_wagered": round(overall.get("total_wagered", 0), 2),
            "total_won": round(overall.get("total_won", 0), 2),
            "net_profit": round(overall.get("total_won", 0) - overall.get("total_wagered", 0), 2),
            "wins": overall.get("wins", 0),
            "losses": overall.get("losses", 0),
            "win_rate": round((overall.get("wins", 0) / overall.get("total_bets", 1)) * 100, 2) if overall.get("total_bets", 0) > 0 else 0,
            "by_game": by_game
        }
    }

@api_router.get("/users/{username}/games/history")
async def get_user_game_history(username: str, game_type: Optional[str] = None, limit: int = 50, offset: int = 0):
    """Get user's game history (public view)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
        {"_id": 0, "id": 1}
    )
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user.get("id")
    query = {"user_id": user_id}
    if game_type:
        query["game_type"] = game_type
    
    total = await db.game_history.count_documents(query)
    history = await db.game_history.find(
        query, 
        {"_id": 0, "server_seed": 0}  # Hide server seed for security
    ).sort("created_at", -1).skip(offset).limit(limit).to_list(length=limit)
    
    return {
        "success": True,
        "history": history,
        "total": total,
        "limit": limit,
        "offset": offset
    }

@api_router.get("/users/{username}/games/active")
async def get_user_active_games(username: str):
    """Get user's ongoing games (public view)"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one(
        {"kick_username": {"$regex": f"^{username}$", "$options": "i"}},
        {"_id": 0, "id": 1}
    )
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_id = user.get("id")
    
    active_games = await db.game_sessions.find(
        {"user_id": user_id, "status": "in_progress"},
        {"_id": 0, "server_seed": 0, "pre_calculated_result": 0}  # Hide sensitive data
    ).to_list(length=10)
    
    # Process games to hide sensitive info but show relevant state
    processed_games = []
    for game in active_games:
        processed = {
            "session_id": game.get("session_id"),
            "game_type": game.get("game_type"),
            "bet_amount": game.get("bet_amount"),
            "multiplier": game.get("multiplier", 1.0),
            "created_at": game.get("created_at"),
            "server_seed_hashed": game.get("server_seed_hashed")
        }
        
        # Add game-specific visible state
        state = game.get("game_state", {})
        if game.get("game_type") == "mines":
            processed["gems_found"] = len(state.get("revealed_tiles", []))
            processed["num_mines"] = state.get("num_mines", 1)
        elif game.get("game_type") == "blackjack":
            processed["player_value"] = state.get("player_value", 0)
            dealer_hand = state.get("dealer_hand", [])
            if dealer_hand:
                processed["dealer_showing"] = dealer_hand[0] if len(dealer_hand) > 0 else None
        
        processed_games.append(processed)
    
    return {"success": True, "active_games": processed_games}


# ==================== ADMIN USER FULL DETAILS ENDPOINTS ====================

@api_router.get("/admin/users/{user_id}/full-details")
async def admin_get_user_full_details(user_id: str, username: str = Depends(verify_admin)):
    """Get complete user details including PnL, wagered, spent, redemptions, games"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get user info
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get game stats
    stats_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": None,
            "total_bets": {"$sum": 1},
            "total_wagered": {"$sum": "$bet_amount"},
            "total_won": {"$sum": "$payout"},
            "wins": {"$sum": {"$cond": [{"$gt": ["$payout", "$bet_amount"]}, 1, 0]}},
            "losses": {"$sum": {"$cond": [{"$lte": ["$payout", "$bet_amount"]}, 1, 0]}}
        }}
    ]
    stats_result = await db.game_history.aggregate(stats_pipeline).to_list(length=1)
    stats = stats_result[0] if stats_result else {"total_bets": 0, "total_wagered": 0, "total_won": 0, "wins": 0, "losses": 0}
    
    # Stats by game type
    by_game_pipeline = [
        {"$match": {"user_id": user_id}},
        {"$group": {
            "_id": "$game_type",
            "bets": {"$sum": 1},
            "wagered": {"$sum": "$bet_amount"},
            "won": {"$sum": "$payout"}
        }}
    ]
    by_game_result = await db.game_history.aggregate(by_game_pipeline).to_list(length=10)
    by_game = {g["_id"]: {"bets": g["bets"], "wagered": round(g["wagered"], 2), "won": round(g["won"], 2), "profit": round(g["won"] - g["wagered"], 2)} for g in by_game_result if g["_id"]}
    
    # Get redemptions
    redemptions = await db.redemptions.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    # Get recent games
    recent_games = await db.game_history.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).limit(50).to_list(length=50)
    
    # Get active games
    active_games = await db.game_sessions.find({"user_id": user_id, "status": "in_progress"}, {"_id": 0, "server_seed": 0}).to_list(length=10)
    
    # Get point adjustments history
    point_adjustments = await db.point_adjustments.find({"user_id": user_id}, {"_id": 0}).sort("timestamp", -1).limit(20).to_list(length=20)
    
    return {
        "success": True,
        "user": user,
        "game_stats": {
            "total_bets": stats.get("total_bets", 0),
            "total_wagered": round(stats.get("total_wagered", 0), 2),
            "total_won": round(stats.get("total_won", 0), 2),
            "net_profit": round(stats.get("total_won", 0) - stats.get("total_wagered", 0), 2),
            "wins": stats.get("wins", 0),
            "losses": stats.get("losses", 0),
            "win_rate": round((stats.get("wins", 0) / stats.get("total_bets", 1)) * 100, 2) if stats.get("total_bets", 0) > 0 else 0,
            "by_game": by_game
        },
        "redemptions": redemptions,
        "redemptions_count": len(redemptions),
        "recent_games": recent_games,
        "active_games": active_games,
        "point_adjustments": point_adjustments
    }

@api_router.get("/admin/users/{user_id}/redemptions")
async def admin_get_user_redemptions(user_id: str, username: str = Depends(verify_admin)):
    """Get all redemptions for a specific user"""
    if db is None:
        return {"success": True, "redemptions": []}
    
    redemptions = await db.redemptions.find({"user_id": user_id}, {"_id": 0}).sort("created_at", -1).to_list(100)
    
    # Get counts by status
    pending = sum(1 for r in redemptions if r.get("status") == "pending")
    approved = sum(1 for r in redemptions if r.get("status") == "approved")
    rejected = sum(1 for r in redemptions if r.get("status") == "rejected")
    
    total_spent = sum(r.get("points_spent", 0) for r in redemptions)
    
    return {
        "success": True,
        "redemptions": redemptions,
        "counts": {"pending": pending, "approved": approved, "rejected": rejected, "total": len(redemptions)},
        "total_points_spent": total_spent
    }


# ==================== ADMIN GAME BAN ENDPOINTS ====================

@api_router.post("/admin/users/{user_id}/ban-games")
async def admin_ban_user_from_games(user_id: str, request: Request, username: str = Depends(verify_admin)):
    """Ban a user from playing games"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1})
    
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {
            "can_play_games": False,
            "game_banned_at": datetime.now(timezone.utc).isoformat(),
            "game_banned_by": username
        }}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    # End any active game sessions
    cancelled = await db.game_sessions.update_many(
        {"user_id": user_id, "status": "in_progress"},
        {"$set": {"status": "cancelled", "cancelled_reason": "User banned from games"}}
    )
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="ban_user_games",
        admin_username=username,
        target_type="user",
        target_id=user_id,
        target_name=user.get("kick_username") if user else None,
        details={"action": "game_ban", "cancelled_games": cancelled.modified_count},
        ip_address=client_ip
    )
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User banned from playing games", "user": updated}

@api_router.post("/admin/users/{user_id}/unban-games")
async def admin_unban_user_from_games(user_id: str, request: Request, username: str = Depends(verify_admin)):
    """Unban a user from playing games"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1})
    
    result = await db.users.update_one(
        {"id": user_id},
        {"$set": {"can_play_games": True}, "$unset": {"game_banned_at": "", "game_banned_by": ""}}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    client_ip = request.client.host if request.client else "unknown"
    await create_audit_log(
        action="unban_user_games",
        admin_username=username,
        target_type="user",
        target_id=user_id,
        target_name=user.get("kick_username") if user else None,
        details={"action": "game_unban"},
        ip_address=client_ip
    )
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User can now play games", "user": updated}


# ==================== ADMIN SPECIFIC GAME VIEW ENDPOINT ====================

@api_router.get("/admin/games/{game_id}")
async def admin_get_game_details(game_id: str, username: str = Depends(verify_admin)):
    """Get full details of a specific game including exact match of what happened"""
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Try to find in game_history first (completed games)
    game = await db.game_history.find_one({"id": game_id}, {"_id": 0})
    game_source = "history"
    
    # If not found, check active sessions
    if not game:
        game = await db.game_sessions.find_one({"session_id": game_id}, {"_id": 0})
        game_source = "active"
    
    if not game:
        raise HTTPException(status_code=404, detail="Game not found")
    
    # Get user info
    user_id = game.get("user_id")
    user = await db.users.find_one({"id": user_id}, {"_id": 0, "kick_username": 1, "avatar": 1, "id": 1})
    
    # Prepare detailed response based on game type
    game_type = game.get("game_type")
    game_data = game.get("game_data", {}) or game.get("game_state", {})
    
    response = {
        "success": True,
        "game_source": game_source,
        "game": {
            "id": game.get("id") or game.get("session_id"),
            "game_type": game_type,
            "user_id": user_id,
            "user": user,
            "bet_amount": game.get("bet_amount"),
            "payout": game.get("payout", 0),
            "profit": game.get("profit", game.get("payout", 0) - game.get("bet_amount", 0)),
            "won": game.get("won", game.get("payout", 0) > game.get("bet_amount", 0)),
            "multiplier": game.get("multiplier", 1.0),
            "status": game.get("status", "completed"),
            "created_at": game.get("created_at"),
            "completed_at": game.get("completed_at"),
            "fairness": {
                "server_seed": game.get("server_seed"),
                "server_seed_hashed": game.get("server_seed_hashed"),
                "client_seed": game.get("client_seed"),
                "nonce": game.get("nonce")
            }
        },
        "game_details": {}
    }
    
    # Add game-specific details
    if game_type == "dice":
        response["game_details"] = {
            "roll_result": game_data.get("result") or game_data.get("roll"),
            "target": game_data.get("target"),
            "roll_over": game_data.get("roll_over"),
            "win_chance": game_data.get("win_chance")
        }
    elif game_type == "limbo":
        response["game_details"] = {
            "result_multiplier": game_data.get("result") or game_data.get("multiplier_result"),
            "target_multiplier": game_data.get("target") or game_data.get("target_multiplier")
        }
    elif game_type == "mines":
        response["game_details"] = {
            "num_mines": game_data.get("num_mines"),
            "mine_positions": game_data.get("mine_positions", []),
            "revealed_tiles": game_data.get("revealed_tiles", []),
            "gems_found": len(game_data.get("revealed_tiles", [])),
            "hit_mine": game_data.get("hit_mine", False),
            "cashed_out": game_data.get("cashed_out", False)
        }
    elif game_type == "blackjack":
        response["game_details"] = {
            "player_hand": game_data.get("player_hand", []),
            "dealer_hand": game_data.get("dealer_hand", []),
            "player_value": game_data.get("player_value"),
            "dealer_value": game_data.get("dealer_value"),
            "result": game_data.get("result"),
            "doubled": game_data.get("doubled", False),
            "player_blackjack": game_data.get("player_blackjack", False),
            "dealer_blackjack": game_data.get("dealer_blackjack", False)
        }
    elif game_type == "wheel":
        response["game_details"] = {
            "segments": game_data.get("segments"),
            "risk": game_data.get("risk"),
            "winning_segment": game_data.get("segment_index") or game_data.get("winning_segment"),
            "result_multiplier": game_data.get("multiplier") or game_data.get("result_multiplier")
        }
    
    return response


# ==================== ADMIN ALL GAMES ENDPOINT ====================

@api_router.get("/admin/games/all")
async def admin_get_all_games(
    status: Optional[str] = None,  # "ongoing", "ended", or None for all
    game_type: Optional[str] = None,
    user_id: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    username: str = Depends(verify_admin)
):
    """Get all games with filters (ongoing, ended, or all)"""
    if db is None:
        return {"success": True, "games": [], "total": 0}
    
    games = []
    total_ongoing = 0
    total_ended = 0
    
    # Build query for active games
    active_query = {"status": "in_progress"}
    if game_type:
        active_query["game_type"] = game_type
    if user_id:
        active_query["user_id"] = user_id
    
    # Build query for game history
    history_query = {}
    if game_type:
        history_query["game_type"] = game_type
    if user_id:
        history_query["user_id"] = user_id
    if search:
        # We'll need to search by username, so get user IDs first
        matching_users = await db.users.find(
            {"kick_username": {"$regex": search, "$options": "i"}},
            {"id": 1}
        ).to_list(100)
        user_ids = [u["id"] for u in matching_users]
        if user_ids:
            history_query["user_id"] = {"$in": user_ids}
            active_query["user_id"] = {"$in": user_ids}
    
    # Get counts
    total_ongoing = await db.game_sessions.count_documents({"status": "in_progress"})
    total_ended = await db.game_history.count_documents({})
    
    if status == "ongoing":
        # Only get active games
        active_games = await db.game_sessions.find(active_query, {"_id": 0, "server_seed": 0, "pre_calculated_result": 0}).sort("created_at", -1).skip(offset).limit(limit).to_list(length=limit)
        
        # Enrich with user info
        for game in active_games:
            user = await db.users.find_one({"id": game.get("user_id")}, {"_id": 0, "kick_username": 1, "avatar": 1})
            game["user"] = user
            game["id"] = game.get("session_id")
            game["status"] = "ongoing"
            games.append(game)
        
        total = await db.game_sessions.count_documents(active_query)
        
    elif status == "ended":
        # Only get completed games
        history = await db.game_history.find(history_query, {"_id": 0}).sort("created_at", -1).skip(offset).limit(limit).to_list(length=limit)
        
        # Enrich with user info
        for game in history:
            user = await db.users.find_one({"id": game.get("user_id")}, {"_id": 0, "kick_username": 1, "avatar": 1})
            game["user"] = user
            game["status"] = "ended"
            games.append(game)
        
        total = await db.game_history.count_documents(history_query)
        
    else:
        # Get both active and completed games, sorted by date
        # First get active games
        active_games = await db.game_sessions.find(active_query, {"_id": 0, "server_seed": 0, "pre_calculated_result": 0}).sort("created_at", -1).to_list(length=100)
        
        for game in active_games:
            user = await db.users.find_one({"id": game.get("user_id")}, {"_id": 0, "kick_username": 1, "avatar": 1})
            game["user"] = user
            game["id"] = game.get("session_id")
            game["status"] = "ongoing"
            games.append(game)
        
        # Then get completed games
        remaining = limit - len(games) if len(games) < limit else 0
        if remaining > 0 or len(games) == 0:
            skip_history = max(0, offset - len(active_games)) if offset > len(active_games) else 0
            history = await db.game_history.find(history_query, {"_id": 0}).sort("created_at", -1).skip(skip_history).limit(remaining if remaining > 0 else limit).to_list(length=remaining if remaining > 0 else limit)
            
            for game in history:
                user = await db.users.find_one({"id": game.get("user_id")}, {"_id": 0, "kick_username": 1, "avatar": 1})
                game["user"] = user
                game["status"] = "ended"
                games.append(game)
        
        # Sort all by created_at
        games.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        games = games[offset:offset+limit] if status is None else games
        
        total = await db.game_sessions.count_documents(active_query) + await db.game_history.count_documents(history_query)
    
    return {
        "success": True,
        "games": games,
        "total": total,
        "counts": {
            "ongoing": total_ongoing,
            "ended": total_ended,
            "all": total_ongoing + total_ended
        },
        "limit": limit,
        "offset": offset
    }


# Include router
app.include_router(api_router)

# Vercel serverless - export app directly (no Mangum needed)
# Vercel's @vercel/python runtime natively supports ASGI apps
