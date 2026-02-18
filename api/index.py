from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
import secrets
from datetime import datetime, timezone, timedelta
import httpx
import hashlib
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
    return {"status": "healthy", "database": "connected" if db else "not_connected"}


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
            
            if isinstance(kick_user, list) and len(kick_user) > 0:
                kick_user = kick_user[0]
            elif isinstance(kick_user, dict):
                if "data" in kick_user:
                    kick_user = kick_user["data"]
                    if isinstance(kick_user, list) and len(kick_user) > 0:
                        kick_user = kick_user[0]
                elif "user" in kick_user:
                    kick_user = kick_user["user"]
            
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
        avatar = kick_user.get("profile_pic") or kick_user.get("avatar") or ""
        
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
    
    response = RedirectResponse(url=f"{FRONTEND_URL}/index.html")
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
async def admin_login(credentials: dict):
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        return {"success": True, "message": "Login successful"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@api_router.get("/admin/settings")
async def admin_get_all_settings(username: str = Depends(verify_admin)):
    all_settings = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        all_settings[site] = await get_leaderboard_settings(site)
    return {"success": True, "settings": all_settings}

@api_router.put("/admin/settings/{site}")
async def admin_update_settings(site: str, settings: LeaderboardSettingsUpdate, username: str = Depends(verify_admin)):
    site = site.lower()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    existing = await get_leaderboard_settings(site)
    update_data = settings.model_dump(exclude_none=True)
    if update_data:
        existing.update(update_data)
        existing["site"] = site
        await db.leaderboard_settings.update_one({"site": site}, {"$set": existing}, upsert=True)
    
    return {"success": True, "message": f"Settings for {site} updated", "settings": existing}


# ==================== ADMIN CHALLENGES ====================

@api_router.get("/admin/challenges")
async def admin_get_challenges(username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "challenges": []}
    challenges = await db.challenges.find({}, {"_id": 0}).to_list(100)
    return {"success": True, "challenges": challenges}

@api_router.post("/admin/challenges")
async def admin_create_challenge(challenge: ChallengeCreate, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    challenge_dict = challenge.model_dump()
    challenge_dict["id"] = str(uuid.uuid4())
    challenge_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    
    await db.challenges.insert_one(challenge_dict)
    challenge_dict.pop("_id", None)
    
    return {"success": True, "message": "Challenge created", "challenge": challenge_dict}

@api_router.put("/admin/challenges/{challenge_id}")
async def admin_update_challenge(challenge_id: str, challenge: ChallengeUpdate, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    update_data = challenge.model_dump(exclude_none=True)
    if not update_data:
        raise HTTPException(status_code=400, detail="No data to update")
    
    result = await db.challenges.update_one({"id": challenge_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    updated = await db.challenges.find_one({"id": challenge_id}, {"_id": 0})
    return {"success": True, "message": "Challenge updated", "challenge": updated}

@api_router.delete("/admin/challenges/{challenge_id}")
async def admin_delete_challenge(challenge_id: str, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.challenges.delete_one({"id": challenge_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    return {"success": True, "message": "Challenge deleted"}


# ==================== ADMIN SHOP ====================

@api_router.get("/admin/shop/items")
async def admin_get_shop_items(username: str = Depends(verify_admin)):
    if db is None:
        return {"success": True, "items": []}
    items = await db.shop_items.find({}, {"_id": 0}).to_list(100)
    return {"success": True, "items": items}

@api_router.post("/admin/shop/items")
async def admin_create_shop_item(item: ShopItemCreate, username: str = Depends(verify_admin)):
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
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.shop_items.delete_one({"id": item_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Item not found")
    
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
async def admin_update_redemption(redemption_id: str, update: RedemptionStatusUpdate, username: str = Depends(verify_admin)):
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
    
    await db.redemptions.update_one({"id": redemption_id}, {"$set": {"status": update.status, "admin_notes": update.admin_notes, "handled_at": datetime.now(timezone.utc).isoformat()}})
    
    updated = await db.redemptions.find_one({"id": redemption_id}, {"_id": 0})
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
async def admin_update_user(user_id: str, update: AdminUserUpdate, username: str = Depends(verify_admin)):
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

@api_router.post("/admin/users/{user_id}/ban")
async def admin_ban_user(user_id: str, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.users.update_one({"id": user_id}, {"$set": {"is_banned": True, "banned_at": datetime.now(timezone.utc).isoformat()}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User banned", "user": updated}

@api_router.post("/admin/users/{user_id}/unban")
async def admin_unban_user(user_id: str, username: str = Depends(verify_admin)):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    
    result = await db.users.update_one({"id": user_id}, {"$set": {"is_banned": False}})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    updated = await db.users.find_one({"id": user_id}, {"_id": 0, "access_token": 0, "refresh_token": 0})
    return {"success": True, "message": "User unbanned", "user": updated}

@api_router.post("/admin/users/{user_id}/adjust-points")
async def admin_adjust_points(user_id: str, adjustment: PointsAdjustment, username: str = Depends(verify_admin)):
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
            elif content_lower in ["!commands", "!help"]:
                response_message = "Commands: !points | !rank | !leaderboard | !site | !menace | !meta | !bit | !discord"
            # Custom promo commands
            elif content_lower == "!site":
                response_message = "🎁 Check out our rewards site! 👉 https://pezrewards.com/"
            elif content_lower == "!menace":
                response_message = "🎰 MENACE $1500 BI-WEEKLY LEADERBOARD! Double Rank-Up Rewards, VIP Transfers, Lossback, Fast Payouts - all live right now. https://menace.com/?r=pez"
            elif content_lower == "!meta":
                response_message = "🔥$3,200 USD Monthly Leaderboard! DOUBLE Rank-Up Rewards, up to 120% Rakeback, Monthly Deposit Comps! 🎉 Sign up & Support now 👉 https://metaspins.com/?ref=pezslaps"
            elif content_lower == "!bit":
                response_message = "5K LEADERBOARD 🏁 | 20K WEEKLY RACE 🏆 | VIP Transfers 💎 | DOUBLE Rank-Up Rewards 🚀 https://join.bitfortune.com/pezslaps"
            elif content_lower == "!discord":
                response_message = "💬 Join the Discord to stay up to date, connect with the community, and enter giveaways! 🎁 👉 https://discord.gg/TRThDgz77W"
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


# Include router
app.include_router(api_router)

# Vercel serverless - export app directly (no Mangum needed)
# Vercel's @vercel/python runtime natively supports ASGI apps
