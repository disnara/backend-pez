from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from mangum import Mangum
import os
import logging
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
import secrets
from datetime import datetime, timezone, timedelta
import httpx
import hashlib
import jwt
import urllib.parse

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB (sync)
mongo_url = os.environ.get('MONGO_URL', '')
db_name = os.environ.get('DB_NAME', 'pezrewards')
db = None

if mongo_url:
    try:
        client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
        db = client[db_name]
        logger.info("MongoDB connected")
    except Exception as e:
        logger.error(f"MongoDB error: {e}")

# Config
KICK_CLIENT_ID = os.environ.get('KICK_CLIENT_ID', '')
KICK_CLIENT_SECRET = os.environ.get('KICK_CLIENT_SECRET', '')
KICK_REDIRECT_URI = os.environ.get('KICK_REDIRECT_URI', '')
KICK_CHANNEL = os.environ.get('KICK_CHANNEL', 'mrbetsit')
JWT_SECRET = os.environ.get('JWT_SECRET', 'pezrewards_secret_key_2026')
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'pezrewards')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'pezrewardadmin123')
POINTS_PER_MESSAGE = int(os.environ.get('POINTS_PER_MESSAGE', '1'))

# App
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

api_router = APIRouter(prefix="/api")
security = HTTPBasic()

# PKCE store
pkce_store = {}

# Models
class ShopItemCreate(BaseModel):
    name: str
    description: str
    image_url: Optional[str] = None
    category: str = "digital"
    price_points: int
    stock: int = -1
    is_active: bool = True

class RedemptionCreate(BaseModel):
    item_id: str
    discord_username: str

class PointsAdjustment(BaseModel):
    amount: int
    reason: Optional[str] = None

# Helpers
def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if not (secrets.compare_digest(credentials.username, ADMIN_USERNAME) and 
            secrets.compare_digest(credentials.password, ADMIN_PASSWORD)):
        raise HTTPException(status_code=401, detail="Invalid credentials", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

def generate_code_verifier():
    return secrets.token_urlsafe(64)[:128]

def generate_code_challenge(verifier: str):
    import base64
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

def create_jwt_token(user_id: str, kick_username: str, is_admin: bool = False):
    payload = {"user_id": user_id, "kick_username": kick_username, "is_admin": is_admin, "exp": datetime.now(timezone.utc) + timedelta(days=7)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(request: Request):
    token = request.cookies.get("auth_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = verify_jwt_token(token)
    if db:
        user = db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
        if user:
            if user.get("is_banned"):
                raise HTTPException(status_code=403, detail="Account banned")
            return user
    return payload

# Default settings
DEFAULT_SETTINGS = {
    "menace": {"prize_pool": "$1,500", "period": "Bi-Weekly", "period_type": "bi-weekly", "start_date": "2026-02-07T00:00:00+00:00", "end_date": "2026-02-21T00:00:00+00:00", "needs_date_filter": True},
    "metaspins": {"prize_pool": "$2,000", "period": "Monthly", "period_type": "monthly", "start_date": "2026-02-01T00:00:00+00:00", "end_date": "2026-03-01T00:00:00+00:00", "needs_date_filter": False},
    "bitfortune": {"prize_pool": "$5,000", "period": "Monthly", "period_type": "monthly", "start_date": "2026-01-27T00:00:00+00:00", "end_date": "2026-02-27T00:00:00+00:00", "fetch_start": 1769472000, "fetch_end": 1772150400, "needs_date_filter": True}
}

def get_settings(site: str):
    if db:
        s = db.leaderboard_settings.find_one({"site": site}, {"_id": 0})
        if s:
            return s
    return DEFAULT_SETTINGS.get(site, {})

def get_end_time(site: str):
    settings = get_settings(site)
    if settings.get("end_date"):
        try:
            return datetime.fromisoformat(settings["end_date"].replace('Z', '+00:00'))
        except:
            pass
    defaults = {"metaspins": datetime(2026, 3, 1, tzinfo=timezone.utc), "menace": datetime(2026, 2, 21, tzinfo=timezone.utc), "bitfortune": datetime(2026, 2, 27, tzinfo=timezone.utc)}
    return defaults.get(site)

# Routes
@api_router.get("/")
def root():
    return {"message": "PezRewards API", "status": "running"}

@api_router.get("/health")
def health():
    return {"status": "ok", "db": "connected" if db else "not_connected"}

# Leaderboards
@api_router.get("/leaderboard/metaspins")
async def leaderboard_metaspins():
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get("https://exportdata.xcdn.tech/metaspins-affiliate-leaderboard-export/1808/182639827/1099561537.json")
            data = r.json()
            if isinstance(data, list):
                users = [{"rank": i+1, "username": u.get("username", "Unknown"), "wagered": u.get("bets", 0)} for i, u in enumerate(data[:20])]
                return {"success": True, "site": "metaspins", "data": users}
    except Exception as e:
        logger.error(f"Metaspins error: {e}")
    return {"success": False, "site": "metaspins", "data": []}

@api_router.get("/leaderboard/menace")
async def leaderboard_menace():
    try:
        settings = get_settings("menace")
        start = settings.get("start_date", "2026-02-07")[:10]
        end = settings.get("end_date", "2026-02-21")[:10]
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(f"https://api-prod.gaze.bet/api/leaderboard/LSNCGAYMCPRJ/fb7d008f-a6e5-4d00-81f9-2e4afd9c5b7a", params={"dateStart": start, "dateEnd": end, "limit": 20})
            data = r.json()
            if "leaderboard" in data:
                users = [{"rank": u.get("place", 0), "username": u.get("nickname", "Unknown"), "wagered": u.get("wagered", 0)} for u in data["leaderboard"][:20]]
                return {"success": True, "site": "menace", "data": users}
    except Exception as e:
        logger.error(f"Menace error: {e}")
    return {"success": False, "site": "menace", "data": []}

@api_router.get("/leaderboard/bitfortune")
async def leaderboard_bitfortune():
    try:
        settings = get_settings("bitfortune")
        fetch_start = settings.get("fetch_start", 1769472000)
        fetch_end = settings.get("fetch_end", 1772150400)
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get("https://platformv2.bitfortune.com/api/v1/external/affiliates/leaderboard", params={"api_key": "082a6a65-4da1-425c-9b44-cf609e988672", "from": fetch_start, "to": fetch_end})
            data = r.json()
            if isinstance(data, list):
                sorted_data = sorted(data, key=lambda x: x.get("total_wager_usd", 0), reverse=True)
                users = [{"rank": i+1, "username": u.get("user_name", "Unknown"), "wagered": u.get("total_wager_usd", 0)} for i, u in enumerate(sorted_data[:20])]
                return {"success": True, "site": "bitfortune", "data": users}
    except Exception as e:
        logger.error(f"Bitfortune error: {e}")
    return {"success": False, "site": "bitfortune", "data": []}

# Timers
@api_router.get("/timer/{site}")
def timer(site: str):
    site = site.lower()
    end_time = get_end_time(site)
    if not end_time:
        raise HTTPException(status_code=404, detail="Timer not found")
    now = datetime.now(timezone.utc)
    remaining = end_time - now
    if remaining.total_seconds() <= 0:
        return {"success": True, "site": site, "ended": True, "days": 0, "hours": 0, "minutes": 0, "seconds": 0}
    days = remaining.days
    hours, rem = divmod(remaining.seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return {"success": True, "site": site, "ended": False, "days": days, "hours": hours, "minutes": minutes, "seconds": seconds, "total_seconds": int(remaining.total_seconds())}

@api_router.get("/timers")
def timers():
    result = {}
    for site in ["menace", "metaspins", "bitfortune"]:
        end_time = get_end_time(site)
        if not end_time:
            continue
        now = datetime.now(timezone.utc)
        remaining = end_time - now
        if remaining.total_seconds() <= 0:
            result[site] = {"ended": True, "days": 0, "hours": 0, "minutes": 0, "seconds": 0}
        else:
            days = remaining.days
            hours, rem = divmod(remaining.seconds, 3600)
            minutes, seconds = divmod(rem, 60)
            result[site] = {"ended": False, "days": days, "hours": hours, "minutes": minutes, "seconds": seconds}
    return {"success": True, "timers": result}

# Settings
@api_router.get("/settings")
def all_settings():
    return {"success": True, "settings": {site: get_settings(site) for site in ["menace", "metaspins", "bitfortune"]}}

@api_router.get("/settings/{site}")
def site_settings(site: str):
    return {"success": True, "site": site, "settings": get_settings(site.lower())}

# Challenges
@api_router.get("/challenges")
def challenges():
    if not db:
        return {"success": True, "challenges": []}
    return {"success": True, "challenges": list(db.challenges.find({}, {"_id": 0}))}

@api_router.get("/challenges/active")
def active_challenges():
    if not db:
        return {"success": True, "challenges": []}
    return {"success": True, "challenges": list(db.challenges.find({"is_active": True}, {"_id": 0}))}

# Auth
@api_router.get("/auth/kick/login")
def kick_login():
    state = secrets.token_urlsafe(32)
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    pkce_store[state] = verifier
    params = {"client_id": KICK_CLIENT_ID, "redirect_uri": KICK_REDIRECT_URI, "response_type": "code", "scope": "user:read events:subscribe chat:write", "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    return {"auth_url": f"https://id.kick.com/oauth/authorize?{urllib.parse.urlencode(params)}"}

@api_router.get("/auth/callback/kick")
async def kick_callback(request: Request, code: str = None, state: str = None, error: str = None):
    is_bot = state and state.startswith("bot_")
    if error or not code or not state:
        return RedirectResponse(url="/admin/dashboard.html?bot_error=auth_failed" if is_bot else "/?error=auth_failed")
    
    verifier = pkce_store.pop(state, None)
    if not verifier:
        return RedirectResponse(url="/admin/dashboard.html?bot_error=invalid_state" if is_bot else "/?error=invalid_state")
    
    try:
        async with httpx.AsyncClient(timeout=30) as c:
            token_resp = await c.post("https://id.kick.com/oauth/token", data={"grant_type": "authorization_code", "client_id": KICK_CLIENT_ID, "client_secret": KICK_CLIENT_SECRET, "code": code, "redirect_uri": KICK_REDIRECT_URI, "code_verifier": verifier})
            if token_resp.status_code != 200:
                return RedirectResponse(url="/admin/dashboard.html?bot_error=token_failed" if is_bot else "/?error=token_failed")
            tokens = token_resp.json()
            access_token = tokens.get("access_token")
            
            user_resp = await c.get("https://api.kick.com/public/v1/users", headers={"Authorization": f"Bearer {access_token}"})
            if user_resp.status_code != 200:
                return RedirectResponse(url="/admin/dashboard.html?bot_error=user_failed" if is_bot else "/?error=user_failed")
            
            kick_user = user_resp.json()
            if isinstance(kick_user, list):
                kick_user = kick_user[0] if kick_user else {}
            elif isinstance(kick_user, dict) and "data" in kick_user:
                kick_user = kick_user["data"][0] if isinstance(kick_user["data"], list) else kick_user["data"]
            
            kick_username = kick_user.get("username") or kick_user.get("name") or "Unknown"
            kick_id = str(kick_user.get("id") or kick_user.get("user_id") or "")
            
            if is_bot:
                if db:
                    db.settings.update_one({"type": "bot_tokens"}, {"$set": {"type": "bot_tokens", "access_token": access_token, "refresh_token": tokens.get("refresh_token"), "username": kick_username, "user_id": kick_id}}, upsert=True)
                    try:
                        await c.post("https://api.kick.com/public/v1/events/subscriptions", headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}, json={"events": [{"name": "chat.message.sent", "version": 1}], "method": "webhook"})
                    except:
                        pass
                return RedirectResponse(url=f"/admin/dashboard.html?bot_success=true&bot_user={kick_username}")
            
            # User login
            if db:
                existing = db.users.find_one({"kick_id": kick_id})
                if existing:
                    db.users.update_one({"kick_id": kick_id}, {"$set": {"kick_username": kick_username, "last_login": datetime.now(timezone.utc).isoformat(), "access_token": access_token}})
                    user_id = existing["id"]
                    is_admin = existing.get("is_admin", False)
                else:
                    user_id = str(uuid.uuid4())
                    db.users.insert_one({"id": user_id, "kick_id": kick_id, "kick_username": kick_username, "points_balance": 0, "registered_at": datetime.now(timezone.utc).isoformat(), "is_banned": False, "is_admin": False})
                    is_admin = False
            else:
                user_id = str(uuid.uuid4())
                is_admin = False
            
            token = create_jwt_token(user_id, kick_username, is_admin)
            response = RedirectResponse(url="/shop.html")
            response.set_cookie(key="auth_token", value=token, httponly=True, secure=True, samesite="lax", max_age=604800)
            return response
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        return RedirectResponse(url="/admin/dashboard.html?bot_error=error" if is_bot else "/?error=error")

@api_router.get("/auth/me")
def auth_me(request: Request):
    try:
        user = get_current_user(request)
        safe = {k: v for k, v in user.items() if k not in ["access_token", "refresh_token", "_id"]}
        return {"success": True, "user": safe}
    except:
        return {"success": False, "user": None}

@api_router.post("/auth/logout")
def logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie("auth_token")
    return resp

# Shop
@api_router.get("/shop/items")
def shop_items(active_only: bool = True):
    if not db:
        return {"success": True, "items": []}
    query = {"is_active": True} if active_only else {}
    return {"success": True, "items": list(db.shop_items.find(query, {"_id": 0}))}

@api_router.post("/shop/redeem")
def shop_redeem(redemption: RedemptionCreate, request: Request):
    user = get_current_user(request)
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")
    item = db.shop_items.find_one({"id": redemption.item_id}, {"_id": 0})
    if not item or not item.get("is_active"):
        raise HTTPException(status_code=404, detail="Item not found")
    if user.get("points_balance", 0) < item["price_points"]:
        raise HTTPException(status_code=400, detail="Insufficient points")
    
    new_balance = user["points_balance"] - item["price_points"]
    db.users.update_one({"id": user["id"]}, {"$set": {"points_balance": new_balance}})
    
    redemption_id = str(uuid.uuid4())
    db.redemptions.insert_one({"id": redemption_id, "user_id": user["id"], "item_id": item["id"], "item_name": item["name"], "points_spent": item["price_points"], "status": "pending", "kick_username": user.get("kick_username"), "discord_username": redemption.discord_username, "created_at": datetime.now(timezone.utc).isoformat()})
    
    return {"success": True, "redemption_id": redemption_id, "new_balance": new_balance}

@api_router.get("/points/balance")
def points_balance(request: Request):
    user = get_current_user(request)
    return {"success": True, "balance": user.get("points_balance", 0)}

@api_router.get("/users/redemptions")
def user_redemptions(request: Request):
    user = get_current_user(request)
    if not db:
        return {"success": True, "redemptions": []}
    return {"success": True, "redemptions": list(db.redemptions.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1).limit(50))}

# Admin
@api_router.post("/admin/login")
def admin_login(creds: dict):
    if creds.get("username") == ADMIN_USERNAME and creds.get("password") == ADMIN_PASSWORD:
        return {"success": True}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@api_router.get("/admin/users")
def admin_users(search: str = None, username: str = Depends(verify_admin)):
    if not db:
        return {"success": True, "users": []}
    query = {"$or": [{"kick_username": {"$regex": search, "$options": "i"}}, {"discord_username": {"$regex": search, "$options": "i"}}]} if search else {}
    return {"success": True, "users": list(db.users.find(query, {"_id": 0, "access_token": 0, "refresh_token": 0}).sort("registered_at", -1).limit(100))}

@api_router.post("/admin/users/{user_id}/ban")
def admin_ban(user_id: str, username: str = Depends(verify_admin)):
    if not db:
        raise HTTPException(status_code=503)
    db.users.update_one({"id": user_id}, {"$set": {"is_banned": True}})
    return {"success": True}

@api_router.post("/admin/users/{user_id}/unban")
def admin_unban(user_id: str, username: str = Depends(verify_admin)):
    if not db:
        raise HTTPException(status_code=503)
    db.users.update_one({"id": user_id}, {"$set": {"is_banned": False}})
    return {"success": True}

@api_router.post("/admin/users/{user_id}/adjust-points")
def admin_adjust(user_id: str, adj: PointsAdjustment, username: str = Depends(verify_admin)):
    if not db:
        raise HTTPException(status_code=503)
    user = db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404)
    new_bal = max(0, user.get("points_balance", 0) + adj.amount)
    db.users.update_one({"id": user_id}, {"$set": {"points_balance": new_bal}})
    return {"success": True, "new_balance": new_bal}

@api_router.get("/admin/shop/items")
def admin_shop_items(username: str = Depends(verify_admin)):
    if not db:
        return {"success": True, "items": []}
    return {"success": True, "items": list(db.shop_items.find({}, {"_id": 0}))}

@api_router.post("/admin/shop/items")
def admin_create_item(item: ShopItemCreate, username: str = Depends(verify_admin)):
    if not db:
        raise HTTPException(status_code=503)
    item_dict = item.model_dump()
    item_dict["id"] = str(uuid.uuid4())
    item_dict["created_at"] = datetime.now(timezone.utc).isoformat()
    db.shop_items.insert_one(item_dict)
    return {"success": True, "item": {k: v for k, v in item_dict.items() if k != "_id"}}

@api_router.delete("/admin/shop/items/{item_id}")
def admin_delete_item(item_id: str, username: str = Depends(verify_admin)):
    if not db:
        raise HTTPException(status_code=503)
    db.shop_items.delete_one({"id": item_id})
    return {"success": True}

@api_router.get("/admin/redemptions")
def admin_redemptions(status: str = None, username: str = Depends(verify_admin)):
    if not db:
        return {"success": True, "redemptions": []}
    query = {"status": status} if status else {}
    return {"success": True, "redemptions": list(db.redemptions.find(query, {"_id": 0}).sort("created_at", -1).limit(100))}

@api_router.put("/admin/redemptions/{rid}")
def admin_update_redemption(rid: str, update: dict, username: str = Depends(verify_admin)):
    if not db:
        raise HTTPException(status_code=503)
    db.redemptions.update_one({"id": rid}, {"$set": {"status": update.get("status"), "handled_at": datetime.now(timezone.utc).isoformat()}})
    return {"success": True}

@api_router.get("/admin/bot-status")
def admin_bot_status(username: str = Depends(verify_admin)):
    if not db:
        return {"success": True, "bot": {"status": "not_configured"}}
    bot = db.settings.find_one({"type": "bot_tokens"}, {"_id": 0})
    return {"success": True, "bot": {"status": "authorized" if bot and bot.get("access_token") else "not_authorized", "authorized_user": bot.get("username") if bot else None, "target_channel": KICK_CHANNEL}}

@api_router.get("/admin/bot/authorize")
def admin_bot_auth(username: str = Depends(verify_admin)):
    state = "bot_" + secrets.token_urlsafe(32)
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier)
    pkce_store[state] = verifier
    params = {"client_id": KICK_CLIENT_ID, "redirect_uri": KICK_REDIRECT_URI, "response_type": "code", "scope": "user:read channel:read chat:write events:subscribe", "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    return {"success": True, "auth_url": f"https://id.kick.com/oauth/authorize?{urllib.parse.urlencode(params)}"}

@api_router.post("/admin/bot/revoke")
def admin_bot_revoke(username: str = Depends(verify_admin)):
    if db:
        db.settings.delete_one({"type": "bot_tokens"})
    return {"success": True}

# Webhook
@api_router.post("/webhook/kick")
async def webhook_kick(request: Request):
    try:
        body = await request.json()
        event = request.headers.get("Kick-Event-Type", "")
        
        if event == "chat.message.sent":
            sender = body.get("sender", {})
            username = sender.get("username", "")
            content = body.get("content", "").lower().strip()
            
            response_msg = None
            if content == "!points":
                if db:
                    user = db.users.find_one({"kick_username": {"$regex": f"^{username}$", "$options": "i"}})
                    response_msg = f"@{username} You have {user.get('points_balance', 0):,} points!" if user else f"@{username} Not registered yet!"
            elif content in ["!leaderboard", "!lb"]:
                if db:
                    users = list(db.users.find({"is_banned": {"$ne": True}, "points_balance": {"$gt": 0}}, {"_id": 0}).sort("points_balance", -1).limit(5))
                    if users:
                        parts = [f"{i+1}. {u.get('kick_username')}: {u.get('points_balance', 0):,}" for i, u in enumerate(users)]
                        response_msg = "Leaderboard: " + " | ".join(parts)
            elif content == "!rank":
                if db:
                    user = db.users.find_one({"kick_username": {"$regex": f"^{username}$", "$options": "i"}})
                    if user:
                        rank = db.users.count_documents({"points_balance": {"$gt": user.get("points_balance", 0)}, "is_banned": {"$ne": True}}) + 1
                        response_msg = f"@{username} You are rank #{rank} with {user.get('points_balance', 0):,} points!"
            
            if response_msg:
                bot = db.settings.find_one({"type": "bot_tokens"}) if db else None
                if bot and bot.get("access_token"):
                    async with httpx.AsyncClient() as c:
                        await c.post("https://api.kick.com/public/v1/chat", headers={"Authorization": f"Bearer {bot['access_token']}", "Content-Type": "application/json"}, json={"content": response_msg, "type": "user", "broadcaster_user_id": bot.get("user_id")})
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return {"status": "error"}

@api_router.get("/webhook/kick")
def webhook_verify():
    return {"status": "ok"}

# Bot legacy endpoints
@api_router.get("/bot/points")
def bot_points(user: str):
    if db:
        u = db.users.find_one({"kick_username": {"$regex": f"^{user}$", "$options": "i"}})
        if u:
            return Response(content=f"@{user} has {u.get('points_balance', 0):,} points!", media_type="text/plain")
    return Response(content=f"@{user} not found", media_type="text/plain")

@api_router.get("/bot/leaderboard")
def bot_leaderboard():
    if db:
        users = list(db.users.find({"points_balance": {"$gt": 0}}, {"_id": 0}).sort("points_balance", -1).limit(5))
        if users:
            parts = [f"{i+1}. {u.get('kick_username')}: {u.get('points_balance', 0):,}" for i, u in enumerate(users)]
            return Response(content=" | ".join(parts), media_type="text/plain")
    return Response(content="No users yet", media_type="text/plain")

# Include router
app.include_router(api_router)

# Vercel handler
handler = Mangum(app, lifespan="off")
