"""
TL DPS Party Server
- Discord OAuth login
- Party create/join
- WebSocket for real-time encounter control
- Results aggregation
"""

import os
import secrets
import time
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import uvicorn

# === CONFIGURATION ===
# Use environment variables for production, with localhost defaults for dev
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "1446291180475387945")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "YOUR_SECRET_HERE")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000")
DISCORD_REDIRECT_URI = f"{BASE_URL}/auth/callback"

# Session secret (use env var in production!)
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

app = FastAPI(title="TL DPS Party Server")

# Middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    session_cookie="tl_session",
    max_age=86400 * 7,  # 1 week
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# === DATA STRUCTURES (In-Memory for MVP) ===

@dataclass
class User:
    id: str  # Discord ID
    username: str
    avatar: Optional[str]
    token: str  # Session token for agent


@dataclass 
class PartyMember:
    user_id: str
    username: str
    avatar: Optional[str]
    websocket: Optional[WebSocket] = None
    agent_websocket: Optional[WebSocket] = None
    connected: bool = False
    agent_connected: bool = False


@dataclass
class EncounterResult:
    user_id: str
    username: str
    target: str
    total_damage: int
    duration: float
    dps: float


@dataclass
class Party:
    code: str
    leader_id: str
    members: dict = field(default_factory=dict)  # user_id -> PartyMember
    encounter_active: bool = False
    encounter_target: str = ""
    encounter_started_at: Optional[datetime] = None
    results: list = field(default_factory=list)  # List of EncounterResult


# In-memory storage
users: dict[str, User] = {}  # user_id -> User
parties: dict[str, Party] = {}  # code -> Party
user_tokens: dict[str, str] = {}  # token -> user_id
user_parties: dict[str, str] = {}  # user_id -> party_code

# Global websocket storage (independent of party membership)
web_sockets: dict[str, WebSocket] = {}  # user_id -> web WebSocket
agent_sockets: dict[str, WebSocket] = {}  # user_id -> agent WebSocket


def generate_party_code() -> str:
    """Generate a 4-character party code"""
    while True:
        code = secrets.token_hex(2).upper()  # 4 chars
        if code not in parties:
            return code


def generate_agent_token() -> str:
    """Generate a token for agent authentication"""
    return secrets.token_hex(16)


def group_results_by_target(results: list) -> list:
    """Group results by target and rank within each group"""
    from collections import defaultdict
    
    # Group by target
    by_target = defaultdict(list)
    for r in results:
        by_target[r.target].append(r)
    
    # Sort each group by damage and calculate ranks
    grouped = []
    for target, target_results in by_target.items():
        sorted_results = sorted(target_results, key=lambda x: x.total_damage, reverse=True)
        total_damage = sum(r.total_damage for r in sorted_results)
        
        grouped.append({
            "target": target,
            "total_damage": total_damage,
            "results": [
                {
                    "rank": i + 1,
                    "user_id": r.user_id,
                    "username": r.username,
                    "total_damage": r.total_damage,
                    "dps": round(r.dps, 1),
                    "percent": round((r.total_damage / total_damage * 100) if total_damage > 0 else 0, 1),
                }
                for i, r in enumerate(sorted_results)
            ]
        })
    
    # Sort groups by total damage (highest first = main boss likely)
    grouped.sort(key=lambda x: x["total_damage"], reverse=True)
    return grouped


# === DISCORD OAUTH ===

# Store pending agent redirects (state -> redirect_url)
agent_redirects: dict[str, str] = {}

@app.get("/auth/login")
async def login():
    """Redirect to Discord OAuth (for web)"""
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
    }
    url = "https://discord.com/api/oauth2/authorize?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url)


@app.get("/auth/agent-login")
async def agent_login(redirect: str):
    """Redirect to Discord OAuth (for agent) - redirects back to agent with token"""
    # Generate state to track this login
    state = secrets.token_hex(16)
    agent_redirects[state] = redirect
    
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
    }
    url = "https://discord.com/api/oauth2/authorize?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url)


@app.get("/auth/callback")
async def auth_callback(code: str, state: Optional[str] = None):
    """Handle Discord OAuth callback"""
    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": DISCORD_CLIENT_ID,
                "client_secret": DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": DISCORD_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        if token_response.status_code != 200:
            raise HTTPException(400, "Failed to authenticate with Discord")
        
        token_data = token_response.json()
        access_token = token_data["access_token"]
        
        # Get user info
        user_response = await client.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        if user_response.status_code != 200:
            raise HTTPException(400, "Failed to get user info")
        
        user_data = user_response.json()
    
    # Create or update user
    user_id = user_data["id"]
    agent_token = generate_agent_token()
    
    users[user_id] = User(
        id=user_id,
        username=user_data["username"],
        avatar=user_data.get("avatar"),
        token=agent_token,
    )
    user_tokens[agent_token] = user_id
    
    # Check if this is an agent login
    if state and state in agent_redirects:
        agent_redirect = agent_redirects.pop(state)
        # Redirect to agent's local callback with token
        return RedirectResponse(f"{agent_redirect}?token={agent_token}")
    
    # Regular web login - redirect to frontend
    return RedirectResponse(f"/?token={agent_token}")


@app.get("/auth/me")
async def get_me(token: str = Query(...)):
    """Get current user info"""
    user_id = user_tokens.get(token)
    if not user_id or user_id not in users:
        raise HTTPException(401, "Invalid token")
    
    user = users[user_id]
    party_code = user_parties.get(user_id)
    party_info = None
    
    if party_code and party_code in parties:
        party = parties[party_code]
        party_info = {
            "code": party.code,
            "is_leader": party.leader_id == user_id,
            "member_count": len(party.members),
            "encounter_active": party.encounter_active,
        }
    
    return {
        "id": user.id,
        "username": user.username,
        "avatar": user.avatar,
        "agent_token": user.token,
        "party": party_info,
    }


# === PARTY MANAGEMENT ===

@app.post("/party/create")
async def create_party(token: str = Query(...)):
    """Create a new party"""
    user_id = user_tokens.get(token)
    if not user_id or user_id not in users:
        raise HTTPException(401, "Invalid token")
    
    # Leave current party if in one
    if user_id in user_parties:
        await leave_party(token)
    
    user = users[user_id]
    code = generate_party_code()
    
    party = Party(
        code=code,
        leader_id=user_id,
        members={
            user_id: PartyMember(
                user_id=user_id,
                username=user.username,
                avatar=user.avatar,
                connected=user_id in web_sockets,
                agent_connected=user_id in agent_sockets,
            )
        },
    )
    
    parties[code] = party
    user_parties[user_id] = code
    
    return {"code": code, "is_leader": True}


@app.post("/party/join/{code}")
async def join_party(code: str, token: str = Query(...)):
    """Join an existing party"""
    user_id = user_tokens.get(token)
    if not user_id or user_id not in users:
        raise HTTPException(401, "Invalid token")
    
    code = code.upper()
    if code not in parties:
        raise HTTPException(404, "Party not found")
    
    # Leave current party if in one
    if user_id in user_parties:
        await leave_party(token)
    
    user = users[user_id]
    party = parties[code]
    
    # Create member with current connection status from global storage
    party.members[user_id] = PartyMember(
        user_id=user_id,
        username=user.username,
        avatar=user.avatar,
        connected=user_id in web_sockets,
        agent_connected=user_id in agent_sockets,
    )
    user_parties[user_id] = code
    
    # Notify other members
    await broadcast_to_party(code, {
        "type": "member_joined",
        "user_id": user_id,
        "username": user.username,
        "member_count": len(party.members),
        "connected": user_id in web_sockets,
        "agent_connected": user_id in agent_sockets,
    })
    
    return {
        "code": code,
        "is_leader": party.leader_id == user_id,
        "member_count": len(party.members),
    }


@app.post("/party/leave")
async def leave_party(token: str = Query(...)):
    """Leave current party"""
    user_id = user_tokens.get(token)
    if not user_id:
        raise HTTPException(401, "Invalid token")
    
    if user_id not in user_parties:
        return {"status": "not in party"}
    
    code = user_parties[user_id]
    if code not in parties:
        del user_parties[user_id]
        return {"status": "party gone"}
    
    party = parties[code]
    
    # Remove from party
    if user_id in party.members:
        del party.members[user_id]
    del user_parties[user_id]
    
    # If leader left, disband or transfer
    if party.leader_id == user_id:
        if party.members:
            # Transfer to first remaining member
            new_leader_id = next(iter(party.members))
            party.leader_id = new_leader_id
            await broadcast_to_party(code, {
                "type": "leader_changed",
                "new_leader_id": new_leader_id,
            })
        else:
            # Disband empty party
            del parties[code]
            return {"status": "party disbanded"}
    
    # Notify remaining members
    await broadcast_to_party(code, {
        "type": "member_left",
        "user_id": user_id,
        "member_count": len(party.members),
    })
    
    return {"status": "left"}


@app.get("/debug/parties")
async def debug_parties():
    """Debug endpoint to see all parties"""
    return {
        "party_count": len(parties),
        "party_codes": list(parties.keys()),
        "user_count": len(users),
        "token_count": len(user_tokens),
    }


@app.get("/party/{code}")
async def get_party(code: str, token: str = Query(...)):
    """Get party info"""
    user_id = user_tokens.get(token)
    if not user_id:
        raise HTTPException(401, "Invalid token")
    
    code = code.upper()
    if code not in parties:
        raise HTTPException(404, "Party not found")
    
    party = parties[code]
    
    return {
        "code": party.code,
        "leader_id": party.leader_id,
        "is_leader": party.leader_id == user_id,
        "encounter_active": party.encounter_active,
        "encounter_target": party.encounter_target,
        "members": [
            {
                "user_id": m.user_id,
                "username": m.username,
                "avatar": m.avatar,
                "connected": m.connected,
                "agent_connected": m.agent_connected,
            }
            for m in party.members.values()
        ],
        "grouped_results": group_results_by_target(party.results),
        "results": [
            {
                "user_id": r.user_id,
                "username": r.username,
                "target": r.target,
                "total_damage": r.total_damage,
                "dps": r.dps,
            }
            for r in sorted(party.results, key=lambda x: x.total_damage, reverse=True)
        ],
    }


# === ENCOUNTER CONTROL ===

@app.post("/party/{code}/start")
async def start_encounter(code: str, token: str = Query(...)):
    """Start an encounter (leader only)"""
    user_id = user_tokens.get(token)
    if not user_id:
        raise HTTPException(401, "Invalid token")
    
    code = code.upper()
    if code not in parties:
        raise HTTPException(404, "Party not found")
    
    party = parties[code]
    
    if party.leader_id != user_id:
        raise HTTPException(403, "Only leader can start encounters")
    
    party.encounter_active = True
    party.encounter_started_at = datetime.now()
    party.results = []  # Clear previous results
    
    # Broadcast to all members (web + agents)
    await broadcast_to_party(code, {
        "type": "encounter_start",
        "timestamp": party.encounter_started_at.isoformat(),
    })
    
    return {"status": "started"}


@app.post("/party/{code}/end")
async def end_encounter(code: str, token: str = Query(...)):
    """End an encounter (leader only)"""
    user_id = user_tokens.get(token)
    if not user_id:
        raise HTTPException(401, "Invalid token")
    
    code = code.upper()
    if code not in parties:
        raise HTTPException(404, "Party not found")
    
    party = parties[code]
    
    if party.leader_id != user_id:
        raise HTTPException(403, "Only leader can end encounters")
    
    party.encounter_active = False
    
    # Broadcast end signal - agents will submit results
    await broadcast_to_party(code, {
        "type": "encounter_end",
    })
    
    return {"status": "ended"}


# === WEBSOCKET ===

async def broadcast_to_party(code: str, message: dict):
    """Send message to all connected party members"""
    if code not in parties:
        return
    
    party = parties[code]
    for member in party.members.values():
        user_id = member.user_id
        
        # Send to web client (from global storage)
        if user_id in web_sockets:
            try:
                await web_sockets[user_id].send_json(message)
            except:
                del web_sockets[user_id]
                member.connected = False
        
        # Send to agent (from global storage)
        if user_id in agent_sockets:
            try:
                await agent_sockets[user_id].send_json(message)
            except:
                del agent_sockets[user_id]
                member.agent_connected = False


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: str, source: str = "web"):
    """WebSocket connection for real-time updates
    
    source: "web" for browser, "agent" for desktop agent
    """
    user_id = user_tokens.get(token)
    if not user_id or user_id not in users:
        await websocket.close(code=4001, reason="Invalid token")
        return
    
    await websocket.accept()
    
    # Store in global websocket storage (works regardless of party status)
    if source == "agent":
        agent_sockets[user_id] = websocket
    else:
        web_sockets[user_id] = websocket
    
    # If user is in a party, update their member status
    party_code = user_parties.get(user_id)
    if party_code and party_code in parties:
        party = parties[party_code]
        if user_id in party.members:
            member = party.members[user_id]
            if source == "agent":
                member.agent_connected = True
            else:
                member.connected = True
            
            # Notify party of connection
            await broadcast_to_party(party_code, {
                "type": "member_status",
                "user_id": user_id,
                "connected": member.connected,
                "agent_connected": member.agent_connected,
            })
    
    try:
        while True:
            data = await websocket.receive_json()
            await handle_ws_message(user_id, data, source)
    except WebSocketDisconnect:
        pass
    finally:
        # Remove from global storage
        if source == "agent":
            agent_sockets.pop(user_id, None)
        else:
            web_sockets.pop(user_id, None)
        
        # Update party member status on disconnect
        party_code = user_parties.get(user_id)
        if party_code and party_code in parties:
            party = parties[party_code]
            if user_id in party.members:
                member = party.members[user_id]
                if source == "agent":
                    member.agent_connected = False
                else:
                    member.connected = False
                
                await broadcast_to_party(party_code, {
                    "type": "member_status",
                    "user_id": user_id,
                    "connected": member.connected,
                    "agent_connected": member.agent_connected,
                })


async def handle_ws_message(user_id: str, data: dict, source: str):
    """Handle incoming WebSocket messages"""
    msg_type = data.get("type")
    
    if msg_type == "submit_results":
        # Agent submitting encounter results (one per target)
        party_code = user_parties.get(user_id)
        if not party_code or party_code not in parties:
            return
        
        party = parties[party_code]
        user = users[user_id]
        
        target = data.get("target", "Unknown")
        
        result = EncounterResult(
            user_id=user_id,
            username=user.username,
            target=target,
            total_damage=data.get("total_damage", 0),
            duration=data.get("duration", 0),
            dps=data.get("dps", 0),
        )
        
        # Update target name from first result
        if not party.encounter_target and result.target:
            party.encounter_target = result.target
        
        # Replace existing result from same user + same target (allow multiple targets per user)
        party.results = [r for r in party.results if not (r.user_id == user_id and r.target == target)]
        party.results.append(result)
        
        # Group results by target and sort by damage within each group
        grouped_results = group_results_by_target(party.results)
        
        # Broadcast updated results
        await broadcast_to_party(party_code, {
            "type": "results_update",
            "target": party.encounter_target,
            "grouped_results": grouped_results,
            # Also send flat list for backwards compatibility
            "results": [
                {
                    "user_id": r.user_id,
                    "username": r.username,
                    "target": r.target,
                    "total_damage": r.total_damage,
                    "dps": round(r.dps, 1),
                }
                for r in sorted(party.results, key=lambda x: x.total_damage, reverse=True)
            ],
        })


# === SERVE FRONTEND ===

@app.get("/")
async def serve_frontend():
    """Serve the frontend HTML"""
    # Check multiple locations for flexibility
    locations = [
        "index.html",              # Same directory (production)
        "../frontend/index.html",  # Development structure
        "frontend/index.html",     # Alternative
    ]
    
    for path in locations:
        try:
            with open(path, "r") as f:
                return HTMLResponse(f.read())
        except FileNotFoundError:
            continue
    
    return HTMLResponse("""
        <h1>Frontend not found</h1>
        <p>Place index.html in the same folder as main.py</p>
        <p>Checked: index.html, ../frontend/index.html, frontend/index.html</p>
    """)


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  TL DPS Party Server")
    print("=" * 50)
    print(f"  Web UI: {BASE_URL}")
    print(f"  Login:  {BASE_URL}/auth/login")
    print("=" * 50 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
