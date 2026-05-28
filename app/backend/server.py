from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
from datetime import datetime
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
import logging
from typing import Optional

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
MONGODB_URL = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGODB_URL)
db: AsyncIOMotorDatabase = client["klik_db"]

# Models
class User(BaseModel):
    user_id: str
    google_id: str
    email: str
    name: str
    picture: str = ""
    is_admin: bool = False
    created_at: datetime = None
    last_login: datetime = None

class LoginData(BaseModel):
    id: str
    email: str
    name: str
    picture: Optional[str] = ""

@app.on_event("startup")
async def startup():
    """Initialize database indexes on startup"""
    try:
        await db.users.create_index("email", unique=True)
        await db.users.create_index("google_id")
        await db.users.create_index("user_id")
        logger.info("Database indexes created")
    except Exception as e:
        logger.error(f"Error creating indexes: {e}")

@app.post("/api/auth/session")
async def create_session(data: LoginData):
    """
    Handle user login/session creation.
    First user to login becomes admin automatically.
    """
    try:
        # Check if user exists
        existing_user = await db.users.find_one(
            {"email": data.email},
            {"_id": 0}
        )
        
        if existing_user:
            # Update existing user's last login
            result = await db.users.update_one(
                {"user_id": existing_user["user_id"]},
                {
                    "$set": {
                        "name": data.name,
                        "picture": data.picture or "",
                        "google_id": data.id,
                        "last_login": datetime.utcnow()
                    }
                }
            )
            user_id = existing_user["user_id"]
            is_admin = existing_user.get("is_admin", False)
            logger.info(f"User {data.email} logged in (admin: {is_admin})")
        else:
            # Create new user
            # Check if this is the first user
            user_count = await db.users.count_documents({})
            is_first_user = user_count == 0
            
            user_id = f"user_{uuid.uuid4().hex[:12]}"
            new_user = User(
                user_id=user_id,
                google_id=data.id,
                email=data.email,
                name=data.name,
                picture=data.picture or "",
                is_admin=is_first_user,  # First user becomes admin
                created_at=datetime.utcnow(),
                last_login=datetime.utcnow()
            )
            
            await db.users.insert_one(new_user.dict())
            
            if is_first_user:
                logger.info(f"🎉 First user {data.email} registered as ADMIN!")
            else:
                logger.info(f"New user {data.email} registered (admin: False)")
            
            is_admin = is_first_user
        
        return {
            "success": True,
            "user_id": user_id,
            "email": data.email,
            "name": data.name,
            "is_admin": is_admin,
            "message": "Session created successfully"
        }
        
    except Exception as e:
        logger.error(f"Error creating session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/auth/me")
async def get_current_user(user_id: str):
    """Get current user information"""
    try:
        user = await db.users.find_one(
            {"user_id": user_id},
            {"_id": 0, "google_id": 0}
        )
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return user
        
    except Exception as e:
        logger.error(f"Error fetching user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/auth/logout")
async def logout(user_id: str):
    """Handle user logout"""
    try:
        logger.info(f"User {user_id} logged out")
        return {"success": True, "message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"Error logging out: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/admin/promote")
async def promote_to_admin(user_id: str, target_user_email: str, promoter_user_id: str):
    """
    Promote a user to admin.
    Only existing admins can promote other users.
    """
    try:
        # Verify promoter is admin
        promoter = await db.users.find_one({"user_id": promoter_user_id})
        if not promoter or not promoter.get("is_admin"):
            raise HTTPException(status_code=403, detail="Only admins can promote users")
        
        # Update target user to admin
        result = await db.users.update_one(
            {"email": target_user_email},
            {"$set": {"is_admin": True}}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        logger.info(f"User {target_user_email} promoted to admin by {promoter.get('email')}")
        
        return {
            "success": True,
            "message": f"User {target_user_email} is now admin",
            "modified_count": result.modified_count
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error promoting user: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/admin/users")
async def list_all_users(admin_user_id: str):
    """
    List all users.
    Only admins can access this endpoint.
    """
    try:
        # Verify admin access
        admin = await db.users.find_one({"user_id": admin_user_id})
        if not admin or not admin.get("is_admin"):
            raise HTTPException(status_code=403, detail="Only admins can view users")
        
        users = await db.users.find({}, {"_id": 0, "google_id": 0}).to_list(None)
        
        return {
            "success": True,
            "total_users": len(users),
            "users": users
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching users: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.on_event("shutdown")
async def shutdown():
    """Close database connection on shutdown"""
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
