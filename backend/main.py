# backend/main.py - Manual Ping Only (No Continuous Loop)
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, select, func, or_
from sqlalchemy.sql import func as sql_func
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional, List
import hashlib
import secrets
import binascii
import asyncio
import random
import json
import subprocess
import platform
import ipaddress
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "postgresql+asyncpg://area51_system:87587@localhost:5432/area51_db"
engine = create_async_engine(DATABASE_URL)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# Security functions (same as before)
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{pwd_hash}"

def verify_password(password: str, hashed: str) -> bool:
    try:
        salt, pwd_hash = hashed.split(':')
        return pwd_hash == hashlib.sha256((password + salt).encode()).hexdigest()
    except:
        return False

def create_access_token(username: str) -> str:
    data = f"{username}:{datetime.utcnow().isoformat()}"
    return binascii.hexlify(data.encode()).decode()

# Enhanced Models (same as before)
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    profile_picture = Column(String, nullable=True)
    phone = Column(String, nullable=True)
    company = Column(String, nullable=True)
    role = Column(String, default="admin")
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())

class Device(Base):
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    device_type = Column(String, nullable=False, index=True)
    operating_system = Column(String, nullable=False)
    os_version = Column(String, nullable=False)
    ip_address = Column(String, nullable=True, index=True)
    hostname = Column(String, nullable=True, index=True)
    business_criticality = Column(String, default="medium")
    environment = Column(String, default="production")
    
    # Health monitoring fields
    status = Column(String, default="unknown")  # online, offline, unknown
    response_time = Column(Float, default=0.0)  # ping response time in ms
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    disk_usage = Column(Float, default=0.0)
    uptime = Column(Integer, default=0)
    last_seen = Column(DateTime(timezone=True), server_default=sql_func.now())
    last_ping = Column(DateTime(timezone=True), nullable=True)
    ping_success_count = Column(Integer, default=0)  # Total successful pings
    ping_total_count = Column(Integer, default=0)    # Total ping attempts
    
    # Additional details
    description = Column(Text, nullable=True)
    location = Column(String, nullable=True)
    owner_contact = Column(String, nullable=True)
    
    owner_id = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=sql_func.now())

# Enhanced Schemas
class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    device_type: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    business_criticality: Optional[str] = None
    environment: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None
    owner_contact: Optional[str] = None

class DeviceCreate(BaseModel):
    name: str
    device_type: str
    operating_system: str
    os_version: str
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    business_criticality: str = "medium"
    environment: str = "production"
    description: Optional[str] = None
    location: Optional[str] = None
    owner_contact: Optional[str] = None

class DeviceResponse(BaseModel):
    id: int
    name: str
    device_type: str
    operating_system: str
    os_version: str
    ip_address: Optional[str]
    hostname: Optional[str]
    business_criticality: str
    environment: str
    status: str
    response_time: float
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    uptime: int
    last_seen: datetime
    last_ping: Optional[datetime]
    ping_success_count: int
    ping_total_count: int
    description: Optional[str]
    location: Optional[str]
    owner_contact: Optional[str]
    owner_id: int
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime]
    
    class Config:
        from_attributes = True

class UserSignup(BaseModel):
    email: str
    username: str
    full_name: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: str
    phone: Optional[str]
    company: Optional[str]
    role: str
    is_active: bool
    last_login: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

# WebSocket manager for real-time updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except:
                pass

manager = ConnectionManager()

# Ping utility functions
async def ping_device(ip_address: str, timeout: int = 3) -> tuple[bool, float]:
    """
    Ping a device and return (success, response_time_ms)
    """
    if not ip_address:
        return False, 0.0
    
    try:
        # Validate IP address
        ipaddress.ip_address(ip_address)
        
        # Determine ping command based on OS
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_address]
        else:  # Linux/Unix/MacOS
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip_address]
        
        # Execute ping command
        start_time = datetime.utcnow()
        result = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=timeout + 1)
        end_time = datetime.utcnow()
        
        # Calculate response time
        response_time = (end_time - start_time).total_seconds() * 1000
        
        # Check if ping was successful
        success = result.returncode == 0
        
        if success:
            # Try to extract actual ping time from output (more accurate)
            output = stdout.decode()
            if system == "windows":
                # Windows: "time=1ms" or "time<1ms"
                import re
                time_match = re.search(r'time[<=]([\d.]+)ms', output.lower())
                if time_match:
                    response_time = float(time_match.group(1))
            else:
                # Linux: "time=1.23 ms"
                import re
                time_match = re.search(r'time=([\d.]+)\s*ms', output.lower())
                if time_match:
                    response_time = float(time_match.group(1))
        
        logger.info(f"Manual ping {ip_address}: {'SUCCESS' if success else 'FAILED'} ({response_time:.1f}ms)")
        return success, response_time
        
    except (ipaddress.AddressValueError, ValueError):
        logger.warning(f"Invalid IP address: {ip_address}")
        return False, 0.0
    except asyncio.TimeoutError:
        logger.warning(f"Ping timeout for {ip_address}")
        return False, timeout * 1000
    except Exception as e:
        logger.error(f"Ping error for {ip_address}: {e}")
        return False, 0.0

# Auth dependency
async def get_current_user(token: str, db: AsyncSession):
    try:
        decoded = binascii.unhexlify(token.encode()).decode()
        username = decoded.split(':')[0]
        
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        
        if not user or not user.is_active:
            return None
        
        return user
    except:
        return None

async def get_db():
    async with SessionLocal() as session:
        yield session

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("🚀 Area51 Manual Ping Platform Ready!")
    
    # Start background task for health simulation (CPU, RAM, etc.)
    asyncio.create_task(simulate_device_health())
    
    yield

# Background task to simulate other health data (CPU, RAM, etc.) - No ping loop
async def simulate_device_health():
    """
    Simulate CPU, RAM, disk usage (since we don't have agents yet)
    No automatic pinging - only manual pings when user clicks
    """
    while True:
        try:
            async with SessionLocal() as db:
                result = await db.execute(select(Device).where(Device.is_active == True))
                devices = result.scalars().all()
                
                for device in devices[:20]:  # Limit to first 20 devices
                    # Only simulate health for devices that have been pinged recently
                    # If device was never pinged, keep status as unknown
                    if device.last_ping is not None:
                        # Simulate more realistic metrics based on device type and status
                        if device.status == "online":
                            if device.device_type in ['server', 'virtual-server']:
                                # Servers typically have higher, more stable usage
                                device.cpu_usage = max(10, min(90, device.cpu_usage + random.uniform(-3, 3)))
                                device.memory_usage = max(20, min(85, device.memory_usage + random.uniform(-2, 2)))
                                device.disk_usage = max(15, min(95, device.disk_usage + random.uniform(-0.5, 0.5)))
                                device.uptime += 30  # Increment uptime for online devices
                            elif device.device_type in ['workstation', 'laptop', 'desktop']:
                                # Workstations have more variable usage
                                device.cpu_usage = max(0, min(100, device.cpu_usage + random.uniform(-10, 10)))
                                device.memory_usage = max(10, min(95, device.memory_usage + random.uniform(-5, 5)))
                                device.disk_usage = max(20, min(90, device.disk_usage + random.uniform(-1, 1)))
                                device.uptime += 30
                            else:
                                # Other devices (mobile, IoT, etc.) have lower usage
                                device.cpu_usage = max(0, min(60, device.cpu_usage + random.uniform(-5, 5)))
                                device.memory_usage = max(5, min(70, device.memory_usage + random.uniform(-3, 3)))
                                device.disk_usage = max(10, min(80, device.disk_usage + random.uniform(-0.5, 0.5)))
                                device.uptime += 30
                        else:
                            # Offline devices don't increment uptime
                            pass
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Health simulation error: {e}")
        
        await asyncio.sleep(30)  # Update every 30 seconds

app = FastAPI(title="Area51 Security Platform - Manual Ping", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === AUTHENTICATION ENDPOINTS ===

@app.post("/auth/signup", response_model=UserResponse)
async def signup(user_data: UserSignup, db: AsyncSession = Depends(get_db)):
    if len(user_data.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    
    email_check = await db.execute(select(User).where(User.email == user_data.email.lower()))
    if email_check.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    username_check = await db.execute(select(User).where(User.username == user_data.username.lower()))
    if username_check.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")
    
    hashed_password = hash_password(user_data.password)
    new_user = User(
        email=user_data.email.lower(),
        username=user_data.username.lower(),
        full_name=user_data.full_name,
        hashed_password=hashed_password
    )
    
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return new_user

@app.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == user_data.username.lower()))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Account deactivated")
    
    user.last_login = datetime.utcnow()
    await db.commit()
    
    access_token = create_access_token(user.username)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user
    }

# === USER PROFILE ENDPOINTS ===

@app.get("/api/profile", response_model=UserResponse)
async def get_profile(token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@app.put("/api/profile", response_model=UserResponse)
async def update_profile(profile_data: UserUpdate, token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if profile_data.full_name:
        user.full_name = profile_data.full_name
    if profile_data.email:
        user.email = profile_data.email
    if profile_data.phone:
        user.phone = profile_data.phone
    if profile_data.company:
        user.company = profile_data.company
    
    await db.commit()
    await db.refresh(user)
    return user

@app.post("/api/change-password")
async def change_password(password_data: PasswordChange, token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not verify_password(password_data.current_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if len(password_data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    
    user.hashed_password = hash_password(password_data.new_password)
    await db.commit()
    
    return {"message": "Password changed successfully"}

# === DEVICE ENDPOINTS ===

@app.get("/api/dashboard")
async def get_dashboard(token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Get comprehensive stats
    total_devices = await db.execute(
        select(func.count(Device.id)).where(Device.owner_id == user.id, Device.is_active == True)
    )
    
    online_devices = await db.execute(
        select(func.count(Device.id)).where(
            Device.owner_id == user.id, 
            Device.is_active == True,
            Device.status == "online"
        )
    )
    
    offline_devices = await db.execute(
        select(func.count(Device.id)).where(
            Device.owner_id == user.id,
            Device.is_active == True,
            Device.status == "offline"
        )
    )
    
    critical_devices = await db.execute(
        select(func.count(Device.id)).where(
            Device.owner_id == user.id,
            Device.is_active == True,
            Device.business_criticality == "critical"
        )
    )
    
    production_devices = await db.execute(
        select(func.count(Device.id)).where(
            Device.owner_id == user.id,
            Device.is_active == True,
            Device.environment == "production"
        )
    )
    
    # Get average response time for devices with ping data
    avg_response_time = await db.execute(
        select(func.avg(Device.response_time)).where(
            Device.owner_id == user.id,
            Device.is_active == True,
            Device.response_time > 0
        )
    )
    
    return {
        "user": user.full_name,
        "total_devices": total_devices.scalar() or 0,
        "online_devices": online_devices.scalar() or 0,
        "offline_devices": offline_devices.scalar() or 0,
        "critical_devices": critical_devices.scalar() or 0,
        "production_devices": production_devices.scalar() or 0,
        "avg_response_time": round(avg_response_time.scalar() or 0, 1),
        "message": f"Welcome back, {user.full_name}!"
    }

@app.post("/api/devices", response_model=DeviceResponse)
async def create_device(device: DeviceCreate, token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    new_device = Device(
        **device.dict(),
        owner_id=user.id,
        status="unknown",  # Start as unknown until first ping
        cpu_usage=random.uniform(10, 30),
        memory_usage=random.uniform(20, 40),
        disk_usage=random.uniform(15, 35),
        uptime=0,  # Start with 0 uptime
        ping_success_count=0,
        ping_total_count=0,
        is_active=True
    )
    
    db.add(new_device)
    await db.commit()
    await db.refresh(new_device)
    
    # Broadcast device added
    await manager.broadcast({
        "type": "device_added",
        "data": {"device_name": device.name, "device_id": new_device.id}
    })
    
    return new_device

@app.get("/api/devices")
async def list_devices(
    token: str, 
    search: Optional[str] = None,
    device_type: Optional[str] = None,
    environment: Optional[str] = None,
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    query = select(Device).where(Device.owner_id == user.id, Device.is_active == True)
    
    # Apply filters
    if search:
        query = query.where(
            or_(
                Device.name.ilike(f"%{search}%"),
                Device.hostname.ilike(f"%{search}%"),
                Device.ip_address.ilike(f"%{search}%"),
                Device.operating_system.ilike(f"%{search}%")
            )
        )
    
    if device_type:
        query = query.where(Device.device_type == device_type)
    
    if environment:
        query = query.where(Device.environment == environment)
    
    if status:
        query = query.where(Device.status == status)
    
    query = query.order_by(Device.created_at.desc())
    
    result = await db.execute(query)
    devices = result.scalars().all()
    
    return {"devices": devices, "total": len(devices)}

@app.get("/api/devices/{device_id}", response_model=DeviceResponse)
async def get_device(device_id: int, token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.owner_id == user.id,
            Device.is_active == True
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return device

@app.post("/api/devices/{device_id}/ping")
async def manual_ping_device(device_id: int, token: str, db: AsyncSession = Depends(get_db)):
    """Manually ping a specific device - ONLY when user clicks"""
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.owner_id == user.id,
            Device.is_active == True
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    if not device.ip_address:
        raise HTTPException(status_code=400, detail="Device has no IP address")
    
    logger.info(f"Manual ping request for {device.name} ({device.ip_address}) by {user.username}")
    
    # Ping the device
    success, response_time = await ping_device(device.ip_address)
    
    # Update device with ping results
    device.status = "online" if success else "offline"
    device.response_time = response_time
    device.last_ping = datetime.utcnow()
    device.ping_total_count += 1
    
    if success:
        device.last_seen = datetime.utcnow()
        device.ping_success_count += 1
    
    await db.commit()
    await db.refresh(device)
    
    # Broadcast ping result to all connected clients
    await manager.broadcast({
        "type": "manual_ping_result",
        "data": {
            "device_id": device_id,
            "device_name": device.name,
            "status": device.status,
            "response_time": response_time,
            "success": success,
            "timestamp": device.last_ping.isoformat(),
            "user": user.username
        }
    })
    
    return {
        "device_id": device_id,
        "device_name": device.name,
        "status": device.status,
        "response_time": response_time,
        "success": success,
        "timestamp": device.last_ping.isoformat(),
        "ping_success_rate": (device.ping_success_count / device.ping_total_count * 100) if device.ping_total_count > 0 else 0
    }

@app.put("/api/devices/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int, 
    device_data: DeviceUpdate, 
    token: str, 
    db: AsyncSession = Depends(get_db)
):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.owner_id == user.id,
            Device.is_active == True
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Update fields
    for field, value in device_data.dict(exclude_unset=True).items():
        setattr(device, field, value)
    
    device.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(device)
    
    # Broadcast device updated
    await manager.broadcast({
        "type": "device_updated",
        "data": {"device_name": device.name, "device_id": device.id}
    })
    
    return device

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: int, token: str, db: AsyncSession = Depends(get_db)):
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.owner_id == user.id,
            Device.is_active == True
        )
    )
    device = result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    device.is_active = False
    await db.commit()
    
    # Broadcast device deleted
    await manager.broadcast({
        "type": "device_deleted",
        "data": {"device_name": device.name, "device_id": device.id}
    })
    
    return {"message": "Device deleted successfully"}

# === WEBSOCKET ENDPOINT ===

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle any client messages if needed
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def root():
    return {"message": "Area51 Security Platform - Manual Ping Only", "status": "ready"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
