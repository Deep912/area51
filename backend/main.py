# backend/main.py - Complete with nmap Integration
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, select, func, or_, JSON, ForeignKey
from sqlalchemy.sql import func as sql_func
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from typing import Optional, List, Dict, Any
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
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import nmap
import requests

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database setup
DATABASE_URL = "postgresql+asyncpg://area51_system:87587@localhost:5432/area51_db"
engine = create_async_engine(DATABASE_URL)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# Security and utility functions
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

# Enhanced Models with Network Features
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
    status = Column(String, default="unknown")
    response_time = Column(Float, default=0.0)
    cpu_usage = Column(Float, default=0.0)
    memory_usage = Column(Float, default=0.0)
    disk_usage = Column(Float, default=0.0)
    uptime = Column(Integer, default=0)
    last_seen = Column(DateTime(timezone=True), server_default=sql_func.now())
    last_ping = Column(DateTime(timezone=True), nullable=True)
    ping_success_rate = Column(Float, default=100.0)
    
    # Network scanning fields
    last_port_scan = Column(DateTime(timezone=True), nullable=True)
    open_ports_count = Column(Integer, default=0)
    services_detected = Column(Text, nullable=True)  # JSON string of services
    
    # Additional details
    description = Column(Text, nullable=True)
    location = Column(String, nullable=True)
    owner_contact = Column(String, nullable=True)
    
    owner_id = Column(Integer, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=sql_func.now())

class PortScan(Base):
    __tablename__ = "port_scans"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    scan_type = Column(String, default="tcp")
    port = Column(Integer, nullable=False)
    status = Column(String, nullable=False)  # open, closed, filtered
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    banner = Column(Text, nullable=True)
    scan_time = Column(DateTime(timezone=True), server_default=sql_func.now())
    response_time = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())

class ScanSession(Base):
    __tablename__ = "scan_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_type = Column(String, nullable=False)  # quick, full, custom
    status = Column(String, default="running")  # running, completed, failed
    ports_scanned = Column(Integer, default=0)
    ports_found = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), server_default=sql_func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    scan_duration = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())

class SecurityAlert(Base):
    __tablename__ = "security_alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    alert_type = Column(String, nullable=False)
    severity = Column(String, default="medium")
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="active")
    first_seen = Column(DateTime(timezone=True), server_default=sql_func.now())
    last_seen = Column(DateTime(timezone=True), server_default=sql_func.now())
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    alert_metadata = Column(JSON, nullable=True)  # FIXED: Changed from metadata
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())

class DeviceMonitoring(Base):
    __tablename__ = "device_monitoring"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    ping_monitoring = Column(Boolean, default=True)
    port_monitoring = Column(Boolean, default=False)
    service_monitoring = Column(Boolean, default=False)
    vulnerability_scanning = Column(Boolean, default=False)
    alert_on_ping_fail = Column(Boolean, default=True)
    alert_on_port_change = Column(Boolean, default=True)
    alert_on_service_change = Column(Boolean, default=True)
    ping_interval = Column(Integer, default=300)  # seconds
    scan_interval = Column(Integer, default=3600)  # seconds
    created_at = Column(DateTime(timezone=True), server_default=sql_func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=sql_func.now())

# Enhanced Schemas
class PortScanResult(BaseModel):
    port: int
    status: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    response_time: float

class ScanRequest(BaseModel):
    scan_type: str = "quick"  # quick, full, custom
    ports: Optional[str] = None  # custom port range like "80,443,22-25"

class SecurityAlertResponse(BaseModel):
    id: int
    device_id: int
    alert_type: str
    severity: str
    title: str
    description: Optional[str]
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    
    class Config:
        from_attributes = True

# Device schemas (keeping existing ones)
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
    ping_success_rate: float
    last_port_scan: Optional[datetime]
    open_ports_count: int
    services_detected: Optional[str]
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

# WebSocket manager
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

    async def send_scan_progress(self, scan_id: int, progress: dict):
        message = {
            "type": "scan_progress",
            "scan_id": scan_id,
            "data": progress
        }
        await self.broadcast(message)

manager = ConnectionManager()

# Enhanced NetworkScanner with full nmap integration
class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        logger.info("🔍 NetworkScanner initialized with nmap")
    
    async def ping_device(self, ip_address: str, timeout: int = 3) -> tuple[bool, float]:
        """Enhanced ping function"""
        if not ip_address:
            return False, 0.0
        
        try:
            ipaddress.ip_address(ip_address)
            
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_address]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), ip_address]
            
            start_time = datetime.utcnow()
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=timeout + 1)
            end_time = datetime.utcnow()
            
            response_time = (end_time - start_time).total_seconds() * 1000
            success = result.returncode == 0
            
            if success:
                output = stdout.decode()
                if system == "windows":
                    import re
                    time_match = re.search(r'time[<=]([\d.]+)ms', output.lower())
                    if time_match:
                        response_time = float(time_match.group(1))
                else:
                    import re
                    time_match = re.search(r'time=([\d.]+)\s*ms', output.lower())
                    if time_match:
                        response_time = float(time_match.group(1))
            
            return success, response_time
            
        except Exception as e:
            logger.error(f"Ping error for {ip_address}: {e}")
            return False, 0.0

    def run_nmap_scan(self, ip_address: str, ports: str, scan_args: str = "-sS -sV --version-intensity 3") -> Dict[str, Any]:
        """
        Run nmap scan with enhanced service detection
        
        Args:
            ip_address: Target IP address
            ports: Port specification (e.g., "22,80,443" or "1-1000")
            scan_args: nmap arguments
        """
        try:
            logger.info(f"🔍 Starting nmap scan on {ip_address}:{ports}")
            
            # Run nmap scan
            self.nm.scan(ip_address, ports, arguments=scan_args)
            
            results = []
            if ip_address in self.nm.all_hosts():
                host_info = self.nm[ip_address]
                
                # Get host status
                host_status = host_info.state()
                
                # Process each protocol (tcp, udp)
                for protocol in host_info.all_protocols():
                    ports_info = host_info[protocol].keys()
                    
                    for port in ports_info:
                        port_info = host_info[protocol][port]
                        
                        # Extract service information
                        service_name = port_info.get('name', 'unknown')
                        service_version = port_info.get('version', '')
                        service_product = port_info.get('product', '')
                        service_extrainfo = port_info.get('extrainfo', '')
                        
                        # Build service version string
                        version_parts = [service_product, service_version, service_extrainfo]
                        full_version = ' '.join(filter(None, version_parts))
                        
                        # Create banner from available info
                        banner_parts = []
                        if service_product:
                            banner_parts.append(service_product)
                        if service_version:
                            banner_parts.append(f"version {service_version}")
                        if service_extrainfo:
                            banner_parts.append(f"({service_extrainfo})")
                        
                        banner = ' '.join(banner_parts) if banner_parts else f"{service_name} service"
                        
                        result = {
                            "port": port,
                            "status": port_info['state'],
                            "service_name": service_name,
                            "service_version": full_version or "Unknown",
                            "banner": banner,
                            "response_time": 0.0,  # nmap doesn't provide individual port response times
                            "protocol": protocol
                        }
                        
                        results.append(result)
                        
            return {
                "host_status": host_status if ip_address in self.nm.all_hosts() else "down",
                "ports": results,
                "scan_info": {
                    "command": self.nm.command_line(),
                    "scan_stats": self.nm.scanstats()
                }
            }
            
        except Exception as e:
            logger.error(f"Nmap scan error for {ip_address}: {e}")
            return {"error": str(e), "ports": []}

    async def scan_device_ports(self, device_id: int, ip_address: str, scan_type: str = "quick", 
                               custom_ports: str = None, db: AsyncSession = None) -> Dict[str, Any]:
        """Scan device ports using nmap with progress updates"""
        
        # Define port ranges and scan arguments
        if scan_type == "quick":
            ports = "21,22,23,25,53,80,110,143,443,993,995,3389,5432,3306,8080,8443"
            scan_args = "-sS -sV --version-intensity 2"
        elif scan_type == "full":
            ports = "1-1000"
            scan_args = "-sS -sV --version-intensity 3"
        elif scan_type == "custom" and custom_ports:
            ports = custom_ports
            scan_args = "-sS -sV --version-intensity 2"
        else:
            ports = "22,80,443"
            scan_args = "-sS -sV --version-intensity 1"
        
        # Send initial progress
        await manager.send_scan_progress(device_id, {
            "completed": 0,
            "total": 100,
            "percentage": 0,
            "current_port": "Starting scan...",
            "open_ports_found": 0
        })
        
        # Run nmap scan in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        scan_result = await loop.run_in_executor(
            None, 
            self.run_nmap_scan, 
            ip_address, 
            ports, 
            scan_args
        )
        
        if "error" in scan_result:
            logger.error(f"Scan failed: {scan_result['error']}")
            return {
                "total_ports_scanned": 0,
                "open_ports_found": 0,
                "open_ports": [],
                "all_results": [],
                "error": scan_result["error"]
            }
        
        port_results = scan_result.get("ports", [])
        open_ports = [port for port in port_results if port["status"] == "open"]
        
        # Save results to database
        if db:
            for result in port_results:
                port_scan = PortScan(
                    device_id=device_id,
                    scan_type=result.get("protocol", "tcp"),
                    port=result["port"],
                    status=result["status"],
                    service_name=result["service_name"],
                    service_version=result["service_version"],
                    banner=result["banner"],
                    response_time=result["response_time"]
                )
                db.add(port_scan)
        
        # Send completion progress
        await manager.send_scan_progress(device_id, {
            "completed": 100,
            "total": 100,
            "percentage": 100,
            "current_port": "Scan completed",
            "open_ports_found": len(open_ports)
        })
        
        return {
            "total_ports_scanned": len(port_results),
            "open_ports_found": len(open_ports),
            "open_ports": open_ports,
            "all_results": port_results,
            "scan_info": scan_result.get("scan_info", {}),
            "host_status": scan_result.get("host_status", "unknown")
        }

scanner = NetworkScanner()

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
    print("🚀 Area51 Advanced Network Security Platform Ready with nmap!")
    
    # Start background tasks
    asyncio.create_task(simulate_device_health())
    
    yield

# Background task
async def simulate_device_health():
    """Simulate CPU, RAM, disk usage only"""
    while True:
        try:
            async with SessionLocal() as db:
                result = await db.execute(select(Device).where(Device.is_active == True))
                devices = result.scalars().all()
                
                for device in devices[:20]:
                    if device.status and device.status != "unknown":
                        if device.device_type in ['server', 'virtual-server']:
                            device.cpu_usage = max(10, min(90, device.cpu_usage + random.uniform(-3, 3)))
                            device.memory_usage = max(20, min(85, device.memory_usage + random.uniform(-2, 2)))
                            device.disk_usage = max(15, min(95, device.disk_usage + random.uniform(-0.5, 0.5)))
                        elif device.device_type in ['workstation', 'laptop', 'desktop']:
                            device.cpu_usage = max(0, min(100, device.cpu_usage + random.uniform(-10, 10)))
                            device.memory_usage = max(10, min(95, device.memory_usage + random.uniform(-5, 5)))
                            device.disk_usage = max(20, min(90, device.disk_usage + random.uniform(-1, 1)))
                        else:
                            device.cpu_usage = max(0, min(60, device.cpu_usage + random.uniform(-5, 5)))
                            device.memory_usage = max(5, min(70, device.memory_usage + random.uniform(-3, 3)))
                            device.disk_usage = max(10, min(80, device.disk_usage + random.uniform(-0.5, 0.5)))
                        
                        if device.status == "online":
                            device.uptime += 15
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Health simulation error: {e}")
        
        await asyncio.sleep(15)

app = FastAPI(title="Area51 Advanced Network Security Platform", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === AUTHENTICATION ENDPOINTS (Same as before) ===

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

# === USER PROFILE ENDPOINTS (Same as before) ===

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

# === DEVICE ENDPOINTS (Same as before) ===

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
    
    # Get average response time for online devices
    avg_response_time = await db.execute(
        select(func.avg(Device.response_time)).where(
            Device.owner_id == user.id,
            Device.is_active == True,
            Device.status == "online",
            Device.response_time > 0
        )
    )
    
    return {
        "user": user.full_name,
        "total_devices": total_devices.scalar() or 0,
        "online_devices": online_devices.scalar() or 0,
        "offline_devices": offline_devices.scalar() or 0,
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
        status="unknown",
        cpu_usage=random.uniform(10, 30),
        memory_usage=random.uniform(20, 40),
        disk_usage=random.uniform(15, 35),
        uptime=0,
        is_active=True
    )
    
    db.add(new_device)
    await db.commit()
    await db.refresh(new_device)
    
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

@app.post("/api/devices/{device_id}/ping")
async def manual_ping_device(device_id: int, token: str, db: AsyncSession = Depends(get_db)):
    """Manual ping - only when user clicks the ping button"""
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
    
    logger.info(f"Manual ping requested by {user.username} for device {device.name} ({device.ip_address})")
    
    # Ping the device
    success, response_time = await scanner.ping_device(device.ip_address)
    
    # Update device
    old_status = device.status
    device.status = "online" if success else "offline"
    device.response_time = response_time
    device.last_ping = datetime.utcnow()
    if success:
        device.last_seen = datetime.utcnow()
        if old_status == "offline":
            device.uptime = 0
    
    # Update success rate
    if device.ping_success_rate is None:
        device.ping_success_rate = 100.0 if success else 0.0
    else:
        current_success = 100.0 if success else 0.0
        device.ping_success_rate = (device.ping_success_rate * 0.8) + (current_success * 0.2)
    
    await db.commit()
    await db.refresh(device)
    
    # Broadcast manual ping result
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
        "status": device.status,
        "response_time": response_time,
        "success": success,
        "timestamp": device.last_ping.isoformat(),
        "message": f"Ping {'successful' if success else 'failed'}"
    }

# === NEW NETWORK SCANNING ENDPOINTS ===

@app.post("/api/devices/{device_id}/scan")
async def scan_device_ports(
    device_id: int, 
    scan_request: ScanRequest,
    background_tasks: BackgroundTasks,
    token: str, 
    db: AsyncSession = Depends(get_db)
):
    """Start a port scan on a device using nmap"""
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Get device
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
    
    # Create scan session
    scan_session = ScanSession(
        device_id=device_id,
        user_id=user.id,
        scan_type=scan_request.scan_type,
        status="running"
    )
    db.add(scan_session)
    await db.commit()
    await db.refresh(scan_session)
    
    # Start background scan
    background_tasks.add_task(
        perform_port_scan, 
        device_id, 
        device.ip_address, 
        scan_request.scan_type,
        scan_request.ports,
        scan_session.id,
        user.id
    )
    
    return {
        "scan_id": scan_session.id,
        "message": f"nmap port scan started for {device.name}",
        "scan_type": scan_request.scan_type
    }

async def perform_port_scan(device_id: int, ip_address: str, scan_type: str, 
                          custom_ports: str, scan_session_id: int, user_id: int):
    """Background task to perform the actual port scan"""
    async with SessionLocal() as db:
        try:
            result = await db.execute(select(ScanSession).where(ScanSession.id == scan_session_id))
            session = result.scalar_one_or_none()
            
            if not session:
                return
            
            # Clear previous scan results for this device
            await db.execute(
                select(PortScan).where(PortScan.device_id == device_id)
            )
            old_scans = await db.execute(
                select(PortScan).where(
                    PortScan.device_id == device_id,
                    PortScan.scan_time > datetime.utcnow() - timedelta(hours=1)
                )
            )
            for old_scan in old_scans.scalars():
                await db.delete(old_scan)
            
            # Perform the nmap scan
            start_time = datetime.utcnow()
            scan_results = await scanner.scan_device_ports(
                device_id, ip_address, scan_type, custom_ports, db
            )
            end_time = datetime.utcnow()
            
            # Update scan session
            session.status = "completed"
            session.ports_scanned = scan_results["total_ports_scanned"]
            session.ports_found = scan_results["open_ports_found"]
            session.completed_at = end_time
            session.scan_duration = (end_time - start_time).total_seconds()
            
            # Update device with scan results
            device_result = await db.execute(select(Device).where(Device.id == device_id))
            device = device_result.scalar_one_or_none()
            
            if device:
                device.last_port_scan = end_time
                device.open_ports_count = scan_results["open_ports_found"]
                device.services_detected = json.dumps([
                    f"{port['port']}/{port['service_name']}" 
                    for port in scan_results["open_ports"] 
                    if port['service_name']
                ])
            
            await db.commit()
            
            # Broadcast completion
            await manager.broadcast({
                "type": "scan_completed",
                "data": {
                    "scan_id": scan_session_id,
                    "device_id": device_id,
                    "results": scan_results,
                    "duration": session.scan_duration
                }
            })
            
            # Check for security alerts
            await check_for_security_alerts(device_id, scan_results["open_ports"], db)
            
        except Exception as e:
            logger.error(f"Port scan error: {e}")
            if session:
                session.status = "failed"
                await db.commit()

async def check_for_security_alerts(device_id: int, current_ports: List[Dict], db: AsyncSession):
    """Check for security alerts based on scan results"""
    try:
        # Get previous scan results
        result = await db.execute(
            select(PortScan).where(
                PortScan.device_id == device_id,
                PortScan.status == "open",
                PortScan.scan_time > datetime.utcnow() - timedelta(days=7)
            ).order_by(PortScan.scan_time.desc())
        )
        previous_scans = result.scalars().all()
        
        previous_ports = {scan.port for scan in previous_scans}
        current_port_numbers = {port["port"] for port in current_ports}
        
        # Check for new open ports
        new_ports = current_port_numbers - previous_ports
        closed_ports = previous_ports - current_port_numbers
        
        if new_ports:
            alert = SecurityAlert(
                device_id=device_id,
                alert_type="port_change",
                severity="medium",
                title=f"New open ports detected: {', '.join(map(str, new_ports))}",
                description=f"Device has {len(new_ports)} new open ports since last scan",
                alert_metadata={"new_ports": list(new_ports), "type": "new_ports"}
            )
            db.add(alert)
        
        if closed_ports:
            alert = SecurityAlert(
                device_id=device_id,
                alert_type="port_change",
                severity="low",
                title=f"Ports closed: {', '.join(map(str, closed_ports))}",
                description=f"Device has {len(closed_ports)} fewer open ports since last scan",
                alert_metadata={"closed_ports": list(closed_ports), "type": "closed_ports"}
            )
            db.add(alert)
        
        await db.commit()
        
    except Exception as e:
        logger.error(f"Error checking security alerts: {e}")

@app.get("/api/devices/{device_id}/scan-results")
async def get_scan_results(device_id: int, token: str, db: AsyncSession = Depends(get_db)):
    """Get latest scan results for a device"""
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Verify device ownership
    device_result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.owner_id == user.id,
            Device.is_active == True
        )
    )
    device = device_result.scalar_one_or_none()
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get latest scan session
    session_result = await db.execute(
        select(ScanSession).where(ScanSession.device_id == device_id)
        .order_by(ScanSession.created_at.desc()).limit(1)
    )
    latest_session = session_result.scalar_one_or_none()
    
    # Get latest port scan results
    ports_result = await db.execute(
        select(PortScan).where(PortScan.device_id == device_id)
        .order_by(PortScan.scan_time.desc()).limit(100)
    )
    port_scans = ports_result.scalars().all()
    
    # Group by scan time (latest scan)
    if port_scans:
        latest_scan_time = port_scans[0].scan_time
        latest_ports = [
            scan for scan in port_scans 
            if abs((scan.scan_time - latest_scan_time).total_seconds()) < 60
        ]
    else:
        latest_ports = []
    
    return {
        "device_id": device_id,
        "device_name": device.name,
        "last_scan": device.last_port_scan,
        "open_ports_count": device.open_ports_count,
        "scan_session": {
            "id": latest_session.id if latest_session else None,
            "scan_type": latest_session.scan_type if latest_session else None,
            "status": latest_session.status if latest_session else None,
            "duration": latest_session.scan_duration if latest_session else None,
            "ports_scanned": latest_session.ports_scanned if latest_session else 0,
            "completed_at": latest_session.completed_at if latest_session else None
        },
        "open_ports": [
            {
                "port": scan.port,
                "service_name": scan.service_name,
                "service_version": scan.service_version,
                "banner": scan.banner,
                "response_time": scan.response_time
            }
            for scan in latest_ports if scan.status == "open"
        ],
        "all_ports": [
            {
                "port": scan.port,
                "status": scan.status,
                "service_name": scan.service_name,
                "service_version": scan.service_version,
                "banner": scan.banner,
                "response_time": scan.response_time
            }
            for scan in latest_ports
        ]
    }

@app.get("/api/security-alerts")
async def get_security_alerts(token: str, db: AsyncSession = Depends(get_db)):
    """Get security alerts for user's devices"""
    user = await get_current_user(token, db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    devices_result = await db.execute(
        select(Device.id).where(Device.owner_id == user.id, Device.is_active == True)
    )
    device_ids = [row[0] for row in devices_result.fetchall()]
    
    if not device_ids:
        return {"alerts": []}
    
    alerts_result = await db.execute(
        select(SecurityAlert).where(
            SecurityAlert.device_id.in_(device_ids),
            SecurityAlert.status == "active"
        ).order_by(SecurityAlert.created_at.desc()).limit(50)
    )
    alerts = alerts_result.scalars().all()
    
    return {"alerts": alerts}

# Keep all other existing endpoints (update_device, delete_device, etc.)

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
    
    return {"message": "Device deleted successfully"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/")
async def root():
    return {"message": "Area51 Advanced Network Security Platform with nmap", "status": "ready"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
