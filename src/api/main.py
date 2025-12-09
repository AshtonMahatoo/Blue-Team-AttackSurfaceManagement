"""
SP101 ASM REST API
Provides API endpoints for interacting with the ASM platform
"""

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
import jwt
from datetime import datetime, timedelta

from src.utils.database import DatabaseManager
from src.utils.config_loader import ConfigLoader

# Security
security = HTTPBearer()

# Models
class Asset(BaseModel):
    id: Optional[str] = None
    ip: str
    hostname: Optional[str] = None
    domain: Optional[str] = None
    type: str
    discovered_at: datetime
    risk_score: float = Field(ge=0.0, le=10.0)
    tags: List[str] = []

class Vulnerability(BaseModel):
    id: Optional[str] = None
    asset_id: str
    cve_id: Optional[str] = None
    severity: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    description: str
    remediation: Optional[str] = None
    discovered_at: datetime

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    intensity: str = "normal"

class Token(BaseModel):
    access_token: str
    token_type: str

# Initialize FastAPI
app = FastAPI(
    title="SP101 ASM API",
    description="Attack Surface Management Platform API",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load configuration
config = ConfigLoader.load_config("config/asm_config.yaml")
db = DatabaseManager(config['database'])

# JWT configuration
JWT_SECRET = config['api']['authentication']['jwt_secret']
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    """Verify JWT token"""
    try:
        token = credentials.credentials
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# Routes
@app.get("/")
async def root():
    """API root endpoint"""
    return {
        "message": "SP101 ASM Platform API",
        "version": "1.0.0",
        "endpoints": [
            "/assets",
            "/vulnerabilities",
            "/scan",
            "/health"
        ]
    }

@app.post("/token")
async def login(username: str, password: str):
    """Get JWT token"""
    # In production, validate against database
    if username == "admin" and password == "admin":
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {"sub": username, "exp": expire}
        token = jwt.encode(token_data, JWT_SECRET, algorithm=ALGORITHM)
        return Token(access_token=token, token_type="bearer")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        db_status = await db.check_health()
        return {
            "status": "healthy" if db_status else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected" if db_status else "disconnected",
            "version": "1.0.0"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/assets", response_model=List[Asset])
async def get_assets(
    limit: int = 100,
    offset: int = 0,
    risk_min: Optional[float] = None,
    risk_max: Optional[float] = None,
    token: dict = Depends(verify_token)
):
    """Get discovered assets"""
    try:
        assets = await db.get_assets(
            limit=limit,
            offset=offset,
            risk_min=risk_min,
            risk_max=risk_max
        )
        return assets
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/assets/{asset_id}", response_model=Asset)
async def get_asset(asset_id: str, token: dict = Depends(verify_token)):
    """Get specific asset by ID"""
    try:
        asset = await db.get_asset(asset_id)
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        return asset
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/vulnerabilities", response_model=List[Vulnerability])
async def get_vulnerabilities(
    severity: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
    token: dict = Depends(verify_token)
):
    """Get vulnerabilities"""
    try:
        vulns = await db.get_vulnerabilities(
            severity=severity,
            limit=limit,
            offset=offset
        )
        return vulns
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan")
async def start_scan(scan_request: ScanRequest, token: dict = Depends(verify_token)):
    """Start a new scan"""
    try:
        # In production, this would trigger an actual scan
        return {
            "message": f"Scan started for {scan_request.target}",
            "scan_id": "scan_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S"),
            "status": "queued"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats")
async def get_statistics(token: dict = Depends(verify_token)):
    """Get platform statistics"""
    try:
        total_assets = await db.get_asset_count()
        total_vulns = await db.get_vulnerability_count()
        critical_vulns = await db.get_critical_vulnerability_count()
        
        return {
            "total_assets": total_assets,
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "assets_by_type": await db.get_assets_by_type(),
            "vulnerabilities_by_severity": await db.get_vulnerabilities_by_severity()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Run the API
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=config['api']['host'],
        port=config['api']['port'],
        log_level="info"
    )