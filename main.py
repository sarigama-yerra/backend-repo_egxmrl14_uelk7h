import os
import secrets
from datetime import datetime, timedelta, timezone, date as date_cls
from typing import Optional, List, Literal

import requests
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database import db

app = FastAPI(title="BBB Auto Sales DMS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Utilities ----------

def normalize_utc_midnight(d: datetime | date_cls) -> datetime:
    if isinstance(d, datetime):
        return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)


def get_counter(name: str) -> int:
    res = db["counters"].find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=True,
    )
    return res.get("seq", 1)


def generate_stock_number(prefix: str) -> str:
    yy = datetime.now(timezone.utc).strftime("%y")
    seq = get_counter(f"stock_{prefix}_{yy}")
    return f"{prefix}{yy}-{seq:03d}"

# ---------- Auth (simple session-based) ----------

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: str
    role: Literal["admin", "user"] = "user"

class LoginRequest(BaseModel):
    email: str
    password: str

class AuthUser(BaseModel):
    id: str
    email: str
    name: str
    role: str

class TokenResponse(BaseModel):
    token: str
    user: AuthUser

from passlib.hash import bcrypt


def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email})


@app.post("/auth/register", response_model=AuthUser)
def register(body: RegisterRequest):
    if get_user_by_email(body.email):
        raise HTTPException(400, "Email already registered")
    hashed = bcrypt.hash(body.password)
    user_doc = {
        "email": body.email,
        "password_hash": hashed,
        "name": body.name,
        "role": body.role,
        "active": True,
        "created_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    return AuthUser(id=str(res.inserted_id), email=body.email, name=body.name, role=body.role)


@app.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest):
    user = get_user_by_email(body.email)
    if not user or not bcrypt.verify(body.password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid credentials")
    if not user.get("active", True):
        raise HTTPException(403, "User inactive")
    token = secrets.token_urlsafe(32)
    session = {
        "user_id": str(user["_id"]),
        "token": token,
        "email": user["email"],
        "name": user.get("name", ""),
        "role": user.get("role", "user"),
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    }
    db["session"].insert_one(session)
    return TokenResponse(
        token=token,
        user=AuthUser(id=str(user["_id"]), email=user["email"], name=user.get("name", ""), role=user.get("role", "user")),
    )


@app.post("/auth/bootstrap", response_model=TokenResponse)
def bootstrap_admin():
    """
    One-click initialization: creates a default admin if no users exist yet
    and returns an auth token for immediate access.
    Email: admin@demo.com, Password: demo1234
    """
    existing = db["user"].count_documents({})
    if existing > 0:
        raise HTTPException(400, "Already initialized")

    email = "admin@demo.com"
    password = "demo1234"
    name = "Admin"
    role = "admin"

    hashed = bcrypt.hash(password)
    user_doc = {
        "email": email,
        "password_hash": hashed,
        "name": name,
        "role": role,
        "active": True,
        "created_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)

    token = secrets.token_urlsafe(32)
    session = {
        "user_id": str(res.inserted_id),
        "token": token,
        "email": email,
        "name": name,
        "role": role,
        "created_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    }
    db["session"].insert_one(session)

    return TokenResponse(
        token=token,
        user=AuthUser(id=str(res.inserted_id), email=email, name=name, role=role),
    )


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Missing token")
    token = authorization.split()[1]
    sess = db["session"].find_one({"token": token})
    if not sess:
        raise HTTPException(401, "Invalid token")
    if sess.get("expires_at") and sess["expires_at"] < datetime.now(timezone.utc):
        raise HTTPException(401, "Session expired")
    return {"id": sess.get("user_id"), "email": sess.get("email"), "name": sess.get("name"), "role": sess.get("role", "user")}


def require_role(required: Literal["admin", "user"]):
    def dep(user: dict = Depends(get_current_user)):
        role = user.get("role", "user")
        if required == "admin" and role != "admin":
            raise HTTPException(403, "Admin only")
        return user
    return dep

# ---------- Inventory ----------

class VehicleIn(BaseModel):
    year: int
    make: str
    model: str
    trim: Optional[str] = None
    vin: str
    price: float
    down_payment: float = 0
    status: Literal["Available", "Sold", "Repairs", "On Hold"] = "Available"
    stock_prefix: Literal["N", "D", "F", "CH", "O"] = "O"
    images: List[str] = []
    color: Optional[str] = None
    mileage: Optional[int] = None
    notes: Optional[str] = None

@app.get("/inventory")
def list_inventory(status: Optional[str] = None, q: Optional[str] = None, limit: int = 100, user=Depends(require_role("user"))):
    filt = {}
    if status:
        filt["status"] = status
    if q:
        filt["$or"] = [
            {"make": {"$regex": q, "$options": "i"}},
            {"model": {"$regex": q, "$options": "i"}},
            {"vin": {"$regex": q, "$options": "i"}},
            {"stock_number": {"$regex": q, "$options": "i"}},
        ]
    docs = db["vehicle"].find(filt).limit(limit)
    res = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        res.append(d)
    return res

@app.post("/inventory")
def add_vehicle(body: VehicleIn, user=Depends(require_role("admin"))):
    stock = generate_stock_number(body.stock_prefix)
    doc = body.model_dump()
    doc["stock_number"] = stock
    doc["created_at"] = datetime.now(timezone.utc)
    inserted = db["vehicle"].insert_one(doc)
    return {"id": str(inserted.inserted_id), **doc}

# ---------- Sales ----------

class MarkSoldRequest(BaseModel):
    stock_number: str
    account_number: Optional[int] = None
    date: datetime
    salesperson: str
    sale_type: Literal["Cash", "BHPH"] = "BHPH"
    true_down: float = 0
    notes: Optional[str] = None

@app.post("/sales/mark_sold")
def mark_sold(body: MarkSoldRequest, user=Depends(require_role("admin"))):
    session = db.client.start_session()
    with session.start_transaction():
        v = db["vehicle"].find_one({"stock_number": body.stock_number})
        if not v:
            raise HTTPException(404, "Vehicle not found")
        if v.get("status") == "Sold":
            raise HTTPException(400, "Already sold")
        account_number = body.account_number or get_counter("account_number")
        db["vehicle"].update_one({"stock_number": body.stock_number}, {"$set": {"status": "Sold", "updated_at": datetime.now(timezone.utc)}})
        sale_doc = {
            "account_number": account_number,
            "stock_number": v.get("stock_number"),
            "vin": v.get("vin"),
            "vehicle": f"{v.get('year')} {v.get('make')} {v.get('model')}",
            "date": normalize_utc_midnight(body.date),
            "salesperson": body.salesperson,
            "sale_type": body.sale_type,
            "true_down": body.true_down,
            "notes": body.notes,
            "created_at": datetime.now(timezone.utc),
        }
        db["sale"].insert_one(sale_doc)
    return {"ok": True, "account_number": account_number}

class RevertSaleRequest(BaseModel):
    account_number: int

@app.post("/sales/revert")
def revert_sale(body: RevertSaleRequest, user=Depends(require_role("admin"))):
    session = db.client.start_session()
    with session.start_transaction():
        sale = db["sale"].find_one({"account_number": body.account_number})
        if not sale:
            raise HTTPException(404, "Sale not found")
        db["sale"].delete_one({"_id": sale["_id"]})
        if sale.get("stock_number"):
            db["vehicle"].update_one({"stock_number": sale["stock_number"]}, {"$set": {"status": "Available", "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}

@app.get("/sales")
def list_sales(limit: int = 200, user=Depends(require_role("user"))):
    docs = db["sale"].find({}).sort("date", -1).limit(limit)
    res = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        res.append(d)
    return res

# ---------- Collections ----------

class PaymentIn(BaseModel):
    date: datetime
    amount: float
    type: Literal["Payment", "Late Fee", "BOA"] = "Payment"
    customer: Optional[str] = None
    salesperson: Optional[str] = None

@app.post("/collections/payments")
def upsert_payments(body: List[PaymentIn], user=Depends(require_role("admin"))):
    for p in body:
        doc = p.model_dump()
        doc["date"] = normalize_utc_midnight(doc["date"])  # normalize
        doc["created_at"] = datetime.now(timezone.utc)
        db["payment"].insert_one(doc)
    return {"ok": True}

@app.get("/collections/payments")
def list_payments(start: Optional[datetime] = None, end: Optional[datetime] = None, user=Depends(require_role("user"))):
    filt = {}
    if start or end:
        filt["date"] = {}
        if start:
            filt["date"]["$gte"] = normalize_utc_midnight(start)
        if end:
            filt["date"]["$lte"] = normalize_utc_midnight(end)
    docs = db["payment"].find(filt).sort("date", -1)
    res = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        res.append(d)
    return res

# ---------- Metrics (Dashboard) ----------

@app.get("/metrics/dashboard")
def dashboard_metrics(user=Depends(require_role("user"))):
    now = datetime.now(timezone.utc)
    start_year = datetime(now.year, 1, 1, tzinfo=timezone.utc)
    ytd_sales = db["sale"].count_documents({"date": {"$gte": start_year}})
    inventory_count = db["vehicle"].count_documents({"status": {"$nin": ["Repairs", "Sold"]}})
    one_week = now - timedelta(days=7)
    weekly_collections = db["payment"].aggregate([
        {"$match": {"date": {"$gte": normalize_utc_midnight(one_week)}}},
        {"$group": {"_id": None, "total": {"$sum": "$amount"}}}
    ])
    weekly_total = 0
    for r in weekly_collections:
        weekly_total = r.get("total", 0)
    snap = db["delinquency"].find({}).sort("date", -1).limit(1)
    delinquency_rate = 0.0
    for s in snap:
        if s.get("open_accounts", 0) > 0:
            delinquency_rate = (s.get("overdue_accounts", 0) / s.get("open_accounts", 1)) * 100
    # next account without incrementing counters permanently
    curr = db["counters"].find_one({"_id": "account_number"}) or {"seq": 0}
    next_account = (curr.get("seq", 0) + 1)
    preview = {}
    for p in ["N", "D", "F", "CH", "O"]:
        yy = now.strftime("%y")
        ct = db["counters"].find_one({"_id": f"stock_{p}_{yy}"}) or {"seq": 0}
        preview[p] = f"{p}{yy}-{ct.get('seq',0)+1:03d}"
    return {
        "ytdSales": ytd_sales,
        "inventoryCount": inventory_count,
        "weeklyCollections": weekly_total,
        "delinquencyRate": round(delinquency_rate, 2),
        "nextAccount": next_account,
        "stockPreview": preview,
    }

# ---------- VIN Decoder ----------

@app.get("/vin/decode")
def decode_vin(vin: str, user=Depends(require_role("user"))):
    try:
        url = f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVin/{vin}?format=json"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        results = {item["Variable"]: item["Value"] for item in data.get("Results", []) if item.get("Value")}
        return {"vin": vin, "data": results}
    except Exception as e:
        raise HTTPException(400, f"VIN decode failed: {e}")

# ---------- Root & Test ----------

@app.get("/")
def read_root():
    return {"message": "BBB Auto Sales DMS API running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os as _os
    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
