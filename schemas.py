"""
Database Schemas for BBB Auto Sales DMS

Each Pydantic model corresponds to a MongoDB collection.
Collection name is the lowercase class name.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Literal
from datetime import date, datetime

# Users (staff)
class User(BaseModel):
    email: str = Field(..., description="Unique email")
    password_hash: str = Field(..., description="BCrypt or hashed password")
    name: str = Field(..., description="Full name")
    role: Literal["admin", "user"] = Field("user", description="Role for RBAC")
    active: bool = Field(True)

# Auth Sessions (token storage for simplicity)
class Session(BaseModel):
    user_id: str
    token: str
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

# Vehicles Inventory
class Vehicle(BaseModel):
    # Display and core fields
    year: int
    make: str
    model: str
    trim: Optional[str] = None
    vin: str
    price: float
    down_payment: float = 0
    status: Literal["Available", "Sold", "Repairs", "On Hold"] = "Available"
    stock_number: Optional[str] = None
    images: List[str] = []
    color: Optional[str] = None
    mileage: Optional[int] = None
    notes: Optional[str] = None

# Sales transactions
class Sale(BaseModel):
    account_number: int
    stock_number: str
    vin: str
    vehicle: str  # "Year Make Model"
    date: date
    salesperson: str
    sale_type: Literal["Cash", "BHPH"] = "BHPH"
    true_down: float = 0
    notes: Optional[str] = None

# Daily Collections (payments)
class Payment(BaseModel):
    date: date
    amount: float
    type: Literal["Payment", "Late Fee", "BOA"] = "Payment"
    customer: Optional[str] = None
    salesperson: Optional[str] = None

# Delinquency snapshot
class Delinquency(BaseModel):
    date: date
    open_accounts: int
    overdue_accounts: int
    rate: float

# Calendar events
class Event(BaseModel):
    title: str
    customer: Optional[str] = None
    salesperson: Optional[str] = None
    start_time: datetime
    end_time: Optional[datetime] = None
    color: Optional[str] = None

# Team chat message
class Message(BaseModel):
    sender: str
    text: str
    created_at: Optional[datetime] = None
