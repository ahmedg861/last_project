from fastapi import FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, MetaData, Table, select
from passlib.context import CryptContext

app = FastAPI()


DATABASE_URL = r"mssql+pyodbc://DESKTOP-G8JOIIS/tourism?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes"

engine = create_engine(DATABASE_URL)
metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("user_id", Integer, primary_key=True, index=True),
    Column("user_name", String(length=255), unique=True, index=True),
    Column("user_email", String),
    Column("user_password", String),
    Column("user_location", String),
    Column("user_phone", String),
    Column("user_age", Integer),
)


metadata.create_all(bind=engine)


class UserRegistration(BaseModel):
    user_name: str
    user_password: str
    user_email: EmailStr
    user_location: str
    user_phone: str
    user_age: int


class UserLogin(BaseModel):
    user_name: str
    user_password: str


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    return password_context.hash(password)


def verify_user_credentials(user_name: str, user_password: str):
    conn = engine.connect()
    query = select(users.c.user_name, users.c.user_password).where(users.c.user_name == user_name)
    result = conn.execute(query).fetchone()

    if result and password_context.verify(user_password, result[1]):
        return True
    return False


def register_user(user: UserRegistration):
    conn = engine.connect()
    conn.execute(users.insert().values(
        user_name=user.user_name,
        user_password=hash_password(user.user_password),  # Hash the password before storing
        user_email=user.user_email,
        user_location=user.user_location,
        user_phone=user.user_phone,
        user_age=user.user_age,
    ))
    conn.commit()


@app.post("/register")
async def register(user: UserRegistration):
    if verify_user_credentials(user.user_name, user.user_password):
        raise HTTPException(status_code=400, detail="Username already registered")

    register_user(user)
    return {"message": "Registration successful"}


@app.post("/login")
async def login(user: UserLogin):
    user_name = user.user_name
    user_password = user.user_password

    if not verify_user_credentials(user_name, user_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"message": "Login successful"}
