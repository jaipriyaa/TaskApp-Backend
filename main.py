from datetime import datetime, timedelta, timezone
import sqlite3

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel, EmailStr

from passlib.context import CryptContext
from jose import jwt, JWTError

from google.oauth2 import id_token
from google.auth.transport import requests


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE = "users.db"

SECRET_KEY = "task-manager-secret-key-change-this-later"

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 15

REFRESH_TOKEN_EXPIRE_DAYS = 7

GOOGLE_WEB_CLIENT_ID = (
    "994801658842-316ielqi0lm0e57t243ddd7okkqi18bd.apps.googleusercontent.com"
)


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title="Task Manager API",
    version="1.0.0",
)


# ============================================================
# PASSWORD HASHING
# ============================================================

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


# ============================================================
# AUTHENTICATION
# ============================================================

security = HTTPBearer()


# ============================================================
# DATABASE
# ============================================================

def get_db():
    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def initialize_database():

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL,
            google_id TEXT,
            name TEXT,
            password_hash TEXT
        )
        """
    )

    connection.commit()

    connection.close()


# ============================================================
# DATABASE MIGRATION
# ============================================================

def migrate_database():

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        "PRAGMA table_info(users)"
    )

    columns = [
        row["name"]
        for row in cursor.fetchall()
    ]

    print(
        "Existing database columns:",
        columns,
    )

    # --------------------------------------------------------
    # password
    # --------------------------------------------------------

    if "password" not in columns:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN password TEXT
            """
        )

        print(
            "Added missing column: password"
        )

    # --------------------------------------------------------
    # password_hash
    # --------------------------------------------------------

    if "password_hash" not in columns:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN password_hash TEXT
            """
        )

        print(
            "Added missing column: password_hash"
        )

    # --------------------------------------------------------
    # google_id
    # --------------------------------------------------------

    if "google_id" not in columns:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN google_id TEXT
            """
        )

        print(
            "Added missing column: google_id"
        )

    # --------------------------------------------------------
    # name
    # --------------------------------------------------------

    if "name" not in columns:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN name TEXT
            """
        )

        print(
            "Added missing column: name"
        )

    # --------------------------------------------------------
    # created_at
    # --------------------------------------------------------

    if "created_at" not in columns:

        cursor.execute(
            """
            ALTER TABLE users
            ADD COLUMN created_at TEXT
            """
        )

        print(
            "Added missing column: created_at"
        )

    connection.commit()

    connection.close()

    print(
        "Database migration completed successfully."
    )


# Run database setup
initialize_database()

migrate_database()


# ============================================================
# REQUEST MODELS
# ============================================================

class RegisterRequest(BaseModel):

    email: EmailStr

    password: str


class LoginRequest(BaseModel):

    email: EmailStr

    password: str


class RefreshRequest(BaseModel):

    refresh_token: str


class GoogleLoginRequest(BaseModel):

    id_token: str


# ============================================================
# PASSWORD FUNCTIONS
# ============================================================

def hash_password(password: str) -> str:

    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> bool:

    return pwd_context.verify(
        plain_password,
        hashed_password,
    )


# ============================================================
# JWT FUNCTIONS
# ============================================================

def create_access_token(
    email: str,
):

    expire = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    )

    payload = {
        "sub": email,
        "type": "access",
        "exp": expire,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def create_refresh_token(
    email: str,
):

    expire = (
        datetime.now(timezone.utc)
        + timedelta(
            days=REFRESH_TOKEN_EXPIRE_DAYS
        )
    )

    payload = {
        "sub": email,
        "type": "refresh",
        "exp": expire,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_token(
    token: str,
):

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        return payload

    except JWTError:

        return None


def token_response(
    email: str,
):

    return {
        "access_token": create_access_token(
            email
        ),
        "refresh_token": create_refresh_token(
            email
        ),
        "token_type": "bearer",
    }


# ============================================================
# REGISTER
# ============================================================

@app.post("/register")
def register(
    request: RegisterRequest,
):

    email = (
        request.email
        .lower()
        .strip()
    )

    password = request.password

    # --------------------------------------------------------
    # VALIDATE PASSWORD
    # --------------------------------------------------------

    if len(password) < 6:

        raise HTTPException(
            status_code=400,
            detail=(
                "Password must contain "
                "at least 6 characters."
            ),
        )

    connection = get_db()

    cursor = connection.cursor()

    # --------------------------------------------------------
    # CHECK EXISTING USER
    # --------------------------------------------------------

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (email,),
    )

    existing_user = cursor.fetchone()

    if existing_user:

        connection.close()

        raise HTTPException(
            status_code=400,
            detail="User already exists.",
        )

    # --------------------------------------------------------
    # HASH PASSWORD
    # --------------------------------------------------------

    password_hash = hash_password(
        password
    )

    created_at = (
        datetime.now(timezone.utc)
        .isoformat()
    )

    # --------------------------------------------------------
    # INSERT USER
    #
    # IMPORTANT:
    # Your old database has a NOT NULL `password`
    # column, so we populate BOTH password and
    # password_hash.
    #
    # `password` stores the same hash, NOT the
    # user's plain-text password.
    # --------------------------------------------------------

    cursor.execute(
        """
        INSERT INTO users
        (
            email,
            password,
            password_hash,
            google_id,
            name,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            email,
            password_hash,
            password_hash,
            None,
            None,
            created_at,
        ),
    )

    connection.commit()

    connection.close()

    return {
        "message": "User registered successfully."
    }


# ============================================================
# NORMAL LOGIN
# ============================================================

@app.post("/login")
def login(
    request: LoginRequest,
):

    email = (
        request.email
        .lower()
        .strip()
    )

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,),
    )

    user = cursor.fetchone()

    connection.close()

    # --------------------------------------------------------
    # USER NOT FOUND
    # --------------------------------------------------------

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    # --------------------------------------------------------
    # GET PASSWORD HASH
    #
    # New users use password_hash.
    #
    # Older users may only have password.
    # --------------------------------------------------------

    password_hash = None

    if "password_hash" in user.keys():

        password_hash = user["password_hash"]

    if not password_hash:

        if "password" in user.keys():

            password_hash = user["password"]

    # --------------------------------------------------------
    # GOOGLE-ONLY ACCOUNT
    # --------------------------------------------------------

    if not password_hash:

        if user["google_id"]:

            raise HTTPException(
                status_code=401,
                detail=(
                    "This account uses "
                    "Google Sign-In."
                ),
            )

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    # --------------------------------------------------------
    # VERIFY PASSWORD
    # --------------------------------------------------------

    try:

        password_valid = verify_password(
            request.password,
            password_hash,
        )

    except Exception:

        password_valid = False

    if not password_valid:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password.",
        )

    # --------------------------------------------------------
    # RETURN JWT TOKENS
    # --------------------------------------------------------

    return token_response(
        email
    )


# ============================================================
# GOOGLE LOGIN
# ============================================================

@app.post("/google-login")
def google_login(
    request: GoogleLoginRequest,
):

    print(
        "\n========== GOOGLE LOGIN =========="
    )

    # ========================================================
    # 1. VERIFY GOOGLE ID TOKEN
    # ========================================================

    try:

        google_info = (
            id_token.verify_oauth2_token(
                request.id_token,
                requests.Request(),
                GOOGLE_WEB_CLIENT_ID,
            )
        )

    except ValueError as error:

        print(
            "Google token verification failed:",
            error,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid Google ID token.",
        )

    # ========================================================
    # 2. EXTRACT GOOGLE INFORMATION
    # ========================================================

    google_id = google_info.get(
        "sub"
    )

    email = google_info.get(
        "email"
    )

    name = google_info.get(
        "name"
    )

    email_verified = google_info.get(
        "email_verified",
        False,
    )

    print(
        "Google email:",
        email,
    )

    print(
        "Google name:",
        name,
    )

    print(
        "Google email verified:",
        email_verified,
    )

    # ========================================================
    # 3. VALIDATE GOOGLE DATA
    # ========================================================

    if not google_id:

        raise HTTPException(
            status_code=401,
            detail="Google ID is missing.",
        )

    if not email:

        raise HTTPException(
            status_code=401,
            detail="Google email is missing.",
        )

    if not email_verified:

        raise HTTPException(
            status_code=401,
            detail=(
                "Google email is not verified."
            ),
        )

    email = (
        email
        .lower()
        .strip()
    )

    # ========================================================
    # 4. OPEN DATABASE
    # ========================================================

    connection = get_db()

    cursor = connection.cursor()

    # ========================================================
    # 5. FIND USER BY EMAIL
    # ========================================================

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE email = ?
        """,
        (email,),
    )

    user = cursor.fetchone()

    # ========================================================
    # 6. EXISTING USER
    # ========================================================

    if user:

        print(
            "Existing user found:",
            email,
        )

        cursor.execute(
            """
            UPDATE users
            SET
                google_id = ?,
                name = ?
            WHERE email = ?
            """,
            (
                google_id,
                name,
                email,
            ),
        )

        print(
            "Existing user linked with Google."
        )

    # ========================================================
    # 7. NEW GOOGLE USER
    # ========================================================

    else:

        print(
            "Creating new Google user:",
            email,
        )

        created_at = (
            datetime.now(timezone.utc)
            .isoformat()
        )

        # IMPORTANT:
        #
        # Your old SQLite table contains:
        #
        # password TEXT NOT NULL
        #
        # Google users don't have a normal password.
        #
        # Therefore we insert an empty string into the
        # legacy password column.
        #
        # We do NOT store the Google password.
        #
        # The Google ID is stored in google_id.

        cursor.execute(
            """
            INSERT INTO users
            (
                email,
                password,
                password_hash,
                google_id,
                name,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                "",
                None,
                google_id,
                name,
                created_at,
            ),
        )

        print(
            "New Google user created."
        )

    # ========================================================
    # 8. SAVE DATABASE
    # ========================================================

    connection.commit()

    connection.close()

    print(
        "Google user database operation successful."
    )

    # ========================================================
    # 9. CREATE OUR APPLICATION JWT TOKENS
    # ========================================================

    tokens = token_response(
        email
    )

    print(
        "Application JWT tokens created."
    )

    print(
        "========== GOOGLE LOGIN SUCCESS ==========\n"
    )

    return tokens


# ============================================================
# REFRESH ACCESS TOKEN
# ============================================================

@app.post("/refresh")
def refresh(
    request: RefreshRequest,
):

    # --------------------------------------------------------
    # DECODE REFRESH TOKEN
    # --------------------------------------------------------

    payload = decode_token(
        request.refresh_token
    )

    if not payload:

        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid or expired "
                "refresh token."
            ),
        )

    # --------------------------------------------------------
    # CHECK TOKEN TYPE
    # --------------------------------------------------------

    if payload.get("type") != "refresh":

        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token.",
        )

    # --------------------------------------------------------
    # GET EMAIL
    # --------------------------------------------------------

    email = payload.get(
        "sub"
    )

    if not email:

        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token.",
        )

    # --------------------------------------------------------
    # CHECK USER EXISTS
    # --------------------------------------------------------

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM users
        WHERE email = ?
        """,
        (email,),
    )

    user = cursor.fetchone()

    connection.close()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="User no longer exists.",
        )

    # --------------------------------------------------------
    # CREATE NEW ACCESS TOKEN
    # --------------------------------------------------------

    return {
        "access_token": create_access_token(
            email
        ),
        "token_type": "bearer",
    }


# ============================================================
# CURRENT USER
# ============================================================

@app.get("/me")
def get_current_user(
    credentials: HTTPAuthorizationCredentials =
    Depends(security),
):

    token = credentials.credentials

    # --------------------------------------------------------
    # DECODE TOKEN
    # --------------------------------------------------------

    payload = decode_token(
        token
    )

    if not payload:

        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid or expired "
                "access token."
            ),
        )

    # --------------------------------------------------------
    # CHECK TOKEN TYPE
    # --------------------------------------------------------

    if payload.get("type") != "access":

        raise HTTPException(
            status_code=401,
            detail="Invalid access token.",
        )

    # --------------------------------------------------------
    # GET EMAIL
    # --------------------------------------------------------

    email = payload.get(
        "sub"
    )

    if not email:

        raise HTTPException(
            status_code=401,
            detail="Invalid access token.",
        )

    # --------------------------------------------------------
    # GET USER
    # --------------------------------------------------------

    connection = get_db()

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            email,
            name,
            google_id
        FROM users
        WHERE email = ?
        """,
        (email,),
    )

    user = cursor.fetchone()

    connection.close()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found.",
        )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {
        "message": "Authenticated successfully",
        "email": user["email"],
        "name": user["name"],
        "google_user": bool(
            user["google_id"]
        ),
    }


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():

    return {
        "message": "Task Manager API is running",
        "status": "online",
    }