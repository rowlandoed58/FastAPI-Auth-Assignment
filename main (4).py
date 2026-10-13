from datetime import datetime, timedelta, timezone
from typing import List, Literal, Optional

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict
from sqlalchemy import (JSON, Boolean, Column, DateTime, Integer, String, Text,
                        create_engine, or_)
from sqlalchemy.orm import Session, declarative_base, sessionmaker


# SETTINGS

SECRET_KEY = "change-this-to-a-long-random-string"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# DATABASE (SQLite + SQLAlchemy)

engine = create_engine("sqlite:///./app.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()


class UserDB(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    full_name = Column(String, nullable=True)
    hashed_password = Column(String, nullable=False)
    disabled = Column(Boolean, default=False)
    role = Column(String, default="user")


class NoteDB(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    owner = Column(String, index=True, nullable=False)  # username
    is_public = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tags = Column(JSON, default=list)


Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# SCHEMAS (what the API accepts and returns)

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None
    role: Literal["admin", "editor", "user"] = "user"


class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str
    email: str
    full_name: Optional[str] = None
    disabled: bool
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str


class NoteCreate(BaseModel):
    title: str
    content: str
    is_public: bool = False
    tags: Optional[List[str]] = None


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    is_public: Optional[bool] = None
    tags: Optional[List[str]] = None


class NoteOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    title: str
    content: str
    owner: str
    is_public: bool
    created_at: datetime
    tags: Optional[List[str]] = None



# SECURITY (hashing + JWT)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)



# DEPENDENCIES

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserDB:
    """Reads the token and returns the logged-in user."""
    bad_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise bad_credentials

    if username is None:
        raise bad_credentials

    user = db.query(UserDB).filter(UserDB.username == username).first()
    if user is None:
        raise bad_credentials
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")
    return user


def get_admin_user(current_user: UserDB = Depends(get_current_user)) -> UserDB:
    """Only lets admins through."""
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


def get_note_owner_or_admin(
    note_id: int,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> NoteDB:
    """Returns the note only if the user owns it or is an admin."""
    note = db.get(NoteDB, note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    if note.owner != current_user.username and current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to modify this note")
    return note



# APP

app = FastAPI(title="FastAPI Auth Assignment")


# ------------------------- AUTH --------------------------------
@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserDB).filter(UserDB.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(UserDB).filter(UserDB.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = UserDB(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hash_password(user.password),
        role=user.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    if user is None or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user.disabled:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Inactive user")

    token = create_access_token(user.username)
    return {"access_token": token, "token_type": "bearer"}


# ------------------------- USERS -------------------------------
@app.get("/users/me", response_model=UserOut)
def read_me(current_user: UserDB = Depends(get_current_user)):
    return current_user


@app.get("/users/", response_model=List[UserOut])
def list_users(admin: UserDB = Depends(get_admin_user), db: Session = Depends(get_db)):
    return db.query(UserDB).all()


@app.put("/users/me", response_model=UserOut)
def update_me(
    update: UserUpdate,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    data = update.model_dump(exclude_unset=True)

    if "email" in data and data["email"] != current_user.email:
        if db.query(UserDB).filter(UserDB.email == data["email"]).first():
            raise HTTPException(status_code=400, detail="Email already registered")
        current_user.email = data["email"]

    if "full_name" in data:
        current_user.full_name = data["full_name"]

    if data.get("password"):
        current_user.hashed_password = hash_password(data["password"])

    db.commit()
    db.refresh(current_user)
    return current_user


@app.delete("/users/me", status_code=status.HTTP_204_NO_CONTENT)
def delete_me(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db.query(NoteDB).filter(NoteDB.owner == current_user.username).delete()
    db.delete(current_user)
    db.commit()


# ------------------------- NOTES -------------------------------
@app.post("/notes/", response_model=NoteOut, status_code=status.HTTP_201_CREATED)
def create_note(
    note: NoteCreate,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    new_note = NoteDB(
        title=note.title,
        content=note.content,
        owner=current_user.username,
        is_public=note.is_public,
        tags=note.tags or [],
    )
    db.add(new_note)
    db.commit()
    db.refresh(new_note)
    return new_note


@app.get("/notes/", response_model=List[NoteOut])
def list_notes(
    tag: Optional[str] = None,
    search_term: Optional[str] = None,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = db.query(NoteDB)

    # Regular users see their own notes + public notes. Admins see everything.
    if current_user.role != "admin":
        query = query.filter(or_(NoteDB.owner == current_user.username, NoteDB.is_public.is_(True)))

    if search_term:
        like = f"%{search_term}%"
        query = query.filter(or_(NoteDB.title.ilike(like), NoteDB.content.ilike(like)))

    notes = query.order_by(NoteDB.created_at.desc()).all()

    if tag:
        notes = [n for n in notes if tag in (n.tags or [])]

    return notes


@app.get("/notes/{note_id}", response_model=NoteOut)
def get_note(
    note_id: int,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    note = db.get(NoteDB, note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")

    allowed = (
        note.is_public
        or note.owner == current_user.username
        or current_user.role == "admin"
    )
    if not allowed:
        raise HTTPException(status_code=403, detail="Not allowed to view this note")
    return note


@app.put("/notes/{note_id}", response_model=NoteOut)
def update_note(
    update: NoteUpdate,
    note: NoteDB = Depends(get_note_owner_or_admin),
    db: Session = Depends(get_db),
):
    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(note, field, value)
    db.commit()
    db.refresh(note)
    return note


@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(note: NoteDB = Depends(get_note_owner_or_admin), db: Session = Depends(get_db)):
    db.delete(note)
    db.commit()
