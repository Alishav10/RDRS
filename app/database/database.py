from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.core.config import config


# Project root directory
BASE_DIR = Path(__file__).resolve().parents[2]


# Database path from config.yaml
database_path = BASE_DIR / config["database"]["path"]

# Make sure the data directory exists
database_path.parent.mkdir(parents=True, exist_ok=True)


# SQLite connection
DATABASE_URL = f"sqlite:///{database_path}"


# Create SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


# Session factory
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


# Base class for database models
class Base(DeclarativeBase):
    pass


def get_db():
    """
    Create a database session.

    The session is automatically closed when finished.
    """
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()