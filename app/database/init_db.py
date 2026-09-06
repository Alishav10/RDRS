from app.database.database import Base, engine
from app.database import models


def initialize_database():
    """
    Create all RDRS database tables.
    """

    Base.metadata.create_all(bind=engine)

    print("RDRS database initialized successfully.")
    print(f"Database tables: {list(Base.metadata.tables.keys())}")


if __name__ == "__main__":
    initialize_database()