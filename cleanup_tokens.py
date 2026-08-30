from datetime import datetime, timezone
from sqlalchemy import or_
from database import SessionLocal
from models import RefreshToken


def cleanup_expired_tokens() -> int:
    db = SessionLocal()
    try:
        deleted = (
            db.query(RefreshToken)
            .filter(or_(RefreshToken.expires_at < datetime.now(timezone.utc), RefreshToken.revoked.is_(True)))
            .delete(synchronize_session=False)
        )
        db.commit()
        return deleted
    finally:
        db.close()


if __name__ == "__main__":
    count = cleanup_expired_tokens()
    print(f"Deleted {count} refresh token row(s)")
