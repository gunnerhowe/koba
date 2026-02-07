"""
Database Migration Utilities

Helper functions for running and managing database migrations.
"""

import sys
import asyncio
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from alembic.config import Config
from alembic import command
from sqlalchemy import text


def get_alembic_config() -> Config:
    """Get Alembic configuration."""
    # Find alembic.ini relative to this file
    ini_path = Path(__file__).parent.parent / "alembic.ini"
    if not ini_path.exists():
        raise FileNotFoundError(f"alembic.ini not found at {ini_path}")

    config = Config(str(ini_path))
    # Set script location explicitly
    config.set_main_option("script_location", str(Path(__file__).parent))
    return config


def run_upgrade(revision: str = "head") -> None:
    """
    Run database migrations up to specified revision.

    Args:
        revision: Target revision (default: "head" for latest)
    """
    config = get_alembic_config()
    command.upgrade(config, revision)
    print(f"Upgraded to revision: {revision}")


def run_downgrade(revision: str = "-1") -> None:
    """
    Downgrade database by specified amount.

    Args:
        revision: Target revision or relative (default: "-1" for one step back)
    """
    config = get_alembic_config()
    command.downgrade(config, revision)
    print(f"Downgraded to revision: {revision}")


def show_current_revision() -> None:
    """Show current database revision."""
    config = get_alembic_config()
    command.current(config)


def show_history() -> None:
    """Show migration history."""
    config = get_alembic_config()
    command.history(config)


def create_revision(message: str, autogenerate: bool = True) -> None:
    """
    Create a new migration revision.

    Args:
        message: Revision message/description
        autogenerate: Whether to autogenerate from model changes
    """
    config = get_alembic_config()
    command.revision(config, message=message, autogenerate=autogenerate)


async def init_database(create_tables: bool = True) -> None:
    """
    Initialize database with migrations or direct table creation.

    Args:
        create_tables: If True, create tables directly (dev mode).
                      If False, use migrations (production mode).
    """
    from vacp.core.database import get_db, Base

    db = get_db()

    if create_tables:
        # Development: Create tables directly
        async with db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        print("Database tables created directly")
    else:
        # Production: Use migrations
        run_upgrade("head")
        print("Database migrated to latest version")


async def reset_database() -> None:
    """
    Reset database by dropping all tables and recreating.

    WARNING: This will delete all data!
    """
    from vacp.core.database import get_db, Base

    db = get_db()

    async with db.engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    print("Database reset complete")


async def check_database_health() -> dict:
    """
    Check database connectivity and migration status.

    Returns:
        Health check results
    """
    from vacp.core.database import get_db

    db = get_db()
    results = {
        "connected": False,
        "tables_exist": False,
        "table_count": 0,
        "error": None,
    }

    try:
        async with db.get_session() as session:
            # Test connectivity
            await session.execute(text("SELECT 1"))
            results["connected"] = True

            # Check for tables (SQLite)
            result = await session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            tables = [row[0] for row in result.fetchall()]
            results["table_count"] = len(tables)
            results["tables_exist"] = "tenants" in tables

    except Exception as e:
        results["error"] = str(e)

    return results


# CLI interface
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Database migration utilities")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # upgrade
    upgrade_parser = subparsers.add_parser("upgrade", help="Run migrations")
    upgrade_parser.add_argument(
        "--revision", default="head", help="Target revision (default: head)"
    )

    # downgrade
    downgrade_parser = subparsers.add_parser("downgrade", help="Rollback migrations")
    downgrade_parser.add_argument(
        "--revision", default="-1", help="Target revision (default: -1)"
    )

    # current
    subparsers.add_parser("current", help="Show current revision")

    # history
    subparsers.add_parser("history", help="Show migration history")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize database")
    init_parser.add_argument(
        "--migrate",
        action="store_true",
        help="Use migrations instead of direct table creation",
    )

    # reset
    subparsers.add_parser("reset", help="Reset database (WARNING: deletes all data)")

    # health
    subparsers.add_parser("health", help="Check database health")

    # revision
    rev_parser = subparsers.add_parser("revision", help="Create new migration")
    rev_parser.add_argument("message", help="Revision message")
    rev_parser.add_argument(
        "--no-autogenerate",
        action="store_true",
        help="Don't autogenerate from models",
    )

    args = parser.parse_args()

    if args.command == "upgrade":
        run_upgrade(args.revision)
    elif args.command == "downgrade":
        run_downgrade(args.revision)
    elif args.command == "current":
        show_current_revision()
    elif args.command == "history":
        show_history()
    elif args.command == "init":
        asyncio.run(init_database(create_tables=not args.migrate))
    elif args.command == "reset":
        confirm = input("This will DELETE ALL DATA. Type 'yes' to confirm: ")
        if confirm.lower() == "yes":
            asyncio.run(reset_database())
        else:
            print("Aborted")
    elif args.command == "health":
        result = asyncio.run(check_database_health())
        for key, value in result.items():
            print(f"{key}: {value}")
    elif args.command == "revision":
        create_revision(args.message, autogenerate=not args.no_autogenerate)
    else:
        parser.print_help()
