"""
VACP Production Entry Point

Usage:
    python -m vacp.main
    # or
    uvicorn vacp.main:app --host 0.0.0.0 --port 8000
"""

import os
from pathlib import Path

# Set storage path before importing server
STORAGE_PATH = Path(os.getenv("VACP_STORAGE_PATH", "./vacp_data"))
STORAGE_PATH.mkdir(parents=True, exist_ok=True)

from vacp.api.server import create_app

# Create the app - demo mode disabled by default for security
# Set DEMO_MODE=true to enable demo data and endpoints
demo_mode = os.getenv("DEMO_MODE", "false").lower() in ("true", "1", "yes")

app = create_app(
    storage_path=STORAGE_PATH,
    demo_mode=demo_mode,
    jwt_secret=os.getenv("JWT_SECRET", None),
)

if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")

    print(f"Starting VACP server on {host}:{port}")
    print(f"Storage path: {STORAGE_PATH}")

    uvicorn.run(
        app,  # Pass app directly instead of string to avoid reload issues
        host=host,
        port=port,
    )
