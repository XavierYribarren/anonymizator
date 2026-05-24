"""Desktop launcher — starts the web server and opens the browser automatically.

Usage:
    python researcher_app.py

For server/VPS deployment (no browser auto-open):
    uvicorn web.main:app --host 0.0.0.0 --port 8000
"""
import threading
import time
import webbrowser

import uvicorn


def _open_browser():
    time.sleep(1.2)  # Give the server time to start
    webbrowser.open("http://localhost:8000")


threading.Thread(target=_open_browser, daemon=True).start()
uvicorn.run("web.main:app", host="127.0.0.1", port=8000, log_level="warning")
