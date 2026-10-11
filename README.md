# CyberShield AI
FastAPI + React + SQLite. One service serves the API and the UI.

Run locally:  `pip install -r requirements.txt && cd backend && uvicorn main:app --reload`  then open http://localhost:8000
Docker:       `docker build -t cybershield . && docker run -p 8000:8000 -v cs:/data cybershield`
Deploy:       push to GitHub, create a Web Service on Render/Railway/Fly.io from the Dockerfile, mount a volume at /data.
Env vars:     ALLOWED_ORIGINS, RATE_LIMIT (requests/min/IP, default 30), DB_PATH
API docs:     /docs
