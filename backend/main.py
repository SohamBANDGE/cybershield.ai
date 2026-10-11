import os, sqlite3, time
from collections import defaultdict, deque
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from analyzer import analyze_message, analyze_url

DB = os.getenv("DB_PATH", "cybershield.db")
ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
RATE, WINDOW = int(os.getenv("RATE_LIMIT", "30")), 60
hits = defaultdict(deque)

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

with db() as c:  # privacy: we store scores only, never the submitted text
    c.execute("CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, kind TEXT, score INT, label TEXT, ts REAL, correct INT)")

app = FastAPI(title="CyberShield AI")
app.add_middleware(CORSMiddleware, allow_origins=ORIGINS, allow_methods=["GET", "POST"], allow_headers=["*"])

@app.middleware("http")
async def limiter(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
        q, now = hits[ip], time.time()
        while q and now - q[0] > WINDOW: q.popleft()
        if len(q) >= RATE:
            return JSONResponse({"detail": "Too many requests. Wait a minute and try again."}, status_code=429)
        q.append(now)
    resp = await call_next(request)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"})
    return resp

class Scan(BaseModel):
    text: str = Field(min_length=3, max_length=5000)

class Feedback(BaseModel):
    id: int
    correct: bool

def record(kind, res):
    with db() as c:
        cur = c.execute("INSERT INTO scans(kind,score,label,ts) VALUES(?,?,?,?)", (kind, res["score"], res["label"], time.time()))
    return {**res, "id": cur.lastrowid, "kind": kind}

@app.post("/api/analyze/url")
def url(b: Scan): return record("url", analyze_url(b.text))

@app.post("/api/analyze/message")
def message(b: Scan): return record("message", analyze_message(b.text))

@app.post("/api/feedback")
def feedback(b: Feedback):
    with db() as c:
        if not c.execute("UPDATE scans SET correct=? WHERE id=?", (int(b.correct), b.id)).rowcount:
            raise HTTPException(404, "Scan not found")
    return {"ok": True}

@app.get("/api/stats")
def stats():
    with db() as c:
        r = c.execute("SELECT COUNT(*) n, SUM(label='dangerous') d, SUM(correct=1) ok, SUM(correct=0) bad FROM scans").fetchone()
    return {"scans": r["n"], "dangerous": r["d"] or 0, "marked_correct": r["ok"] or 0, "marked_wrong": r["bad"] or 0}

@app.get("/health")
def health(): return {"status": "ok"}

app.mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "..", "frontend"), html=True), name="ui")
