from fastapi import FastAPI
from routes.incidents import router as incidents_router
from routes.receipts import router as receipts_router

app = FastAPI(
    title="Observable Incident Agent",
    version="2.0.0"
)

# Register API routes
app.include_router(incidents_router)
app.include_router(receipts_router)


@app.get("/")
def home():
    return {
        "message": "Observable Incident Agent is running"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }
