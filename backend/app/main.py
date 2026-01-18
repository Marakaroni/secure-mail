from fastapi import FastAPI

app = FastAPI(title="secure-mail")

@app.get("/health")
def health():
    return {"status": "ok"}
