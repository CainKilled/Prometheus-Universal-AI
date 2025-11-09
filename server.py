from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import json
import os

app = FastAPI()
MEMORY_PATH = "../memory/codex_embeddings.json"

class MemoryEntry(BaseModel):
    key: str
    value: str

@app.get("/")
def read_root():
    return {"status": "Prometheus HAL API Online"}

@app.get("/memory/{key}")
def get_memory(key: str):
    if not os.path.exists(MEMORY_PATH):
        raise HTTPException(status_code=404, detail="Memory file not found")
    with open(MEMORY_PATH, "r") as f:
        memory = json.load(f)
    return {"value": memory.get(key, "Not Found")}

@app.post("/memory")
def insert_memory(entry: MemoryEntry):
    memory = {}
    if os.path.exists(MEMORY_PATH):
        with open(MEMORY_PATH, "r") as f:
            memory = json.load(f)
    memory[entry.key] = entry.value
    with open(MEMORY_PATH, "w") as f:
        json.dump(memory, f, indent=4)
    return {"status": "inserted", "key": entry.key}

@app.get("/hal/ping")
def hal_ping():
    return {"hal": "online", "mode": "bound", "authority": "Adam Henry Nagle"}
