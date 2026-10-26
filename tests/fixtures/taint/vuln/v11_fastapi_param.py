import subprocess

from fastapi import FastAPI

app = FastAPI()


@app.get("/ping")
def ping(host: str):
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)  # SINK command
