import uuid
from fastapi import FastAPI
from app.schemas import ScanRequest, ScanResponse, DiscoveryResponse
from app.detectors.tamper import run_tamper
from app.utils.baseline import BaselineStore
from fastapi import HTTPException
from app.detectors.malware import run_malware
from app.detectors.tls import run_tls

app = FastAPI(title="secbot-detector", version="0.1.0")

@app.get("/health")
def health():
    import shutil
    tools = ["subfinder", "httpx", "katana", "gobuster",
             "nuclei", "whatweb", "wpscan", "testssl"]
    return {"status": "ok",
            "tools": {t: (shutil.which(t) is not None) for t in tools}}

from app.detectors.discovery import run_discovery

@app.post("/scan/discovery", response_model=DiscoveryResponse)
def scan_discovery(req: ScanRequest):
    return run_discovery(req)
    
from app.detectors.vuln import run_vuln

@app.post("/scan/vuln", response_model=ScanResponse)
def scan_vuln(req: ScanRequest):
    return run_vuln(req)

@app.post("/scan/tamper")
def scan_tamper(req: ScanRequest):
    risks = run_tamper(req.assets, req.config)
    return ScanResponse(job_id=str(uuid.uuid4()), count=len(risks), risks=risks)

@app.delete("/baselines")
def reset_baseline(url: str):
    """复测用：删除某 URL 的基线，使其下一次扫描重新建档。"""
    BaselineStore().remove(url)
    return {"url": url, "reset": True}

@app.post("/scan/malware")
def scan_malware(req: ScanRequest):
    risks = run_malware(req.assets, req.config)
    return ScanResponse(job_id=str(uuid.uuid4()), count=len(risks), risks=risks)

@app.post("/scan/tls")
def scan_tls(req: ScanRequest):
    risks = run_tls(req.assets, req.config)
    return ScanResponse(job_id=str(uuid.uuid4()), count=len(risks), risks=risks)