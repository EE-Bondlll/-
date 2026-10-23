import uuid
from app.schemas import ScanRequest, ScanResponse
from app.adapters.nuclei import NucleiAdapter
from app.adapters.wpscan import WpscanAdapter
from app.adapters.headers import HeadersAdapter

def run_vuln(req: ScanRequest) -> ScanResponse:
    nuclei, wpscan, headers = NucleiAdapter(), WpscanAdapter(), HeadersAdapter()
    risks = []
    for asset in req.assets:
        # 1. nuclei 通用漏洞 + 弱配置（容错：单资产失败不中断整轮）
        try:
            risks += nuclei.run(asset, req.config)
        except Exception:
            pass
        # 2. wpscan：仅 WordPress 资产
        if asset.fingerprint.get("cms") == "wordpress":
            try:
                risks += wpscan.run_wp(asset, req.config)
            except Exception:
                pass
        # 3. 安全头：所有资产
        try:
            risks += headers.check(asset, req.config)
        except Exception:
            pass
    return ScanResponse(job_id=str(uuid.uuid4()), risks=risks)