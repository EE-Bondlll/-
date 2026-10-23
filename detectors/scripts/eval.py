"""质量评估：对 testbed 全量跑检测管线，计算 recall / fp_rate，输出报告。

用法：
    python scripts/eval.py            # 全量（含 testssl，约 10~20 分钟）
    python scripts/eval.py --quick    # 跳过 testssl，日常迭代用
"""
import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.schemas import Asset, ScanConfig, ScanRequest
from app.detectors.vuln import run_vuln
from app.detectors.malware import run_malware
from app.detectors.tamper import run_tamper
from app.detectors.tls import run_tls
from app.utils.baseline import BaselineStore

EXPECTED_FILE = ROOT / "testbed" / "expected_results.json"
REPORT_FILE = ROOT / "eval_report.json"

GATE_RECALL = 0.90
GATE_FP = 0.10

TAMPER_CONTAINER = "tb-tamper"
TAMPER_HTML = "/usr/share/nginx/html/index.html"


def _docker(*args):
    subprocess.run(["docker", "exec", TAMPER_CONTAINER, *args], check=True)


def run_pipeline(assets, config, quick=False):
    """跑全部检测器，返回 (records, errors)。tamper 做 基线→注入→复扫→还原。"""
    records, errors = [], []

    def safe(name, fn):
        try:
            records.extend(fn())
        except Exception as e:
            errors.append(f"{name}: {type(e).__name__}: {e}")

    def _vuln():
        resp = run_vuln(ScanRequest(assets=assets, config=config))
        return list(resp.risks)

    safe("vuln", _vuln)
    safe("malware", lambda: run_malware(assets, config))
    if not quick:
        safe("tls", lambda: run_tls(assets, config))

    # tamper：先基线，再注入，再复扫，最后还原
    store = BaselineStore()
    try:
        original = subprocess.run(
            ["docker", "exec", TAMPER_CONTAINER, "cat", TAMPER_HTML],
            capture_output=True, text=True, check=True).stdout
        for a in assets:
            store.remove(a.url)
        safe("tamper-baseline", lambda: run_tamper(assets, config, store))
        _docker("sh", "-c",
                f"echo '<iframe src=\"http://evil.example/x\" style=\"display:none\"></iframe>' >> {TAMPER_HTML}")
        safe("tamper-rescan", lambda: run_tamper(assets, config, store))
    except Exception as e:
        errors.append(f"tamper-setup: {e}")
    finally:
        try:
            _docker("sh", "-c", f"cat > {TAMPER_HTML} << 'PAGE'\n{original}\nPAGE")
        except Exception:
            pass
    return records, errors


def match_record(rec, url, category, needle):
    if not rec.asset_url.startswith(url):
        return False
    if str(rec.category) != category and getattr(rec.category, "value", "") != category:
        return False
    haystack = f"{rec.raw_output or ''}{rec.description or ''}{rec.template or ''}"
    return needle in haystack


def main():
    quick = "--quick" in sys.argv
    expected = json.loads(EXPECTED_FILE.read_text(encoding="utf-8"))["targets"]
    if quick:
        expected = [t for t in expected if not t["url"].startswith("https")]
    assets = [
    Asset(
        url=t["url"],
        host=urlparse(t["url"]).netloc,
        fingerprint=t.get("fingerprint", {}),   # 新增这一行
    )
    for t in expected
    ]
    config = ScanConfig()

    print(f"[1/3] 跑检测管线（quick={quick}）...")
    records, errors = run_pipeline(assets, config, quick=quick)
    print(f"      共 {len(records)} 条记录" + (f"，{len(errors)} 个环节出错" if errors else ""))
    for e in errors:
        print(f"      ! {e}")

    print("[2/3] 对账...")
    tp, fn_list, fp_list, unlisted = 0, [], [], []

    def _target_records(url):
        return [r for r in records if r.asset_url.startswith(url)]

    for t in expected:
        matched_ids = set()
        for exp in t["expected"]:
            hit_idx = [i for i, r in enumerate(_target_records(t["url"]))
                       if match_record(r, t["url"], exp["category"], exp["match"])]
            if hit_idx:
                tp += 1
                matched_ids.update(hit_idx)
            else:
                fn_list.append({"target": t["url"], **exp})

        recs = _target_records(t["url"])
        if t.get("clean"):
            fp_list += [{"target": t["url"], "title": r.title, "category": str(r.category)}
                        for r in recs]
        else:
            for i, r in enumerate(recs):
                if i in matched_ids:
                    continue
                is_known_fp = any(match_record(r, t["url"], k["category"], k["match"])
                                  for k in t.get("known_fp", []))
                if is_known_fp:
                    fp_list.append({"target": t["url"], "title": r.title, "category": str(r.category)})
                else:
                    unlisted.append({"target": t["url"], "title": r.title})   # 真发现，只是没列进 checklist

    total_expected = sum(len(t["expected"]) for t in expected)
    recall = tp / total_expected if total_expected else 1.0
    fp_rate = len(fp_list) / (len(fp_list) + tp) if (len(fp_list) + tp) else 0.0

    print("[3/3] 报告")
    print(f"  预期 {total_expected} 条，命中 {tp}，漏报 {len(fn_list)}，误报 {len(fp_list)}")
    print(f"  recall = {recall:.1%}（门槛 {GATE_RECALL:.0%}）")
    print(f"  fp_rate = {fp_rate:.1%}（门槛 {GATE_FP:.0%}）")
    if fn_list:
        print("  漏报明细：")
        for x in fn_list:
            print(f"    - {x['target']} [{x['category']}] {x['match']}")
    if fp_list:
        print("  误报明细：")
        for x in fp_list:
            print(f"    - {x['target']} [{x['category']}] {x['title']}")

    REPORT_FILE.write_text(json.dumps({
        "recall": recall, "fp_rate": fp_rate, "tp": tp,
        "missed": fn_list, "false_positives": fp_list, "errors": errors,
        "records_total": len(records),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  报告已写入 {REPORT_FILE}")

    ok = recall >= GATE_RECALL and fp_rate <= GATE_FP and not errors
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()