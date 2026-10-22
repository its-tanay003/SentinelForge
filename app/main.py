"""SentinelForge - Main FastAPI Application."""
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks, Request
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.config import settings
from app.db import get_db, init_db
from app.models import Scan, Finding, IntelResult, RiskItem, Incident

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelforge")

# ── App bootstrap ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="SentinelForge",
    description=(
        "Automated Web Security Posture, Threat-Intel & Response Platform. "
        "⚠️ FOR AUTHORIZED TESTING ONLY."
    ),
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Static files & templates
_static_dir = Path(__file__).parent / "static"
_templates_dir = Path(__file__).parent / "templates"

app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")
templates = Jinja2Templates(directory=str(_templates_dir))


@app.on_event("startup")
async def startup():
    init_db()
    logger.info(f"SentinelForge {settings.APP_VERSION} started.")
    logger.info("⚠️  ETHICAL NOTICE: Only scan systems you own or are authorized to test.")


# ── Pydantic schemas ───────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target_url: str
    api_pattern: Optional[str] = "/api/users/{id}"
    sample_ids: Optional[list[str]] = ["1", "2", "3"]
    run_bola: Optional[bool] = True


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    risk_score: float
    created_at: datetime
    completed_at: Optional[datetime] = None
    finding_count: int = 0


# ── Core scan runner (background task) ────────────────────────────────────────
async def _run_scan(scan_id: int):
    """Execute a full scan pipeline in the background."""
    from app.db import SessionLocal
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()
        logger.info(f"Scan {scan_id} started for {scan.target_url}")

        # ── 1. Run scanners ────────────────────────────────────────────────────
        from app.scanner.headers import scan_headers
        from app.scanner.cors import scan_cors
        from app.scanner.cookies import scan_cookies
        from app.scanner.tls import scan_tls
        from app.scanner.bola import scan_bola
        from app.risk.stride_map import get_stride_category
        from app.risk.nist_map import get_nist_function

        all_findings = []

        try:
            all_findings += await scan_headers(scan.target_url)
        except Exception as e:
            logger.error(f"Headers scan failed: {e}")

        try:
            all_findings += await scan_cors(scan.target_url)
        except Exception as e:
            logger.error(f"CORS scan failed: {e}")

        try:
            all_findings += await scan_cookies(scan.target_url)
        except Exception as e:
            logger.error(f"Cookies scan failed: {e}")

        try:
            all_findings += await scan_tls(scan.target_url)
        except Exception as e:
            logger.error(f"TLS scan failed: {e}")

        # BOLA scan - try to get pattern from scan metadata
        summary_data = scan.summary_dict
        api_pattern = summary_data.get("api_pattern", "/api/users/{id}")
        sample_ids = summary_data.get("sample_ids", ["1", "2", "3"])

        try:
            all_findings += await scan_bola(scan.target_url, api_pattern, sample_ids)
        except Exception as e:
            logger.error(f"BOLA scan failed: {e}")

        # ── 2. Save findings to DB ─────────────────────────────────────────────
        db_findings = []
        for f in all_findings:
            stride = get_stride_category(f.finding_id, f.category)
            nist = get_nist_function(f.finding_id, f.category)
            db_f = Finding(
                scan_id=scan.id,
                finding_id=f.finding_id,
                title=f.title,
                category=f.category,
                severity=f.severity,
                evidence=f.evidence,
                remediation=f.remediation,
                stride_category=stride,
                nist_function=nist,
            )
            db.add(db_f)
            db_findings.append(db_f)
        db.commit()

        # ── 3. Threat Intelligence ─────────────────────────────────────────────
        from app.intel.aggregator import aggregate_intel
        intel_data = await aggregate_intel(scan.target_url, db)
        intel_risk_score = intel_data.get("aggregate", {}).get("risk_score", 0.0)
        malicious_count = intel_data.get("aggregate", {}).get("malicious_count", 0)

        ir = IntelResult(
            scan_id=scan.id,
            target=intel_data.get("domain", ""),
            source="combined",
            is_mock=intel_data.get("aggregate", {}).get("is_mock", True),
            reputation_score=intel_risk_score,
            malicious_count=malicious_count,
            data=json.dumps(intel_data),
        )
        db.add(ir)
        db.commit()

        # ── 4. Risk scoring ────────────────────────────────────────────────────
        from app.risk.scoring import compute_scan_risk_score
        risk_score = compute_scan_risk_score(db_findings, intel_risk_score)

        scan.risk_score = risk_score
        db.commit()

        # ── 5. Risk register ───────────────────────────────────────────────────
        from app.risk.register import build_risk_register
        # Reload findings from db to have IDs
        fresh_findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
        build_risk_register(scan, fresh_findings, intel_risk_score, db)

        # ── 6. SOAR playbooks ──────────────────────────────────────────────────
        from app.soar.engine import run_playbooks
        fresh_intel = db.query(IntelResult).filter(IntelResult.scan_id == scan.id).all()
        run_playbooks(scan, fresh_findings, fresh_intel, db)

        # ── 7. Report ──────────────────────────────────────────────────────────
        from app.reporter import generate_report
        generate_report(scan, db)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()

        logger.info(
            f"Scan {scan_id} completed. Findings: {len(db_findings)}, "
            f"Risk score: {risk_score:.1f}"
        )

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            db.commit()
    finally:
        db.close()


# ── REST API Endpoints ─────────────────────────────────────────────────────────
@app.post("/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(req: ScanRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Start a new security scan against a target URL."""
    # Validate URL
    parsed = urlparse(req.target_url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Target URL must start with http:// or https://")

    scan = Scan(
        target_url=req.target_url,
        status="pending",
        summary=json.dumps({
            "api_pattern": req.api_pattern,
            "sample_ids": req.sample_ids,
            "run_bola": req.run_bola,
        }),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    background_tasks.add_task(_run_scan, scan.id)

    return ScanResponse(
        id=scan.id,
        target_url=scan.target_url,
        status=scan.status,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        finding_count=0,
    )


@app.get("/scans", tags=["Scans"])
async def list_scans(db: Session = Depends(get_db)):
    """List all scans."""
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    result = []
    for s in scans:
        finding_count = db.query(Finding).filter(Finding.scan_id == s.id).count()
        result.append({
            "id": s.id,
            "target_url": s.target_url,
            "status": s.status,
            "risk_score": s.risk_score,
            "created_at": s.created_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "finding_count": finding_count,
        })
    return result


@app.get("/scans/{scan_id}", tags=["Scans"])
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get scan details by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "risk_score": scan.risk_score,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "finding_count": len(findings),
        "severity_breakdown": severity_counts,
    }


@app.get("/findings", tags=["Findings"])
async def list_findings(
    scan_id: Optional[int] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List all findings with optional filters."""
    q = db.query(Finding)
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category == category)
    
    findings = q.order_by(Finding.scan_id.desc(), Finding.severity).all()
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "finding_id": f.finding_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "stride_category": f.stride_category,
            "nist_function": f.nist_function,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]


@app.get("/risk-register", tags=["Risk"])
async def get_risk_register(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """Get the risk register."""
    q = db.query(RiskItem)
    if scan_id:
        q = q.filter(RiskItem.scan_id == scan_id)
    
    items = q.order_by(RiskItem.risk_score.desc()).all()
    return [
        {
            "id": r.id,
            "scan_id": r.scan_id,
            "risk_id": r.risk_id,
            "asset": r.asset,
            "threat": r.threat,
            "stride_category": r.stride_category,
            "nist_function": r.nist_function,
            "likelihood": r.likelihood,
            "impact": r.impact,
            "risk_score": r.risk_score,
            "owner": r.owner,
            "treatment": r.treatment,
            "status": r.status,
            "finding_id": r.finding_id,
            "created_at": r.created_at.isoformat(),
        }
        for r in items
    ]


@app.get("/incidents", tags=["SOAR"])
async def list_incidents(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """List SOAR incidents."""
    q = db.query(Incident)
    if scan_id:
        q = q.filter(Incident.scan_id == scan_id)
    
    incidents = q.order_by(Incident.created_at.desc()).all()
    return [
        {
            "id": inc.id,
            "scan_id": inc.scan_id,
            "playbook_name": inc.playbook_name,
            "trigger_condition": json.loads(inc.trigger_condition) if inc.trigger_condition else {},
            "actions_taken": inc.actions_list,
            "status": inc.status,
            "created_at": inc.created_at.isoformat(),
        }
        for inc in incidents
    ]


@app.get("/intel", tags=["Intel"])
async def list_intel(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    """List threat intelligence results."""
    q = db.query(IntelResult)
    if scan_id:
        q = q.filter(IntelResult.scan_id == scan_id)
    
    results = q.order_by(IntelResult.cached_at.desc()).all()
    return [
        {
            "id": ir.id,
            "scan_id": ir.scan_id,
            "target": ir.target,
            "source": ir.source,
            "is_mock": ir.is_mock,
            "reputation_score": ir.reputation_score,
            "malicious_count": ir.malicious_count,
            "data": ir.data_dict,
            "cached_at": ir.cached_at.isoformat(),
        }
        for ir in results
    ]


@app.get("/report/{scan_id}", tags=["Reports"])
async def get_report(scan_id: int, fmt: str = "md", db: Session = Depends(get_db)):
    """Download scan report (md or html)."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail=f"Scan not completed yet (status: {scan.status})")

    from app.reporter import generate_report
    md_path, html_path = generate_report(scan, db)

    if fmt == "html":
        return FileResponse(html_path, media_type="text/html")
    else:
        return FileResponse(md_path, media_type="text/markdown")


@app.get("/stats", tags=["Dashboard"])
async def get_stats(db: Session = Depends(get_db)):
    """Get aggregate statistics for dashboard."""
    total_scans = db.query(Scan).count()
    total_findings = db.query(Finding).count()
    total_incidents = db.query(Incident).count()

    severity_counts = {}
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        severity_counts[sev] = db.query(Finding).filter(Finding.severity == sev).count()

    stride_counts = {}
    for item in db.query(RiskItem).all():
        stride_counts[item.stride_category] = stride_counts.get(item.stride_category, 0) + 1

    nist_counts = {}
    for item in db.query(RiskItem).all():
        nist_counts[item.nist_function] = nist_counts.get(item.nist_function, 0) + 1

    # Risk trend
    recent_scans = db.query(Scan).filter(Scan.status == "completed").order_by(Scan.created_at.desc()).limit(10).all()
    risk_trend = [
        {"scan_id": s.id, "score": s.risk_score, "date": s.created_at.isoformat(), "target": s.target_url}
        for s in reversed(recent_scans)
    ]

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "total_incidents": total_incidents,
        "severity_counts": severity_counts,
        "stride_counts": stride_counts,
        "nist_counts": nist_counts,
        "risk_trend": risk_trend,
    }


# ── UI Routes ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse, tags=["UI"])
async def index(request: Request, db: Session = Depends(get_db)):
    """Dashboard overview."""
    recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()
    scan_data = []
    for s in recent_scans:
        fc = db.query(Finding).filter(Finding.scan_id == s.id).count()
        scan_data.append({"scan": s, "finding_count": fc})
    
    return templates.TemplateResponse("index.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "demo_target": settings.DEMO_TARGET_URL,
        "recent_scans": scan_data,
    })


@app.get("/scan", response_class=HTMLResponse, tags=["UI"])
async def scan_page(request: Request):
    return templates.TemplateResponse("scan.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "demo_target": settings.DEMO_TARGET_URL,
    })


@app.get("/findings-ui", response_class=HTMLResponse, tags=["UI"])
async def findings_page(request: Request, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return templates.TemplateResponse("findings.html", {
        "request": request,
        "app_name": settings.APP_NAME,
        "scans": scans,
    })


@app.get("/intel-ui", response_class=HTMLResponse, tags=["UI"])
async def intel_page(request: Request):
    return templates.TemplateResponse("intel.html", {
        "request": request,
        "app_name": settings.APP_NAME,
    })


@app.get("/risk-ui", response_class=HTMLResponse, tags=["UI"])
async def risk_page(request: Request):
    return templates.TemplateResponse("risk.html", {
        "request": request,
        "app_name": settings.APP_NAME,
    })


@app.get("/soar-ui", response_class=HTMLResponse, tags=["UI"])
async def soar_page(request: Request):
    return templates.TemplateResponse("soar.html", {
        "request": request,
        "app_name": settings.APP_NAME,
    })
