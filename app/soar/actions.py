"""SOAR actions - simulated only, no real system changes."""
import json
import logging
from datetime import datetime
from pathlib import Path
from app.config import settings

logger = logging.getLogger(__name__)

# Incident log file
INCIDENT_LOG = settings.REPORTS_DIR / "incident_log.jsonl"


def _log_action(scan_id: int, action: str, details: dict) -> dict:
    """Write action to incident log file."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "scan_id": scan_id,
        "action": action,
        "details": details,
    }
    try:
        with open(INCIDENT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to write incident log: {e}")
    return entry


def action_create_ticket(scan_id: int, finding_ids: list[str], severity: str) -> dict:
    """Simulate creating a security ticket (no real ticketing system)."""
    ticket_id = f"SF-TICKET-{scan_id:04d}-{datetime.utcnow().strftime('%H%M%S')}"
    details = {
        "ticket_id": ticket_id,
        "scan_id": scan_id,
        "finding_ids": finding_ids,
        "severity": severity,
        "priority": "P1" if severity in ("Critical", "High") else "P2",
        "status": "SIMULATED - Not sent to real ticketing system",
        "assigned_to": "security-team@example.com",
    }
    logger.warning(f"[SOAR SIMULATED] Creating ticket {ticket_id} for scan {scan_id}")
    return _log_action(scan_id, "create_ticket", details)


def action_simulate_block_ip(scan_id: int, target: str, reason: str) -> dict:
    """Simulate blocking an IP/domain (no real network changes)."""
    details = {
        "target": target,
        "reason": reason,
        "simulated_rule": f"BLOCK {target} - added to simulated blocklist",
        "status": "SIMULATED - No real network changes made",
        "note": "In production, this would call your firewall/WAF API",
    }
    logger.warning(f"[SOAR SIMULATED] Block IP/domain: {target} for scan {scan_id}")
    return _log_action(scan_id, "simulate_block_ip", details)


def action_notify(scan_id: int, message: str, channels: list[str] = None) -> dict:
    """Simulate sending notifications (console output + optional webhook)."""
    if channels is None:
        channels = ["console", "email"]

    details = {
        "message": message,
        "channels": channels,
        "status": "SIMULATED",
        "console_output": f"[ALERT] Scan {scan_id}: {message}",
    }

    # Attempt real webhook if configured
    if settings.SOAR_WEBHOOK_URL and "webhook" in channels:
        try:
            import httpx
            import asyncio
            payload = {"text": f"SentinelForge Alert - Scan {scan_id}: {message}"}
            # Note: In async context this should be called with await
            details["webhook_status"] = "configured (call async endpoint for real delivery)"
        except Exception as e:
            details["webhook_error"] = str(e)

    logger.warning(f"[SOAR SIMULATED] Notify: {message}")
    return _log_action(scan_id, "notify", details)


def action_generate_report(scan_id: int) -> dict:
    """Trigger report generation for a scan."""
    details = {
        "scan_id": scan_id,
        "report_path": str(settings.REPORTS_DIR / f"scan_{scan_id}_report.md"),
        "status": "triggered",
    }
    logger.info(f"[SOAR] Report generation triggered for scan {scan_id}")
    return _log_action(scan_id, "generate_report", details)


ACTION_MAP = {
    "create_ticket": action_create_ticket,
    "simulate_block_ip": action_simulate_block_ip,
    "notify": action_notify,
    "generate_report": action_generate_report,
}
