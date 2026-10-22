"""SOAR playbook engine."""
import json
import logging
from pathlib import Path
import yaml
from sqlalchemy.orm import Session
from app.models import Scan, Finding, Incident, IntelResult
from app.soar.actions import ACTION_MAP

logger = logging.getLogger(__name__)

PLAYBOOKS_DIR = Path(__file__).parent / "playbooks"


def load_playbooks() -> list[dict]:
    """Load all YAML playbooks from the playbooks directory."""
    playbooks = []
    if not PLAYBOOKS_DIR.exists():
        return playbooks
    
    for path in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        try:
            with open(path) as f:
                pb = yaml.safe_load(f)
                if pb:
                    playbooks.append(pb)
                    logger.debug(f"Loaded playbook: {pb.get('name', path.name)}")
        except Exception as e:
            logger.error(f"Failed to load playbook {path}: {e}")
    
    return playbooks


def _evaluate_condition(condition: dict, context: dict) -> bool:
    """Evaluate a single playbook condition against context."""
    field = condition.get("field", "")
    operator = condition.get("operator", "eq")
    value = condition.get("value")

    ctx_value = context.get(field)
    if ctx_value is None:
        return False

    if operator == "eq":
        return ctx_value == value
    elif operator == "neq":
        return ctx_value != value
    elif operator == "gte":
        return ctx_value >= value
    elif operator == "lte":
        return ctx_value <= value
    elif operator == "gt":
        return ctx_value > value
    elif operator == "lt":
        return ctx_value < value
    elif operator == "in":
        return ctx_value in (value if isinstance(value, list) else [value])
    elif operator == "contains":
        return str(value).lower() in str(ctx_value).lower()
    else:
        return False


def _evaluate_trigger(trigger: dict, context: dict) -> bool:
    """Evaluate all conditions in a trigger (AND logic)."""
    conditions = trigger.get("conditions", [])
    if not conditions:
        return True  # No conditions = always trigger
    
    logic = trigger.get("logic", "AND").upper()
    
    results = [_evaluate_condition(c, context) for c in conditions]
    
    if logic == "AND":
        return all(results)
    elif logic == "OR":
        return any(results)
    else:
        return all(results)


def _execute_action(action: dict, context: dict) -> dict:
    """Execute a single SOAR action."""
    action_name = action.get("action", "")
    params = action.get("params", {})
    
    # Resolve template params from context
    resolved_params = {}
    for k, v in params.items():
        if isinstance(v, str) and v.startswith("$"):
            ctx_key = v[1:]  # Remove $
            resolved_params[k] = context.get(ctx_key, v)
        else:
            resolved_params[k] = v

    func = ACTION_MAP.get(action_name)
    if func:
        try:
            scan_id = context.get("scan_id", 0)
            result = func(scan_id=scan_id, **resolved_params)
            return {"action": action_name, "status": "success", "result": result}
        except Exception as e:
            logger.error(f"Action {action_name} failed: {e}")
            return {"action": action_name, "status": "failed", "error": str(e)}
    else:
        return {"action": action_name, "status": "unknown_action"}


def run_playbooks(
    scan: Scan,
    findings: list[Finding],
    intel_results: list[IntelResult],
    db: Session,
) -> list[Incident]:
    """
    Run all playbooks against scan results.
    Returns list of triggered incidents.
    """
    playbooks = load_playbooks()
    incidents = []

    # Build context
    severities = [f.severity for f in findings]
    severity_counts = {s: severities.count(s) for s in ["Critical", "High", "Medium", "Low", "Info"]}
    
    malicious_count = 0
    for ir in intel_results:
        if ir.data:
            data = json.loads(ir.data)
            agg = data.get("aggregate", {})
            malicious_count += agg.get("malicious_count", 0)

    max_severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    max_severity = "Info"
    for sev in max_severity_order:
        if severity_counts.get(sev, 0) > 0:
            max_severity = sev
            break

    context = {
        "scan_id": scan.id,
        "target_url": scan.target_url,
        "total_findings": len(findings),
        "critical_count": severity_counts.get("Critical", 0),
        "high_count": severity_counts.get("High", 0),
        "medium_count": severity_counts.get("Medium", 0),
        "low_count": severity_counts.get("Low", 0),
        "max_severity": max_severity,
        "intel_malicious_count": malicious_count,
        "risk_score": scan.risk_score,
        "finding_ids": [f.finding_id for f in findings],
        "categories": list(set(f.category for f in findings)),
    }

    for playbook in playbooks:
        pb_name = playbook.get("name", "unnamed")
        trigger = playbook.get("trigger", {})

        try:
            if _evaluate_trigger(trigger, context):
                logger.info(f"Playbook '{pb_name}' triggered for scan {scan.id}")
                
                actions_taken = []
                for action_def in playbook.get("actions", []):
                    result = _execute_action(action_def, context)
                    actions_taken.append(result)

                incident = Incident(
                    scan_id=scan.id,
                    playbook_name=pb_name,
                    trigger_condition=json.dumps(trigger),
                    actions_taken=json.dumps(actions_taken),
                    status="executed",
                )
                db.add(incident)
                incidents.append(incident)
            else:
                logger.debug(f"Playbook '{pb_name}' not triggered for scan {scan.id}")
        except Exception as e:
            logger.error(f"Error running playbook '{pb_name}': {e}")

    db.commit()
    return incidents
