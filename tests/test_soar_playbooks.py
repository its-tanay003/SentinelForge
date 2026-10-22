"""Tests for the SOAR playbook engine."""
import json
import pytest
from unittest.mock import MagicMock, patch
from app.soar.engine import (
    load_playbooks,
    _evaluate_condition,
    _evaluate_trigger,
    _execute_action,
)


class TestPlaybookConditions:

    def test_eq_operator_true(self):
        ctx = {"max_severity": "Critical"}
        cond = {"field": "max_severity", "operator": "eq", "value": "Critical"}
        assert _evaluate_condition(cond, ctx) is True

    def test_eq_operator_false(self):
        ctx = {"max_severity": "Low"}
        cond = {"field": "max_severity", "operator": "eq", "value": "Critical"}
        assert _evaluate_condition(cond, ctx) is False

    def test_gte_operator(self):
        ctx = {"high_count": 5}
        cond = {"field": "high_count", "operator": "gte", "value": 3}
        assert _evaluate_condition(cond, ctx) is True

        ctx2 = {"high_count": 1}
        assert _evaluate_condition(cond, ctx2) is False

    def test_gt_operator(self):
        ctx = {"intel_malicious_count": 3}
        cond = {"field": "intel_malicious_count", "operator": "gt", "value": 0}
        assert _evaluate_condition(cond, ctx) is True

        ctx2 = {"intel_malicious_count": 0}
        assert _evaluate_condition(cond, ctx2) is False

    def test_missing_field_returns_false(self):
        ctx = {}
        cond = {"field": "nonexistent", "operator": "eq", "value": "anything"}
        assert _evaluate_condition(cond, ctx) is False

    def test_in_operator(self):
        ctx = {"max_severity": "High"}
        cond = {"field": "max_severity", "operator": "in", "value": ["High", "Critical"]}
        assert _evaluate_condition(cond, ctx) is True

    def test_lt_operator(self):
        ctx = {"risk_score": 10.0}
        cond = {"field": "risk_score", "operator": "lt", "value": 50.0}
        assert _evaluate_condition(cond, ctx) is True


class TestPlaybookTriggers:

    def test_and_logic_all_true(self):
        ctx = {"high_count": 3, "intel_malicious_count": 2}
        trigger = {
            "logic": "AND",
            "conditions": [
                {"field": "high_count", "operator": "gte", "value": 1},
                {"field": "intel_malicious_count", "operator": "gt", "value": 0},
            ]
        }
        assert _evaluate_trigger(trigger, ctx) is True

    def test_and_logic_one_false(self):
        ctx = {"high_count": 3, "intel_malicious_count": 0}
        trigger = {
            "logic": "AND",
            "conditions": [
                {"field": "high_count", "operator": "gte", "value": 1},
                {"field": "intel_malicious_count", "operator": "gt", "value": 0},
            ]
        }
        assert _evaluate_trigger(trigger, ctx) is False

    def test_or_logic_one_true(self):
        ctx = {"critical_count": 1, "high_count": 0}
        trigger = {
            "logic": "OR",
            "conditions": [
                {"field": "critical_count", "operator": "gt", "value": 0},
                {"field": "high_count", "operator": "gt", "value": 5},
            ]
        }
        assert _evaluate_trigger(trigger, ctx) is True

    def test_empty_conditions_always_true(self):
        ctx = {}
        trigger = {"conditions": []}
        assert _evaluate_trigger(trigger, ctx) is True


class TestPlaybookLoading:

    def test_load_playbooks_returns_list(self):
        """load_playbooks should return a list."""
        playbooks = load_playbooks()
        assert isinstance(playbooks, list)

    def test_playbooks_have_required_fields(self):
        """Each playbook should have name, trigger, actions."""
        playbooks = load_playbooks()
        for pb in playbooks:
            assert "name" in pb, f"Playbook missing 'name' field"
            assert "trigger" in pb, f"Playbook '{pb.get('name')}' missing 'trigger' field"
            assert "actions" in pb, f"Playbook '{pb.get('name')}' missing 'actions' field"

    def test_at_least_3_playbooks_loaded(self):
        """Should have at least 3 sample playbooks."""
        playbooks = load_playbooks()
        assert len(playbooks) >= 3, f"Expected at least 3 playbooks, got {len(playbooks)}"

    def test_playbook_actions_have_action_field(self):
        """All playbook actions should have an 'action' field."""
        playbooks = load_playbooks()
        for pb in playbooks:
            for action in pb.get("actions", []):
                assert "action" in action, f"Action in '{pb['name']}' missing 'action' field"


class TestActionExecution:

    def test_create_ticket_action(self):
        """create_ticket action should be simulated successfully."""
        ctx = {
            "scan_id": 999,
            "finding_ids": ["HDR-001", "CRS-001"],
            "target_url": "http://test.example.com",
        }
        action_def = {
            "action": "create_ticket",
            "params": {
                "finding_ids": ["HDR-001"],
                "severity": "High",
            }
        }
        with patch("app.soar.actions._log_action") as mock_log:
            mock_log.return_value = {"action": "create_ticket", "status": "success"}
            result = _execute_action(action_def, ctx)

        assert result["status"] == "success"

    def test_unknown_action_handled(self):
        """Unknown action names should not crash, return unknown_action."""
        ctx = {"scan_id": 1}
        action_def = {"action": "nonexistent_action", "params": {}}
        result = _execute_action(action_def, ctx)
        assert result["status"] == "unknown_action"

    def test_notify_action(self):
        """notify action should succeed with console channel."""
        ctx = {
            "scan_id": 1,
            "target_url": "http://test.example.com",
        }
        action_def = {
            "action": "notify",
            "params": {
                "message": "Test notification",
                "channels": ["console"],
            }
        }
        with patch("app.soar.actions._log_action") as mock_log:
            mock_log.return_value = {"status": "success"}
            result = _execute_action(action_def, ctx)

        assert result["status"] == "success"
