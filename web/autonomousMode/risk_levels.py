"""Risk level -> which existing task types the autonomous loop may pick.

A risk level can only ever *narrow* the action types already permitted by
RBAC, scope, and the active EngineType's YAML task list (see policy.py) -
it must never grant an action type outside what the operator's own engine
config already enabled.
"""

from autonomousMode.models import AutonomousAssessment

PASSIVE_RECON_ACTIONS = {
    'subdomain_discovery',
    'osint',
    'screenshot',
    'waf_detection',
    # reconIntel passive intelligence steps: all read-only / OSINT-grade
    # (fetch JS already served, query Wayback/crt.sh, score findings already
    # in the DB), so they belong at the SAFE tier alongside other passive recon.
    'js_analysis',
    'param_discovery',
    'origin_ip_discovery',
    'response_dedup',
    'finding_scoring',
}

ACTIVE_SCAN_ACTIONS = {
    'port_scan',
    'fetch_url',
    'dir_file_fuzz',
}

ACTIVE_VALIDATION_ACTIONS = {
    'vulnerability_scan',
}

RISK_LEVEL_ALLOWED_ACTIONS = {
    AutonomousAssessment.RISK_SAFE: set(PASSIVE_RECON_ACTIONS),
    AutonomousAssessment.RISK_STANDARD: PASSIVE_RECON_ACTIONS | ACTIVE_SCAN_ACTIONS,
    AutonomousAssessment.RISK_CONTROLLED: (
        PASSIVE_RECON_ACTIONS | ACTIVE_SCAN_ACTIONS | ACTIVE_VALIDATION_ACTIONS
    ),
}

# Action types that are otherwise ALLOWED at this risk level but must still
# be queued for a human to approve before dispatch.
RISK_LEVEL_REQUIRES_APPROVAL = {
    AutonomousAssessment.RISK_SAFE: set(),
    AutonomousAssessment.RISK_STANDARD: set(),
    AutonomousAssessment.RISK_CONTROLLED: set(ACTIVE_VALIDATION_ACTIONS),
}

# Every action type the decision engine is ever allowed to propose, regardless
# of risk level - anchors it to exactly what initiate_subscan can dispatch
# (reNgine/tasks.py: initiate_subscan does globals().get(scan_type)).
KNOWN_SUBSCAN_ACTIONS = PASSIVE_RECON_ACTIONS | ACTIVE_SCAN_ACTIONS | ACTIVE_VALIDATION_ACTIONS
