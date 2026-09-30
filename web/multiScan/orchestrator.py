"""Pure, testable batching/throttle logic for the assessment orchestrator.

Kept free of Celery/Django-task imports so it can be unit-tested directly.
The Celery wrapper in tasks.py calls these functions.
"""

from reNgine.definitions import ABORTED_TASK, FAILED_TASK, SUCCESS_TASK

TERMINAL_SCAN_STATUSES = {SUCCESS_TASK, FAILED_TASK, ABORTED_TASK}


def select_next_domains(runs, batch_size):
    """Given the current AssessmentDomainRun states, decide which pending
    domains to launch next so that no more than `batch_size` run concurrently.

    `runs` is an iterable of objects with a `.status` attribute using
    AssessmentDomainRun status strings. Returns the number of NEW domains that
    may be launched this tick (caller launches that many pending runs).
    """
    running = sum(1 for r in runs if r.status == 'running')
    slots = max(0, batch_size - running)
    pending = [r for r in runs if r.status == 'pending']
    return pending[:slots]


def is_scan_terminal(scan_status):
    return scan_status in TERMINAL_SCAN_STATUSES


def all_runs_terminal(runs):
    """True when every domain run has reached a terminal state (completed/failed)."""
    runs = list(runs)
    if not runs:
        return True
    return all(r.status in ('completed', 'failed') for r in runs)
