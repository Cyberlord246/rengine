(function () {
	'use strict';

	let lastEventId = 0;
	let assessmentId = null;
	let pollHandle = null;

	function statusBadgeClass(statusDisplay) {
		const map = {
			'Running': 'bg-primary',
			'Paused': 'bg-warning',
			'Completed': 'bg-success',
			'Stopped': 'bg-secondary',
			'Failed': 'bg-danger',
			'Pending': 'bg-info',
		};
		return map[statusDisplay] || 'bg-secondary';
	}

	function renderStatus(data) {
		document.getElementById('assessment-mode').textContent = data.mode_display;
		document.getElementById('assessment-risk').textContent = data.risk_level_display;
		document.getElementById('assessment-actions').textContent = data.actions_taken_count;

		const statusEl = document.getElementById('assessment-status');
		statusEl.textContent = data.status_display;
		statusEl.className = 'badge ' + statusBadgeClass(data.status_display);

		const reasonEl = document.getElementById('assessment-completion-reason');
		reasonEl.textContent = data.completion_reason ? ('Completion reason: ' + data.completion_reason) : '';

		const running = data.status_display === 'Running';
		const paused = data.status_display === 'Paused';
		document.getElementById('btn-pause').disabled = !running;
		document.getElementById('btn-resume').disabled = !paused;
		document.getElementById('btn-stop').disabled = !(running || paused);
	}

	function escapeHtml(str) {
		const div = document.createElement('div');
		div.textContent = str == null ? '' : String(str);
		return div.innerHTML;
	}

	function appendEvents(events) {
		if (!events || !events.length) {
			return;
		}
		const tbody = document.getElementById('event-log-body');
		events.forEach(function (event) {
			const row = document.createElement('tr');
			row.innerHTML =
				'<td>' + escapeHtml(event.sequence) + '</td>' +
				'<td>' + escapeHtml(event.action_type) + '</td>' +
				'<td>' + escapeHtml(event.target) + '</td>' +
				'<td>' + escapeHtml(event.reason) + '</td>' +
				'<td>' + escapeHtml(event.policy_result) + '</td>' +
				'<td>' + escapeHtml(event.status) + '</td>';
			tbody.appendChild(row);
			lastEventId = Math.max(lastEventId, event.sequence);
		});
	}

	function renderApprovalQueue(items) {
		const tbody = document.getElementById('approval-queue-body');
		tbody.innerHTML = '';
		(items || []).forEach(function (item) {
			const row = document.createElement('tr');
			const actionsCell = document.createElement('td');

			const approveBtn = document.createElement('button');
			approveBtn.className = 'btn btn-success btn-xs me-1';
			approveBtn.textContent = 'Approve';
			approveBtn.addEventListener('click', function () { decideApproval(item.id, true); });

			const rejectBtn = document.createElement('button');
			rejectBtn.className = 'btn btn-danger btn-xs';
			rejectBtn.textContent = 'Reject';
			rejectBtn.addEventListener('click', function () { decideApproval(item.id, false); });

			actionsCell.appendChild(approveBtn);
			actionsCell.appendChild(rejectBtn);

			row.innerHTML =
				'<td>' + escapeHtml(item.action_type) + '</td>' +
				'<td>' + escapeHtml(item.target) + '</td>';
			row.appendChild(actionsCell);
			tbody.appendChild(row);
		});
	}

	function decideApproval(decisionId, approve) {
		fetch('/api/autonomous/approvals/decide/', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-CSRFToken': getCookie('csrftoken'),
			},
			body: JSON.stringify({ decision_id: decisionId, approve: approve }),
		}).then(function () { pollAssessment(); });
	}

	function pollAssessment() {
		fetch('/api/autonomous/status/?assessment_id=' + assessmentId)
			.then(function (r) { return r.json(); })
			.then(renderStatus);

		fetch('/api/autonomous/events/?assessment_id=' + assessmentId + '&since_id=' + lastEventId)
			.then(function (r) { return r.json(); })
			.then(function (data) { appendEvents(data.events); });

		fetch('/api/autonomous/approvals/?assessment_id=' + assessmentId)
			.then(function (r) { return r.json(); })
			.then(function (data) { renderApprovalQueue(data.results); });
	}

	function controlAction(path) {
		fetch(path, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'X-CSRFToken': getCookie('csrftoken'),
			},
			body: JSON.stringify({ assessment_id: assessmentId }),
		}).then(function () { pollAssessment(); });
	}

	document.addEventListener('DOMContentLoaded', function () {
		const root = document.getElementById('assessment-root');
		if (!root) {
			return;
		}
		assessmentId = root.getAttribute('data-assessment-id');

		document.getElementById('btn-pause').addEventListener('click', function () {
			controlAction('/api/autonomous/pause/');
		});
		document.getElementById('btn-resume').addEventListener('click', function () {
			controlAction('/api/autonomous/resume/');
		});
		document.getElementById('btn-stop').addEventListener('click', function () {
			controlAction('/api/autonomous/stop/');
		});

		pollAssessment();
		pollHandle = setInterval(pollAssessment, 5000);
	});
})();
