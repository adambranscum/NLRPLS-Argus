import requests
from .base import BaseConnector, NormalizedEvent


class SemaphoreConnector(BaseConnector):
    """Polls Semaphore's task history for failed/error runs.
    Uses the project-scoped tasks endpoint — adjust project_id if you run more than one."""

    name = "semaphore"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.base_url = cfg["base_url"].rstrip("/")
        self.project_id = cfg.get("project_id", 1)  # confirm against your Semaphore project
        self._last_task_id = 0

    def poll(self) -> list[NormalizedEvent]:
        resp = requests.get(
            f"{self.base_url}/api/project/{self.project_id}/tasks",
            timeout=15,
        )
        resp.raise_for_status()
        tasks = resp.json()

        events = []
        for task in tasks:
            task_id = task.get("id", 0)
            if task_id <= self._last_task_id:
                continue
            status = task.get("status", "")
            if status in ("error", "failed"):
                events.append(NormalizedEvent(
                    source="semaphore",
                    host=task.get("template_name", "unknown-playbook"),
                    severity="high",
                    message=f"Task #{task_id} ({task.get('template_name','?')}) finished with status={status}",
                    raw_timestamp=task.get("end", task.get("start", "")),
                    rule_id=str(task.get("template_id", "")),
                ))
        if tasks:
            self._last_task_id = max(t.get("id", 0) for t in tasks)
        return events
