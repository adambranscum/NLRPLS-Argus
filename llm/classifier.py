import json
import requests

CLASSIFY_TOOL = {
    "type": "function",
    "function": {
        "name": "classify_finding",
        "description": "Classify a monitoring event and decide whether it warrants a DB record and alert.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                "summary": {"type": "string", "description": "One-line human-readable summary"},
                "report_worthy": {"type": "boolean", "description": "false for noise/known-benign"},
            },
            "required": ["severity", "summary", "report_worthy"],
        },
    },
}


class Classifier:
    def __init__(self, base_url: str, model: str, temperature: float = 0.1):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature

    def classify(self, event, similar_past: list[dict]) -> dict:
        context = ""
        if similar_past:
            context = "Similar past incidents:\n" + "\n".join(
                f"- {p['summary']} (resolution: {p['resolution'] or 'none recorded'})"
                for p in similar_past
            )

        prompt = (
            f"Source: {event.source}\nHost: {event.host}\n"
            f"Raw severity hint: {event.severity}\nMessage: {event.message}\n\n"
            f"{context}\n\n"
            "Classify this event using the classify_finding tool."
        )

        resp = requests.post(
            f"{self.base_url}/chat/completions",
            json={
                "model": self.model,
                "temperature": self.temperature,
                "messages": [{"role": "user", "content": prompt}],
                "tools": [CLASSIFY_TOOL],
                "tool_choice": {"type": "function", "function": {"name": "classify_finding"}},
            },
            timeout=30,
        )
        resp.raise_for_status()
        message = resp.json()["choices"][0]["message"]
        tool_call = message["tool_calls"][0]
        return json.loads(tool_call["function"]["arguments"])
