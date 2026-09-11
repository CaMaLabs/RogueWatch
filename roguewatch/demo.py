from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .models import Event


def demo_events() -> list[Event]:
    start = datetime(2026, 9, 11, 12, 0, tzinfo=timezone.utc)
    events: list[Event] = []
    token = "f93817aa21bc45de"
    for i in range(8):
        t = start + timedelta(seconds=i * 30)
        events.append(Event(source="honeysite", actor_id="agent-alpha", timestamp=t, text=f'{{"task_id":"{token}","seq":{i},"status":"ready"}}'))
        events.append(Event(source="honeysite", actor_id="agent-beta", timestamp=t + timedelta(milliseconds=650), parent_actor_id="agent-alpha", text=f"ACK task_id={token} seq={i} status=received"))
    events.extend([
        Event(source="honeysite", actor_id="human-jules", timestamp=start + timedelta(minutes=2, seconds=7), text="That repair guide solved it, thanks."),
        Event(source="honeysite", actor_id="human-jules", timestamp=start + timedelta(hours=5, minutes=13), text="One follow-up: which firmware version did you use?"),
        Event(source="honeysite", actor_id="human-mara", timestamp=start + timedelta(minutes=18), text="I had the same issue last year."),
    ])
    return events
