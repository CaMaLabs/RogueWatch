from roguewatch.demo import demo_events
from roguewatch.scoring import analyze_actors, analyze_channels


def test_demo_flags_agents_and_channel():
    events = demo_events()
    actors = {finding.actor_id: finding for finding in analyze_actors(events)}
    channels = analyze_channels(events)

    assert actors["agent-alpha"].confidence > actors["human-jules"].confidence
    assert actors["agent-beta"].confidence > actors["human-jules"].confidence
    assert actors["agent-alpha"].classification.value in {"AI_AGENT", "CONVENTIONAL_BOT"}
    assert any({finding.actor_a, finding.actor_b} == {"agent-alpha", "agent-beta"} and finding.confidence >= 0.3 for finding in channels)
