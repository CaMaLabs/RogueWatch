from __future__ import annotations

import networkx as nx

from .models import ChannelFinding, Event, Finding


def build_graph(events: list[Event], actor_findings: list[Finding], channels: list[ChannelFinding]) -> dict:
    graph = nx.MultiDiGraph()
    actor_map = {finding.actor_id: finding for finding in actor_findings}

    for event in events:
        finding = actor_map.get(event.actor_id)
        graph.add_node(event.actor_id, kind="actor", classification=finding.classification.value if finding else "UNKNOWN", confidence=finding.confidence if finding else 0.0)
        graph.add_node(event.id, kind="event", source=event.source, timestamp=event.timestamp.isoformat(), url=event.url)
        graph.add_edge(event.actor_id, event.id, kind="emitted")
        if event.parent_actor_id:
            graph.add_node(event.parent_actor_id, kind="actor")
            graph.add_edge(event.id, event.parent_actor_id, kind="targets")

    for channel in channels:
        graph.add_edge(channel.actor_a, channel.actor_b, kind="suspected_channel", confidence=channel.confidence)

    return {
        "nodes": [{"id": node, **attrs} for node, attrs in graph.nodes(data=True)],
        "edges": [{"source": src, "target": dst, **attrs} for src, dst, attrs in graph.edges(data=True)],
    }
