from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

import httpx
from bs4 import BeautifulSoup

from ..models import Event


@dataclass
class PublicHttpCollector:
    """Conservative public-web collector.

    It only visits explicitly allowlisted hosts, honors robots.txt, does not authenticate,
    and intentionally avoids anti-bot bypasses or stealth behavior.
    """

    allowed_hosts: set[str]
    user_agent: str = "RogueWatch/0.1 defensive-research"
    delay_seconds: float = 1.0
    timeout_seconds: float = 15.0
    _robots: dict[str, RobotFileParser] = field(default_factory=dict)

    def _validate_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only http/https URLs are supported")
        if not parsed.hostname or parsed.hostname not in self.allowed_hosts:
            raise PermissionError(f"Host {parsed.hostname!r} is not allowlisted")
        if parsed.username or parsed.password:
            raise PermissionError("Authenticated URLs are not supported by the public collector")

    async def _robots_allowed(self, client: httpx.AsyncClient, url: str) -> bool:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._robots:
            robots_url = urljoin(origin, "/robots.txt")
            parser = RobotFileParser()
            parser.set_url(robots_url)
            try:
                response = await client.get(robots_url)
                parser.parse(response.text.splitlines() if response.status_code < 400 else [])
            except httpx.HTTPError:
                return False
            self._robots[origin] = parser
        return self._robots[origin].can_fetch(self.user_agent, url)

    async def collect_page(self, url: str) -> list[Event]:
        self._validate_url(url)
        headers = {"User-Agent": self.user_agent}
        async with httpx.AsyncClient(headers=headers, timeout=self.timeout_seconds, follow_redirects=True) as client:
            if not await self._robots_allowed(client, url):
                raise PermissionError("robots.txt does not permit this collector to fetch the URL")
            await asyncio.sleep(max(0.0, self.delay_seconds))
            response = await client.get(url)
            response.raise_for_status()
            final = str(response.url)
            self._validate_url(final)

        soup = BeautifulSoup(response.text, "html.parser")
        events: list[Event] = []
        selectors = ["article", "[data-author]", ".comment", ".post"]
        seen: set[str] = set()
        for selector in selectors:
            for index, node in enumerate(soup.select(selector)):
                text = " ".join(node.stripped_strings)
                if not text or text in seen:
                    continue
                seen.add(text)
                actor = node.get("data-author") or node.get("data-user") or f"unknown:{index}"
                events.append(Event(source=urlparse(final).hostname or "web", actor_id=str(actor), text=text[:20000], url=final, metadata={"selector": selector}))
        return events
