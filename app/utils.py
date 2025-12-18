from fastapi import Request
import tldextract, user_agents
from typing import Any

def get_client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None

def parse_user_agent(ua: str | None):
    if not ua:
        return None
    ua_p = user_agents.parse(ua)
    return {
        "os": ua_p.os.family,
        "os_version": ua_p.os.version_string,
        "browser": ua_p.browser.family,
        "browser_version": ua_p.browser.version_string,
        "device": ua_p.device.family,
        "is_mobile": ua_p.is_mobile,
        "is_tablet": ua_p.is_tablet,
        "is_pc": ua_p.is_pc,
    }

def subdomain_of(url: Any) -> str | None:
    """Return subdomain from a URL-like object (HttpUrl/str/None)."""
    if not url:
        return None
    s = str(url)  # <-- coerce HttpUrl to plain string
    ext = tldextract.extract(s)
    return ext.subdomain or None
