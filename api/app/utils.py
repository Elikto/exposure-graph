import ipaddress
import re
from urllib.parse import urlparse

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+?[0-9][0-9 .()\-]{6,20}$")
DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")


def detect_kind(value: str) -> str:
    text = value.strip()
    if EMAIL_RE.match(text):
        return "email"
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if PHONE_RE.match(text):
        return "phone"
    parsed = urlparse(text if "://" in text else f"https://{text}")
    host = parsed.hostname or ""
    if DOMAIN_RE.match(host) and "/" not in text.replace("://", ""):
        return "domain"
    if " " in text:
        return "person"
    return "username"


def root_node_id(kind: str, value: str) -> str:
    normalized = value.strip().lower()
    return f"target:{kind}:{normalized}"
