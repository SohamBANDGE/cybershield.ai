"""Explainable rule-based scoring. Never fetches URLs: it only inspects the string (no SSRF)."""
import re
from urllib.parse import urlparse

SUSP_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "icu", "rest", "support", "work"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy"}
BRANDS = ["paypal", "google", "microsoft", "apple", "amazon", "netflix", "facebook", "instagram",
          "hdfc", "icici", "paytm", "phonepe", "whatsapp", "linkedin"]
WORDS = ["login", "verify", "secure", "update", "account", "wallet", "password", "confirm", "signin", "billing", "kyc"]
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s"})

MSG_RULES = [
    (r"\b(urgent|immediately|act now|within \d+ (hours?|minutes?)|last warning|final notice)\b", 15,
     "The message pressures you to act urgently."),
    (r"\b(suspended|blocked|locked|deactivated|unauthori[sz]ed|unusual activity)\b", 15,
     "It warns that an account is suspended or at risk, a common scare tactic."),
    (r"\b(password|otp|pin|cvv|card number|net ?banking|login details|kyc)\b", 25,
     "It asks for, or mentions, sensitive credentials such as passwords, OTPs or card details."),
    (r"\b(gift cards?|wire transfer|bitcoin|crypto|processing fees?|western union|registration fee|claim fee|release fee)\b", 20,
        "It asks for payment in a hard-to-trace way or requests a fee."),
    (r"\b(you (have )?won|winner|lottery|prize|claim your|free (gift|iphone))\b", 25,
     "It promises a prize or reward you did not sign up for."),
    (r"\b(dear (customer|user|client|member)|valued customer)\b", 8,
     "It uses a generic greeting instead of your name."),
    (r"\b(click (here|below|the link)|tap (here|the link))\b", 8,
     "It pushes you to click a link."),
]

def _reg(host):
    p = host.split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in {"co", "com", "org", "net", "gov", "ac"}:
        return ".".join(p[-3:])
    return ".".join(p[-2:])

def _finish(signals):
    signals.sort(key=lambda s: -s[0])
    score = min(100, sum(w for w, _ in signals))
    label = "safe" if score < 30 else "suspicious" if score < 60 else "dangerous"
    reasons = [t for _, t in signals[:6]] or ["No common phishing signals found. This is not a guarantee of safety."]
    return {"score": score, "label": label, "reasons": reasons}

def analyze_url(raw):
    raw = raw.strip()
    has_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    try:
        p = urlparse(raw if has_scheme else "http://" + raw)
        host, port = (p.hostname or "").lower(), p.port
    except ValueError:
        return _finish([(60, "The URL is malformed, which is unusual for a legitimate link.")])
    s = []
    if not host:
        return _finish([(60, "No valid domain could be found in this link.")])
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        s.append((35, "The link uses a raw IP address instead of a domain name."))
    if "@" in p.netloc:
        s.append((25, "The link hides its real destination behind an '@' sign."))
    if "xn--" in host:
        s.append((25, "The domain uses look-alike (punycode) characters."))
    if host in SHORTENERS:
        s.append((20, "It is a shortened link, so the real destination is hidden."))
    if host.rsplit(".", 1)[-1] in SUSP_TLDS:
        s.append((15, f"The '.{host.rsplit('.', 1)[-1]}' ending is heavily used in scams."))
    if len(host.split(".")) - len(_reg(host).split(".")) >= 3:
        s.append((15, "It has an unusually long chain of subdomains."))
    if host.count("-") >= 3:
        s.append((10, "The domain contains many hyphens."))
    if len(raw) > 75:
        s.append((10, "The URL is unusually long."))
    norm = host.translate(LEET)
    for b in BRANDS:
        if b in norm and b not in host:
            s.append((40, f"The domain imitates '{b}' by swapping in look-alike characters.")); break
        if b in host and not _reg(host).startswith(b + "."):
            s.append((30, f"It uses the name '{b}' but is not the official {b} domain.")); break
    if sum(w in raw.lower() for w in WORDS) >= 2:
        s.append((10, "It combines words like 'login', 'verify' or 'account', typical of phishing pages."))
    if has_scheme and p.scheme == "http":
        s.append((10, "The link is not encrypted (HTTP, not HTTPS)."))
    if port not in (None, 80, 443):
        s.append((10, "It connects through an unusual port."))
    return _finish(s)


def analyze_message(text):
    s = [
        (w, why)
        for rx, w, why in MSG_RULES
        if re.search(rx, text, re.I)
    ]

    # Extract URLs without visiting them.
    urls = re.findall(
        r"""https?://[^\s<>"']+|www\.[^\s<>"']+""",
        text,
        re.I,
    )[:5]

    worst = max(
        (analyze_url(u) for u in urls),
        key=lambda r: r["score"],
        default=None,
    )

    if worst and worst["score"] >= 30:
        s.append((
            int(worst["score"] * 0.6),
            "It contains a risky link: " + worst["reasons"][0],
        ))
    elif urls:
        s.append((
            5,
            "It contains a link. Check the address before you click.",
        ))

    # Detect unsolicited prizes combined with payment requests.
    prize_pattern = (
        r"\b(you (have )?won|winner|lottery|prize|"
        r"claim your|free (gift|iphone))\b"
    )

    payment_pattern = (
        r"(?:\b(pay|paying|payment|send|transfer|deposit)\b"
        r".{0,80}?"
        r"(?:₹\s*[\d,]+|rs\.?\s*[\d,]+|inr\s*[\d,]+|"
        r"\bfees?\b|\bprocessing\b|\bcharges?\b))"
        r"|"
        r"\b(processing fees?|registration fee|claim fee|"
        r"release fee)\b"
    )

    has_prize = bool(re.search(prize_pattern, text, re.I))
    has_payment_request = bool(
        re.search(payment_pattern, text, re.I)
    )

    if has_prize and has_payment_request:
        s.append((
            25,
            "It combines an unsolicited prize with an upfront "
            "payment request, a common advance-fee scam pattern.",
        ))

    # Always return a result, including for ordinary messages.
    return _finish(s)
