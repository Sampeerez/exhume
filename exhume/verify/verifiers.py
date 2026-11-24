"""Active verifiers: confirm whether a credential is LIVE.

Each verifier makes ONE request to the provider API and returns
(Verified, detail). Inspired by TruffleHog. For authorized audits only:
it authenticates against real systems using the discovered credentials.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import json
import re
import urllib.error
import urllib.request

from ..models import Verified

_TIMEOUT = 8
_UA = "exhume/4.0"


def _http(url, method="GET", headers=None, data=None):
    """Simple HTTP request. Returns (status|None, body). None => network error."""
    req = urllib.request.Request(url, method=method, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return r.status, r.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception as e:
        return None, f"neterr:{type(e).__name__}"


def _result(status, live_detail, dead_codes=(401, 403)):
    if status is None:
        return Verified.UNKNOWN, "no verificable (red)"
    if status == 200:
        return Verified.LIVE, live_detail
    if status in dead_codes:
        return Verified.DEAD, f"rechazada (HTTP {status})"
    return Verified.UNKNOWN, f"respuesta HTTP {status}"


def _github(secret):
    st, body = _http("https://api.github.com/user",
                     headers={"Authorization": f"token {secret}", "User-Agent": _UA})
    if st == 200:
        try:
            login = json.loads(body).get("login")
        except Exception:
            login = None
        return Verified.LIVE, f"GitHub user: {login}"
    return _result(st, "")


def _gitlab(secret):
    st, body = _http("https://gitlab.com/api/v4/user", headers={"PRIVATE-TOKEN": secret})
    if st == 200:
        try:
            user = json.loads(body).get("username")
        except Exception:
            user = None
        return Verified.LIVE, f"GitLab user: {user}"
    return _result(st, "")


def _slack(secret):
    st, body = _http("https://slack.com/api/auth.test", method="POST",
                     headers={"Authorization": f"Bearer {secret}",
                              "Content-Type": "application/x-www-form-urlencoded"}, data=b"")
    if st == 200:
        try:
            j = json.loads(body)
        except Exception:
            j = {}
        if j.get("ok"):
            return Verified.LIVE, f"Slack team: {j.get('team')} user: {j.get('user')}"
        return Verified.DEAD, j.get("error", "rechazada")
    return _result(st, "")


def _stripe(secret):
    auth = base64.b64encode((secret + ":").encode()).decode()
    st, _ = _http("https://api.stripe.com/v1/account", headers={"Authorization": f"Basic {auth}"})
    return _result(st, "clave Stripe VIVA", dead_codes=(401,))


def _sendgrid(secret):
    st, _ = _http("https://api.sendgrid.com/v3/scopes", headers={"Authorization": f"Bearer {secret}"})
    return _result(st, "SendGrid VIVA")


def _npm(secret):
    st, body = _http("https://registry.npmjs.org/-/whoami", headers={"Authorization": f"Bearer {secret}"})
    if st == 200:
        try:
            user = json.loads(body).get("username")
        except Exception:
            user = None
        return Verified.LIVE, f"npm user: {user}"
    return _result(st, "", dead_codes=(401,))


def _digitalocean(secret):
    st, _ = _http("https://api.digitalocean.com/v2/account", headers={"Authorization": f"Bearer {secret}"})
    return _result(st, "DigitalOcean VIVA", dead_codes=(401,))


def _postman(secret):
    st, _ = _http("https://api.getpostman.com/me", headers={"X-Api-Key": secret})
    return _result(st, "Postman VIVA")


def _telegram(secret):
    st, body = _http(f"https://api.telegram.org/bot{secret}/getMe")
    if st == 200 and '"ok":true' in body:
        return Verified.LIVE, "Telegram bot VIVO"
    return _result(st, "", dead_codes=(401, 404))


def _discord(secret):
    st, _ = _http("https://discord.com/api/users/@me", headers={"Authorization": f"Bot {secret}"})
    return _result(st, "Discord bot VIVO", dead_codes=(401,))


VERIFIERS = {
    "github": _github, "gitlab": _gitlab, "slack": _slack, "stripe": _stripe,
    "sendgrid": _sendgrid, "npm": _npm, "digitalocean": _digitalocean,
    "postman": _postman, "telegram": _telegram, "discord": _discord,
}


def verify_single(verifier_key: str, secret: str):
    fn = VERIFIERS.get(verifier_key)
    if not fn:
        return Verified.UNKNOWN, None
    try:
        return fn(secret)
    except Exception:
        return Verified.UNKNOWN, "error"


def verify_aws_pair(access_key: str, secret_key: str):
    """Verifica un par AWS con STS GetCallerIdentity (firma SigV4)."""
    service, region, host = "sts", "us-east-1", "sts.amazonaws.com"
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    t = _dt.datetime.now(_dt.timezone.utc)
    amz = t.strftime("%Y%m%dT%H%M%SZ")
    ds = t.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canon_headers = f"content-type:application/x-www-form-urlencoded\nhost:{host}\nx-amz-date:{amz}\n"
    signed = "content-type;host;x-amz-date"
    canon = f"POST\n/\n\n{canon_headers}\n{signed}\n{payload_hash}"
    scope = f"{ds}/{region}/{service}/aws4_request"
    string_to_sign = f"AWS4-HMAC-SHA256\n{amz}\n{scope}\n{hashlib.sha256(canon.encode()).hexdigest()}"

    def _sign(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _sign(("AWS4" + secret_key).encode(), ds)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    auth = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={signed}, Signature={signature}")
    st, resp = _http(f"https://{host}/", method="POST",
                     headers={"Content-Type": "application/x-www-form-urlencoded",
                              "X-Amz-Date": amz, "Authorization": auth},
                     data=body.encode())
    if st == 200:
        arn = re.search(r"<Arn>([^<]+)</Arn>", resp)
        acc = re.search(r"<Account>([^<]+)</Account>", resp)
        return Verified.LIVE, f"AWS VIVA — cuenta {acc.group(1) if acc else '?'} / {arn.group(1) if arn else '?'}"
    return _result(st, "", dead_codes=(401, 403))
