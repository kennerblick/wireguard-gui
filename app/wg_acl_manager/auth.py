"""Optionale HTTP-Basic-Auth fuer die gesamte Web-UI."""

import hmac

from flask import Response, request

from . import app, config


@app.before_request
def require_basic_auth():
    if not config.ADMIN_USER or not config.ADMIN_PASSWORD:
        return None
    if request.endpoint == "static":
        return None
    auth = request.authorization
    if (
        auth
        and hmac.compare_digest(auth.username or "", config.ADMIN_USER)
        and hmac.compare_digest(auth.password or "", config.ADMIN_PASSWORD)
    ):
        return None
    return Response(
        "Anmeldung erforderlich.",
        401,
        {"WWW-Authenticate": 'Basic realm="WireGuard ACL Manager"'},
    )
