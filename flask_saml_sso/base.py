import functools
import requests

import flask
from werkzeug import exceptions

from . import session
from . import sso


def init_app(app):
    """
    Perform initial setup of SSO and Session
    """
    enabled = app.config.setdefault('SAML_AUTH_ENABLE', False)
    if not enabled:
        return

    app.session_interface = session.get_session_interface(app)
    # Create the session database table, if it doesn't exist
    app.session_interface.db.create_all()
    app.register_blueprint(sso.blueprint)


def requires_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if flask.current_app.config['SAML_AUTH_ENABLE']:
            check_saml_authentication()
        return f(*args, **kwargs)
    return decorated


def check_saml_authentication():
    # Check if session exists is valid
    if not flask.session.get(sso.LOGGED_IN):
        raise exceptions.Unauthorized


def get_session_id():
    """
    Fetch session_id from either cookie or request header, whichever has been
    set
    """
    session_key = flask.current_app.session_cookie_name

    if flask.request.headers.get(session_key):
        return flask.request.headers.get(session_key)
    elif flask.request.cookies.get(session_key):
        return flask.request.cookies.get(session_key)
    return None


class SAMLAuth(requests.auth.AuthBase):
    def __init__(self, session_id=None):
        self.session_id = session_id

    def __call__(self, r):
        if self.session_id:
            session_id = self.session_id
        else:
            session_id = get_session_id()
        if session_id:
            session_key = flask.current_app.session_cookie_name
            r.headers[session_key] = session_id

        return r
