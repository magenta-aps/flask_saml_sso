import enum

from datetime import datetime
from datetime import timedelta

import flask
from flask_session import sessions
from itsdangerous import BadSignature, want_bytes

LOGGED_IN = 'loggedIn'
SAML_SESSION_INDEX = 'samlSessionIndex'
SAML_NAME_ID = 'samlNameId'
SAML_ATTRIBUTES = 'samlAttributes'
SAML_SESSION_TYPE = 'samlSessionType'


class SessionType(enum.Enum):
    User = 1
    Service = 2


def create_session_dict(session_type: SessionType, attributes: dict):
    logger = flask.current_app.logger.getChild('sso')

    session_dict = {
        SAML_SESSION_TYPE: session_type,
        SAML_ATTRIBUTES: attributes,
        LOGGED_IN: True,
    }
    logger.info('Creating session: {}'.format(session_dict))

    return session_dict


def get_session_interface(app):
    config = app.config.copy()

    config.setdefault('SESSION_SQLALCHEMY', None)
    config.setdefault('SESSION_SQLALCHEMY_TABLE', 'sessions')
    config.setdefault('SESSION_PERMANENT', True)
    config.setdefault('SESSION_USE_SIGNER', False)
    config.setdefault('SESSION_KEY_PREFIX', 'session:')

    return SqlAlchemySessionInterfaceWithHeaders(
        app,
        config['SESSION_SQLALCHEMY'],
        config['SESSION_SQLALCHEMY_TABLE'],
        config['SESSION_KEY_PREFIX'],
        config['SESSION_USE_SIGNER'],
        config['SESSION_PERMANENT'],
    )


class SqlAlchemySessionInterfaceWithHeaders(sessions.SqlAlchemySessionInterface):
    """
    SqlAlchemySessionInterface with added support for fetching session from
    request header, as well as support for inserting additional sessions aside
    from the one currently active
    """

    def insert_new_session(self, session_dict):
        """
        Insert a new session in the session store, outside of the
        currently active session
        """
        app = flask.current_app

        sid = self._generate_sid()
        store_id = self.key_prefix + sid
        expires = self.get_session_expiration_time_by_type(app, SessionType.Service)

        session_obj = self.session_class(session_dict, sid=sid, permanent=True)

        new_session = self.sql_session_model(
            store_id, self.serializer.dumps(dict(session_obj)), expires
        )

        self.db.session.add(new_session)

        return sid

    def get_session_expiration_time_by_type(self, app, session_type: SessionType):
        if session_type == SessionType.Service:
            lifetime_seconds = app.config.get('SAML_SERVICE_SESSION_LIFETIME', 2678400)
            return datetime.utcnow() + timedelta(seconds=lifetime_seconds)
        else:
            return datetime.utcnow() + app.permanent_session_lifetime

    def get_expiration_time(self, app, session):
        if session.permanent:
            return self.get_session_expiration_time_by_type(
                app, session.get(SAML_SESSION_TYPE)
            )

    def _get_sid(self, app, request):
        # Fetch session ID from either header, or cookie
        if request.headers.get(app.session_cookie_name):
            return request.headers.get(app.session_cookie_name)
        elif request.cookies.get(app.session_cookie_name):
            return request.cookies.get(app.session_cookie_name)
        else:
            return None

    def open_session(self, app, request):  # pragma: no cover
        # XXX: Updated to use cookies and headers
        sid = self._get_sid(app, request)
        if not sid:
            sid = self._generate_sid()
            return self.session_class(sid=sid, permanent=self.permanent)
        if self.use_signer:
            signer = self._get_signer(app)
            if signer is None:
                return None
            try:
                sid_as_bytes = signer.unsign(sid)
                sid = sid_as_bytes.decode()
            except BadSignature:
                sid = self._generate_sid()
                return self.session_class(sid=sid, permanent=self.permanent)

        store_id = self.key_prefix + sid
        saved_session = self.sql_session_model.query.filter_by(
            session_id=store_id
        ).first()
        if saved_session and saved_session.expiry <= datetime.utcnow():
            # Delete expired session
            self.db.session.delete(saved_session)
            self.db.session.commit()
            saved_session = None
        if saved_session:
            try:
                val = saved_session.data
                data = self.serializer.loads(want_bytes(val))
                return self.session_class(data, sid=sid)
            except:
                return self.session_class(sid=sid, permanent=self.permanent)
        return self.session_class(sid=sid, permanent=self.permanent)
