from datetime import datetime

from flask_session import sessions
from itsdangerous import BadSignature, want_bytes


def get_session_interface(app):
    config = app.config.copy()

    config.setdefault('SESSION_SQLALCHEMY', None)
    config.setdefault('SESSION_SQLALCHEMY_TABLE', 'sessions')
    config.setdefault('SESSION_PERMANENT', True)
    config.setdefault('SESSION_USE_SIGNER', False)
    config.setdefault('SESSION_KEY_PREFIX', 'session:')

    return ModifiedSqlAlchemySessionInterface(
        app,
        config['SESSION_SQLALCHEMY'],
        config['SESSION_SQLALCHEMY_TABLE'],
        config['SESSION_KEY_PREFIX'],
        config['SESSION_USE_SIGNER'],
        config['SESSION_PERMANENT']
    )


class ModifiedSqlAlchemySessionInterface(sessions.SqlAlchemySessionInterface):
    """
    SqlAlchemySessionInterface with added support for fetching session from
    request header
    """

    def open_session(self, app, request):
        # XXX: Updated to use cookies and headers
        sid = None
        if request.cookies.get(app.session_cookie_name):
            sid = request.cookies.get(app.session_cookie_name)
        elif request.headers.get(app.session_cookie_name):
            sid = request.headers.get(app.session_cookie_name)
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
            session_id=store_id).first()
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
