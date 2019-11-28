import logging

from requests import RequestException

from flask_saml_sso import settings
from sqlalchemy.exc import SQLAlchemyError

logger = logging.getLogger(__name__)


def session_database(app):
    """Verify whether the session database can be reached"""
    try:
        app.session_interface.sql_session_model.query.first()
    except (AttributeError, SQLAlchemyError) as e:
        logger.exception("Sessions database error {}".format(e))
        return False
    return True


def idp(app):
    """Verify whether the IdP can be reached"""
    try:
        settings.get_saml_settings(app)
    except (ValueError, RequestException) as e:
        logger.exception("Auth IdP error: {}".format(e))
        return False
    return True
