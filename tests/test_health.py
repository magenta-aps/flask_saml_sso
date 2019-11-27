from mock import patch, MagicMock
from requests import RequestException
from sqlalchemy.exc import SQLAlchemyError

import health
from tests.util import TestCaseBase


class TestIdpHealth(TestCaseBase):
    @patch("flask_saml_sso.settings.get_saml_settings", new=lambda x: {})
    def test_idp_health_returns_true_idp_reachable(self):
        actual = health.idp(self.app)

        self.assertEqual(True, actual)

    @patch("flask_saml_sso.settings.get_saml_settings", side_effect=ValueError())
    def test_idp_returns_false_if_value_error(self, mock):
        actual = health.idp(self.app)

        self.assertEqual(False, actual)

    @patch("flask_saml_sso.settings.get_saml_settings", side_effect=RequestException())
    def test_idp_returns_false_if_request_exception(self, mock):
        actual = health.idp(self.app)

        self.assertEqual(False, actual)


class TestSessionHealth(TestCaseBase):
    def test_session_database_returns_true_if_database_reachable(self):
        app_mock = MagicMock()
        actual = health.session_database(app_mock)

        self.assertEqual(True, actual)

    def test_session_database_returns_false_if_attribute_error(self):
        app_mock = MagicMock()
        app_mock.session_interface = {}
        actual = health.session_database(app_mock)

        self.assertEqual(False, actual)

    def test_session_database_returns_false_if_sql_alchemy_error(self):
        app_mock = MagicMock()
        app_mock.session_interface.sql_session_model.query.side_effect = (
            SQLAlchemyError()
        )
        actual = health.session_database(app_mock)

        self.assertEqual(False, actual)
