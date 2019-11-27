import os

import flask
from flask_testing import TestCase

import flask_saml_sso

TESTS_DIR = os.path.dirname(__file__)


class TestCaseBase(TestCase):
    maxDiff = None

    def create_app(self):
        app = flask.Flask(__name__)

        app.config["SAML_AUTH_ENABLE"] = True
        app.config["SAML_IDP_METADATA_FILE"] = TESTS_DIR + "/sso/idp.xml"
        app.config["SERVER_NAME"] = "127.0.0.1:5000"
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"

        flask_saml_sso.init_app(app)
        flask_saml_sso.init_sessions_table(app)

        return app
