#
# Copyright (c) 2017-2018, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
import os
from unittest.mock import MagicMock

import flask
import werkzeug
from flask_testing import TestCase
from werkzeug.http import dump_cookie

import flask_saml_sso

TESTS_DIR = os.path.dirname(__file__)


class TestBase(TestCase):
    def create_app(self):
        app = flask.Flask(__name__)

        app.config['SAML_AUTH_ENABLE'] = True
        app.config['SAML_IDP_METADATA_FILE'] = TESTS_DIR + '/sso/idp.xml'
        app.config['SERVER_NAME'] = "127.0.0.1:5000"

        flask_saml_sso.init_app(app)
        return app

    def test_init_app_disabled(self):
        """Assert that we don't add blueprint and session interface if
        auth is disabled"""
        app = MagicMock()
        app.config = {'SAML_AUTH_ENABLE': False}
        expected_interface = app.session_interface

        flask_saml_sso.init_app(app)

        self.assertEqual(expected_interface, app.session_interface)
        app.register_blueprint.assert_not_called()

    def test_check_saml_authentication_raises_on_invalid_session(self):
        with self.assertRaises(werkzeug.exceptions.Unauthorized):
            flask_saml_sso.check_saml_authentication()

    def test_check_saml_authentication_does_not_raise_on_valid_session(self):
        flask.session[flask_saml_sso.session.LOGGED_IN] = True

        # No exceptions should be raised
        flask_saml_sso.check_saml_authentication()

    def test_get_session_id_from_header(self):
        expected_session_id = "e545bd7d-e0f5-4605-9f15-9626a5cfc337"

        cookie_name = self.app.session_cookie_name

        with self.app.test_request_context(
            headers={cookie_name: expected_session_id}
        ) as rctx:
            actual_session_id = flask_saml_sso.get_session_id()

        self.assertEqual(expected_session_id, actual_session_id)

    def test_get_session_id_from_cookie(self):
        expected_session_id = "e545bd7d-e0f5-4605-9f15-9626a5cfc337"

        cookie_name = self.app.session_cookie_name

        header = dump_cookie(cookie_name, expected_session_id)

        with self.app.test_request_context(environ_base={'HTTP_COOKIE': header}):
            actual_session_id = flask_saml_sso.get_session_id()

        self.assertEqual(expected_session_id, actual_session_id)

    def test_get_session_id_none(self):
        actual_session_id = flask_saml_sso.get_session_id()

        self.assertEqual(None, actual_session_id)

    def test_get_session_attributes(self):
        expected_attributes = {'whatever': '1234'}

        flask.session[flask_saml_sso.session.SAML_ATTRIBUTES] = expected_attributes

        actual_attributes = flask_saml_sso.get_session_attributes()

        self.assertEqual(expected_attributes, actual_attributes)
