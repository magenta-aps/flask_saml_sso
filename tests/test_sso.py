#
# Copyright (c) 2017-2018, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
import base64
import os
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs, urlencode

import flask
import freezegun
from flask_testing import TestCase
from onelogin.saml2.utils import OneLogin_Saml2_Utils as saml_utils

import flask_saml_sso
from flask_saml_sso import sso

TESTS_DIR = os.path.dirname(__file__)


class TestSSO(TestCase):

    def create_app(self):
        app = flask.Flask(__name__)

        app.config['SAML_AUTH_ENABLE'] = True
        app.config['SAML_IDP_METADATA_FILE'] = TESTS_DIR + '/sso/idp.xml'
        app.config['SERVER_NAME'] = "127.0.0.1:5000"

        flask_saml_sso.init_app(app)
        return app

    def get_sso_response(self):
        with open(TESTS_DIR + '/sso/sso_response.xml', 'rb') as sso_response:
            return base64.b64encode(sso_response.read())

    def get_slo_response(self):
        with open(TESTS_DIR + '/sso/slo_response.xml', 'rb') as slo_response:
            return saml_utils.deflate_and_base64_encode(slo_response.read())

    def test_sso_redirects_to_login_with_next(self):
        r = self.client.get('/saml/sso/?next=http://redirect.me/to/here')
        url = urlparse(r.location)
        query = parse_qs(url.query)

        self.assertEqual(302, r.status_code)
        self.assertEqual('https', url.scheme)
        self.assertEqual('192.168.1.212', url.netloc)
        self.assertEqual('/simplesaml/saml2/idp/SSOService.php', url.path)
        self.assertEqual('http://redirect.me/to/here',
                         query.get('RelayState')[0])

    def test_sso_redirects_to_login_with_no_next(self):
        r = self.client.get('/saml/sso/')
        url = urlparse(r.location)
        query = parse_qs(url.query)

        self.assertEqual(302, r.status_code)
        self.assertEqual('https', url.scheme)
        self.assertEqual('192.168.1.212', url.netloc)
        self.assertEqual('/simplesaml/saml2/idp/SSOService.php', url.path)
        self.assertEqual('http://127.0.0.1:5000/',
                         query.get('RelayState')[0])

    @freezegun.freeze_time('2018-09-17T13:30:00Z')
    def test_acs_redirects_correctly_with_relaystate(self):
        data = {
            'SAMLResponse': self.get_sso_response(),
            'RelayState': 'http://redirect.me/to/here'
        }
        r = self.client.post('/saml/acs/', data=data)

        self.assertEqual(302, r.status_code)
        self.assertEqual('http://redirect.me/to/here', r.location)

    @freezegun.freeze_time('2018-09-17T13:30:00Z')
    def test_acs_redirects_correctly_with_no_relaystate(self):
        data = {
            'SAMLResponse': self.get_sso_response(),
        }
        r = self.client.post('/saml/acs/', data=data)

        self.assertEqual(302, r.status_code)
        self.assertEqual('http://127.0.0.1:5000/', r.location)

    @freezegun.freeze_time('2018-09-17T13:30:00Z')
    def test_acs_sets_session_correctly(self):
        data = {
            'SAMLResponse': self.get_sso_response(),
        }
        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get('MO-Token'))

        r = self.client.post('/saml/acs/', data=data)

        samlUserData = {
            'urn:oid:0.9.2342.19200300.100.1.1': ['bruce'],
            'urn:oid:0.9.2342.19200300.100.1.3': ['bruce@kung.fu'],
            'urn:oid:2.5.4.41': ['Bruce Lee']
        }
        samlNameId = '_e3dfaf3e3385fd182b1c4d4164644393cce3ac7bfe'
        samlSessionIndex = '_6a54ed11e21b64af1a0380b1fba3ec575b05855465'

        with self.client.session_transaction() as sess:
            self.assertEqual(samlUserData, sess.get('samlAttributes'))
            self.assertEqual(samlNameId, sess.get('samlNameId'))
            self.assertEqual(samlSessionIndex, sess.get('samlSessionIndex'))

    @freezegun.freeze_time('2010-09-17T13:30:00Z')
    def test_acs_returns_error_when_timestamp_is_not_valid(self):
        data = {
            'SAMLResponse': self.get_sso_response(),
        }

        expected = ['invalid_response']

        r = self.client.post('/saml/acs/', data=data)

        self.assertEqual(401, r.status_code)
        self.assertEqual(expected, r.json)

    def test_slo_redirects_to_logout_page(self):
        with self.client.session_transaction() as sess:
            sess[flask_saml_sso.session.SAML_SESSION_INDEX] = '1234'
            sess[flask_saml_sso.session.SAML_NAME_ID] = '1234'

        r = self.client.get('/saml/slo/')
        url = urlparse(r.location)

        self.assertEqual(302, r.status_code)
        self.assertEqual('https', url.scheme)
        self.assertEqual('192.168.1.212', url.netloc)
        self.assertEqual('/simplesaml/saml2/idp/SingleLogoutService.php',
                         url.path)

    def test_sls_redirects_correctly(self):
        data = {
            'SAMLResponse': self.get_slo_response(),
        }
        r = self.client.get('/saml/sls/', query_string=urlencode(data))

        self.assertEqual(302, r.status_code)
        self.assertEqual('http://127.0.0.1:5000/', r.location)

    def test_sls_deletes_session(self):
        data = {
            'SAMLResponse': self.get_slo_response(),
        }

        with self.client.session_transaction() as sess:
            sess[flask_saml_sso.session.LOGGED_IN] = True

        r = self.client.get('/saml/sls/', query_string=urlencode(data))

        with self.client.session_transaction() as sess:
            self.assertFalse(sess.get(flask_saml_sso.session.LOGGED_IN))

    @patch('onelogin.saml2.auth.OneLogin_Saml2_Auth.get_errors',
           lambda *x, **y: ['ERROR 2'])
    def test_sls_returns_errors(self):
        data = {
            'SAMLResponse': self.get_slo_response(),
        }

        r = self.client.get('/saml/sls/', query_string=urlencode(data))

        expected = ['ERROR 2']

        self.assertEqual(401, r.status_code)
        self.assertEqual(expected, r.json)

    def test_metadata_returns_metadata(self):
        ns = 'onelogin.saml2.settings.OneLogin_Saml2_Settings'
        metadata = b"<metadata/>"

        with patch(ns + '.validate_metadata') as validate, \
            patch(ns + '.get_sp_metadata') as get_sp:
            validate.return_value = False
            get_sp.return_value = metadata

            r = self.client.get('/saml/metadata/')

        self.assertEqual(metadata, r.data)
        self.assertIn(('Content-Type', 'text/xml'), list(r.headers))

    @patch(
        'onelogin.saml2.settings.OneLogin_Saml2_Settings.validate_metadata',
        lambda *x, **y: ['ERROR 3', 'ERROR 4']
    )
    def test_metadata_returns_errors(self):
        r = self.client.get('/saml/metadata/')

        expected = ['ERROR 3', 'ERROR 4']

        self.assertEqual(401, r.status_code)
        self.assertEqual(expected, r.json)

    def test_api_token_redirects_on_invalid_session(self):
        r = self.client.get('/saml/api-token/')

        self.assertEqual(302, r.status_code)

    def test_api_token(self):
        """Assert that an API token is created corresponding to a Service
        session with the same attributes as the creating session"""
        attributes = {'whatever': 1234}

        with self.client.session_transaction() as sess:
            sess[flask_saml_sso.session.LOGGED_IN] = True
            sess[flask_saml_sso.session.SAML_ATTRIBUTES] = attributes

        r = self.client.get('/saml/api-token/')
        self.assertEqual(200, r.status_code)

        expected_api_session = {
            flask_saml_sso.session.SAML_ATTRIBUTES: attributes,
            flask_saml_sso.session.SAML_SESSION_TYPE:
                flask_saml_sso.session.SessionType.Service,
            flask_saml_sso.session.LOGGED_IN: True,
            '_permanent': True
        }

        with self.app.test_request_context('/saml/metadata/',
                                           headers={'session': r.json}):
            self.assertEqual(expected_api_session, flask.session)

    def test_api_token_with_restriction(self):
        """Assert that api token creation returns 200 when restriction is
        enabled and sufficient permissions are available"""
        self.app.config['SAML_API_TOKEN_RESTRICT'] = True
        self.app.config['SAML_API_TOKEN_RESTRICT_ATTR'] = 'roles'
        self.app.config['SAML_API_TOKEN_RESTRICT_VALUE'] = 'allowed'

        attributes = {'roles': ['allowed']}

        with self.client.session_transaction() as sess:
            sess[flask_saml_sso.session.LOGGED_IN] = True
            sess[flask_saml_sso.session.SAML_ATTRIBUTES] = attributes

        r = self.client.get('/saml/api-token/')
        self.assertEqual(200, r.status_code)

    def test_api_token_returns_403_on_restricted_access(self):
        """Assert that api token creation returns 403 when restriction is
        enabled and unsufficient permissions are available"""
        self.app.config['SAML_API_TOKEN_RESTRICT'] = True
        self.app.config['SAML_API_TOKEN_RESTRICT_ATTR'] = 'asd'
        self.app.config['SAML_API_TOKEN_RESTRICT_VALUE'] = 'asd'

        attributes = {'whatever': 1234}

        with self.client.session_transaction() as sess:
            sess[flask_saml_sso.session.LOGGED_IN] = True
            sess[flask_saml_sso.session.SAML_ATTRIBUTES] = attributes

        r = self.client.get('/saml/api-token/')
        self.assertEqual(403, r.status_code)
