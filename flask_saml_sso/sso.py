#
# Copyright (c) 2017-2018, Magenta ApS
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
import contextlib
import os
from urllib import parse

import flask
import functools
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.response import OneLogin_Saml2_Response
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML
from werkzeug import exceptions

from . import session

basedir = os.path.dirname(__file__)

blueprint = flask.Blueprint('sso', __name__, static_url_path='',
                            url_prefix='/saml')


def _get_logger():
    return flask.current_app.logger.getChild('sso')


def _build_error_response(message):
    return flask.jsonify(message), 401


def _get_saml_settings(app):
    """Generate the internal config file for OneLogin"""
    logger = _get_logger()
    config = app.config.copy()

    insecure = config.setdefault('SAML_IDP_INSECURE', False)
    cert_file = config.setdefault('SAML_CERT_FILE', None)
    key_file = config.setdefault('SAML_KEY_FILE', None)
    requests_signed = config.setdefault('SAML_REQUESTS_SIGNED', False)
    saml_idp_metadata_file = config.setdefault('SAML_IDP_METADATA_FILE', None)
    saml_idp_metadata_url = config.setdefault('SAML_IDP_METADATA_URL', None)

    if saml_idp_metadata_file:
        with open(saml_idp_metadata_file, 'r') as idp:
            remote = OneLogin_Saml2_IdPMetadataParser.parse(idp.read())
    else:
        remote = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            saml_idp_metadata_url,
            validate_cert=not insecure
        )

    s = {
        "strict": True,
        "debug": True,
        "sp": {
            "entityId": flask.url_for('sso.metadata', _external=True),
            "assertionConsumerService": {
                "url": flask.url_for('sso.acs', _external=True),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "singleLogoutService": {
                "url": flask.url_for('sso.sls', _external=True),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
        },
        "security": {
            "authnRequestsSigned": requests_signed,
            "logoutRequestSigned": requests_signed
        }
    }

    s.setdefault('sp', {}).update(remote.get('sp'))
    s.setdefault('idp', {}).update(remote.get('idp'))

    if requests_signed:
        try:
            with open(cert_file, 'r') as cf:
                cert = cf.read()
        except OSError:
            logger.exception('Unable to read cert file {}'.format(cert_file))
            raise

        try:
            with open(key_file, 'r') as kf:
                key = kf.read()
        except OSError:
            logger.exception('Unable to read key file {}'.format(key_file))
            raise

        s['sp'].update({
            "x509cert": cert,
            "privateKey": key
        })

    logger.debug('SAML Settings: \n{}'.format(s))

    return s


def _prepare_flask_request():
    """Construct OneLogin-friendly request object from Flask request"""
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = parse.urlparse(flask.request.url)
    return {
        'https': 'on' if flask.request.scheme == 'https' else 'off',
        'http_host': flask.request.host,
        'server_port': url_data.port,
        'script_name': flask.request.path,
        'get_data': flask.request.args.copy(),
        'post_data': flask.request.form.copy()
    }


def _prepare_saml_auth(func):
    """Decorator to create and initialize the OneLogin SAML2 Auth client"""
    @functools.wraps(func)
    def wrapper():
        app = flask.current_app
        config = app.extensions.get('saml')
        if not config:
            config = _get_saml_settings(app)
            app.extensions['saml'] = config
        req = _prepare_flask_request()
        auth = OneLogin_Saml2_Auth(req, config)
        return func(auth)
    return wrapper


@blueprint.route('/api-token/')
def api_token():
    """
    Create a new Service user session with associated API token based on
    the rights of the current logged in user.

    If no user is currently logged in, redirect to SSO flow and return here
    """
    logger = _get_logger()
    logger.debug('API-token called')

    if not flask.session.get(session.LOGGED_IN):
        qargs = parse.urlencode({
            'next': flask.url_for('sso.api_token')
        })
        redirect_url = "{}?{}".format(flask.url_for('sso.sso'), qargs)

        logger.info('User not logged in, redirecting to {}'.format(
            redirect_url))
        return flask.redirect(redirect_url)

    app = flask.current_app
    # Check if user is permitted to create API tokens

    if app.config.get('SAML_API_TOKEN_RESTRICT', False):
        logger.info('Token restriction enabled')

        group = app.config['SAML_API_TOKEN_RESTRICT_ATTR']
        value = app.config['SAML_API_TOKEN_RESTRICT_VALUE']
        attrs = flask.session.get(session.SAML_ATTRIBUTES)

        logger.debug(
            'SAML_API_TOKEN_RESTRICT_ATTR: {}'.format(group))
        logger.debug(
            'SAML_API_TOKEN_RESTRICT_VALUE: {}'.format(value))
        logger.debug('SAML Attributes: {}'.format(attrs))

        if not attrs.get(group) or value not in attrs.get(group):
            logger.info('User not permitted to create API tokens')
            raise exceptions.Forbidden

    session_dict = session.create_session_dict(
        session.SessionType.Service,
        flask.session.get(session.SAML_ATTRIBUTES)
    )
    sid = flask.current_app.session_interface.insert_new_session(session_dict)

    return flask.jsonify(sid)


@blueprint.route('/metadata/')
@_prepare_saml_auth
def metadata(auth):
    """
    SAML metadata endpoint

    Exposes XML configuration of the Service Provider
    """
    logger = _get_logger()
    logger.debug('Metadata called')

    settings = auth.get_settings()
    sp_metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(sp_metadata)

    if errors:
        logger.error('Metadata Errors: {}'.format(errors))
        return _build_error_response(errors)

    logger.debug('XML: \n{}'.format(sp_metadata))

    resp = flask.make_response(sp_metadata, 200)
    resp.headers['Content-Type'] = 'text/xml'
    return resp


@blueprint.route('/sso/')
@_prepare_saml_auth
def sso(auth):
    """
    Initiate SAML single sign-on

    Redirects user to IdP login page specified in metadata
    """
    logger = _get_logger()
    logger.debug('SSO called')

    return_to = flask.request.args.get(
        'next', flask.request.host_url)
    login = auth.login(return_to=return_to)

    logger.debug('RelayState: {}'.format(return_to))
    logger.debug('SSO Request XML: \n{}'.format(auth.get_last_request_xml()))

    logger.info('Redirecting to "{}" to initiate login'.format(login))
    return flask.redirect(login)


@blueprint.route('/acs/', methods=['POST'])
@_prepare_saml_auth
def acs(auth):
    """
    Assertion Consumer Service endpoint

    Called by IdP with SAML assertion when authentication has been performed
    """
    logger = _get_logger()
    logger.debug('ACS called')

    with _allow_duplicate_attribute_names():
        auth.process_response()
    errors = auth.get_errors()

    logger.debug('ACS Response XML: \n{}'.format(
        auth.get_last_response_xml()))
    logger.debug('User attributes: {}'.format(auth.get_attributes()))

    if errors:
        logger.error('ACS Errors: {}'.format(errors))
        return _build_error_response(errors)

    flask.session.update(session.create_session_dict(
        session.SessionType.User,
        auth.get_attributes()
    ))
    # Set SSO specific IdP metadata
    flask.session[session.SAML_NAME_ID] = auth.get_nameid()
    flask.session[session.SAML_SESSION_INDEX] = auth.get_session_index()

    logger.debug('Name ID: {}'.format(auth.get_nameid()))
    logger.debug('SAML Session Index: {}'.format(
        auth.get_session_index()))

    if 'RelayState' in flask.request.form:
        redirect_to = auth.redirect_to(flask.request.form['RelayState'])
    else:
        redirect_to = '/'

    logger.info('Redirecting back to "{}" after login'.format(redirect_to))
    return flask.redirect(redirect_to)


@blueprint.route('/slo/')
@_prepare_saml_auth
def slo(auth):
    """
    Initiate SAML single logout

    Redirects user to IdP SLO specified in metadata
    """
    logger = _get_logger()
    logger.debug('SLO called')

    name_id = flask.session.get(session.SAML_NAME_ID)
    session_index = flask.session.get(session.SAML_SESSION_INDEX)

    logger.debug('Name ID: {}'.format(name_id))
    logger.debug('SAML Session Index: {}'.format(session_index))

    # If session originates from IdP
    if name_id and session_index:
        logout = auth.logout(name_id=name_id, session_index=session_index)
        logger.debug('SLO Request XML: \n{}'.format(
            auth.get_last_request_xml()))
        redirect_to = logout
    else:
        flask.session.clear()
        redirect_to = '/'

    logger.info('Redirecting to "{}" to initiate logout'.format(redirect_to))
    return flask.redirect(redirect_to)


@blueprint.route('/sls/')
@_prepare_saml_auth
def sls(auth):
    """
    Single Logout Service

    Consumes LogoutResponse from IdP when logout has been performed, and
    sends user back to landing page
    """
    logger = _get_logger()
    logger.debug('SLS called')

    # Process the SLO message received from IdP
    url = auth.process_slo(delete_session_cb=lambda: flask.session.clear())
    logger.debug('SLS Response XML: \n{}'.format(
        auth.get_last_response_xml()))

    errors = auth.get_errors()
    if errors:
        logger.error('SLS Errors: {}'.format(errors))
        return _build_error_response(errors)
    if url is not None:
        redirect_to = url
    else:
        redirect_to = '/'

    logger.info('Redirecting back to "{}" after logout'.format(
        redirect_to))
    return flask.redirect(redirect_to)


@contextlib.contextmanager
def _allow_duplicate_attribute_names():  # pragma: no cover
    """
    Patches get_attributes on OneLogin Response object to handle duplicate
    attribute names
    see: https://github.com/onelogin/python3-saml/issues/39
    """
    def _get_attributes_patched(self):
        """
        Gets the Attributes from the AttributeStatement element.
        EncryptedAttributes are not supported

        XXX: Fix for duplicate attribute keys
        see: https://github.com/onelogin/python3-saml/issues/39
        """
        attributes = {}
        attribute_nodes = self._OneLogin_Saml2_Response__query_assertion(
            '/saml:AttributeStatement/saml:Attribute')
        for attribute_node in attribute_nodes:
            attr_name = attribute_node.get('Name')
            # XXX: Fix for duplicate attribute keys
            # if attr_name in attributes.keys():
            #     raise OneLogin_Saml2_ValidationError(
            #         'Found an Attribute element with duplicated Name',
            #         OneLogin_Saml2_ValidationError.DUPLICATED_ATTRIBUTE_NAME_FOUND
            #     )

            values = []
            for attr in attribute_node.iterchildren(
                    '{%s}AttributeValue' % OneLogin_Saml2_Constants.NSMAP[
                        'saml']):
                attr_text = OneLogin_Saml2_XML.element_text(attr)
                if attr_text:
                    attr_text = attr_text.strip()
                    if attr_text:
                        values.append(attr_text)

                # Parse any nested NameID children
                for nameid in attr.iterchildren(
                        '{%s}NameID' % OneLogin_Saml2_Constants.NSMAP[
                            'saml']):
                    values.append({
                        'NameID': {
                            'Format': nameid.get('Format'),
                            'NameQualifier': nameid.get('NameQualifier'),
                            'value': nameid.text
                        }
                    })
            # XXX: Fix for duplicate attribute keys
            attributes[attr_name] = attributes.setdefault(
                attr_name, []) + values
        return attributes

    app = flask.current_app
    if app.config.get('SAML_DUPLICATE_ATTRIBUTES'):
        orig_fn = OneLogin_Saml2_Response.get_attributes
        OneLogin_Saml2_Response.get_attributes = _get_attributes_patched
        yield
        OneLogin_Saml2_Response.get_attributes = orig_fn
    else:
        yield
