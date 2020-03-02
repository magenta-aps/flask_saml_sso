import logging

import flask
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

logger = logging.getLogger(__name__)


def _generate_url_for(schema: str, host: str, endpoint: str):
    return "{}://{}{}".format(schema, host, flask.url_for(endpoint))


def _get_saml_sp_settings(app):
    config = app.config.copy()

    name_id_format = config.setdefault(
        'SAML_NAME_ID_FORMAT', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'
    )
    force_https = config.setdefault('SAML_FORCE_HTTPS', False)

    sp_domain = config.setdefault('SAML_SP_DOMAIN', None)

    cert_file = config.setdefault('SAML_CERT_FILE', None)
    key_file = config.setdefault('SAML_KEY_FILE', None)
    requests_signed = config.setdefault('SAML_REQUESTS_SIGNED', False)

    if sp_domain:
        url_scheme = 'https' if force_https else 'http'
        entity_id = _generate_url_for(url_scheme, sp_domain, 'sso.metadata')
        acs = _generate_url_for(url_scheme, sp_domain, 'sso.acs')
        sls = _generate_url_for(url_scheme, sp_domain, 'sso.sls')
    else:
        # If not forcing HTTPS, set to None, to make url_for handle it on its own
        url_scheme = 'https' if force_https else None
        entity_id = flask.url_for('sso.metadata', _external=True, _scheme=url_scheme)
        acs = flask.url_for('sso.acs', _external=True, _scheme=url_scheme)
        sls = flask.url_for('sso.sls', _external=True, _scheme=url_scheme)

    sp_settings = {
        "sp": {
            "entityId": entity_id,
            "assertionConsumerService": {
                "url": acs,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sls,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": name_id_format,
        }
    }

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

        sp_settings['sp'].update({"x509cert": cert, "privateKey": key})

    return sp_settings


def _get_saml_idp_settings(app):
    config = app.config.copy()

    saml_idp_metadata_file = config.setdefault('SAML_IDP_METADATA_FILE', None)
    saml_idp_metadata_url = config.setdefault('SAML_IDP_METADATA_URL', None)
    insecure = config.setdefault('SAML_IDP_INSECURE', False)

    if saml_idp_metadata_file:
        with open(saml_idp_metadata_file, 'r') as idp:
            idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(idp.read())
    else:
        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            saml_idp_metadata_url, validate_cert=not insecure
        )

    return idp_settings


def _get_saml_security_settings(app):
    config = app.config.copy()

    signature_algorithm = config.setdefault(
        'SAML_SIGNATURE_ALGORITHM', 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
    )
    digest_algorithm = config.setdefault(
        'SAML_DIGEST_ALGORITHM', 'http://www.w3.org/2001/04/xmlenc#sha256'
    )
    requests_signed = config.setdefault('SAML_REQUESTS_SIGNED', False)
    want_name_id = config.setdefault('SAML_WANT_NAME_ID', True)
    want_attribute_statement = config.setdefault('SAML_WANT_ATTRIBUTE_STATEMENT', False)
    requested_authn_context = config.setdefault('SAML_REQUESTED_AUTHN_CONTEXT', True)
    requested_authn_context_comparison = config.setdefault(
        'SAML_REQUESTED_AUTHN_CONTEXT_COMPARISON', 'exact'
    )

    return {
        "security": {
            "authnRequestsSigned": requests_signed,
            "logoutRequestSigned": requests_signed,
            "signatureAlgorithm": signature_algorithm,
            "digestAlgorithm": digest_algorithm,
            "wantNameId": want_name_id,
            "wantAttributeStatement": want_attribute_statement,
            "requestedAuthnContext": requested_authn_context,
            "requestedAuthnContextComparison": requested_authn_context_comparison,
        }
    }


def get_saml_settings(app, idp=True):
    """Generate the internal config file for OneLogin"""
    config = app.config.copy()
    strict = config.setdefault('SAML_STRICT', True)
    debug = config.setdefault('SAML_DEBUG', False)

    s = {"strict": strict, "debug": debug}

    if idp:
        s.update(_get_saml_idp_settings(app))
    s.update(_get_saml_security_settings(app))
    s.update(_get_saml_sp_settings(app))

    return s
