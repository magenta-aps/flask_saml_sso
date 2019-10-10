Flask SAML SSO
==============

This package contains a Flask blueprint and session mechanisms for handling
SAML single sign-on with a shared SQL session store.

Usage
-----

The auth module is imported and added to the Flask app with the following.

.. code-block:: python

    import flask_saml_sso
    flask_saml_sso.init_app(app)
    flask_saml_sso.init_sessions_table(app)

This registers the blueprint, adding all the relevant endpoints, as well as
initializing the session backend.

Single sign-on and logout
^^^^^^^^^^^^^^^^^^^^^^^^^
We support SAML 2.0 Web-based SSO for login and logout. Currently, we support
the HTTP-POST binding for login, and HTTP-Redirect for logout.

For login and logout, redirect the user to either ``/saml/sso`` or
``/saml/slo`` respectively. Once a user successfully logs in, a session is
created in the session store with the user attributes given to us by the IdP.
The session ID is then attached to the response as a cookie.
Each session has an expiry, which is refreshed whenever the session is accessed.

As an alternative to cookies, the session ID can also be supplied as a header,
with the same name as the cookie. The header will be checked first,
over the cookie.

========================    ==================================================
Endpoint                    Description
========================    ==================================================
``/saml/metadata``          The XML SP metadata for the application. Used for
                            configuring the application as a Service Provider
                            with the IdP
``/saml/sso``               Initiate single sign-on flow, redirecting the user
                            to the IdP login page
``/saml/acs``               Assertion Consumer Service, used for handling login
                            responses from IdP
``/saml/slo``               Initiate single logout. Redirects to IdP page for
                            logout. Logs user out of both our own and the
                            IdP's session
``/saml/sls``               Single Logout Service, used for handling logout
                            responses from IdP
========================    ==================================================

API tokens
^^^^^^^^^^

It is possible to generate API tokens, with corresponding sessions that have a
much longer expiry than normal sessions.

The API token is created based on the current user's SAML attributes.
Furthermore, creation of API tokens can be restricted to users with
certain attributes with the configuration entries,
``SAML_API_TOKEN_RESTRICT``, ``SAML_API_TOKEN_RESTRICT_ATTR``
and ``SAML_API_TOKEN_RESTRICT_VALUE``.

The API token is used similarly to normal session ID and can be attached as a
header in the same fashion.

========================    ==================================================
Endpoint                    Description
========================    ==================================================
``/saml/api-token``         Generate an API token. User creating token
                            must be logged in.
========================    ==================================================


Configuration
-------------

The most relevant configuration settings are listed in the table below.

+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Config key                                  | Default                                                   | Description                                                                                                                                                                   |
+=============================================+===========================================================+===============================================================================================================================================================================+
| ``SAML_AUTH_ENABLE``                        | True                                                      | Whether auth should be enabled                                                                                                                                                |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_IDP_INSECURE``                       | False                                                     | Whether the certificate of the IdP metadata should be considered insecure, e.g. when dealing with self-signed certificates                                                    |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_FORCE_HTTPS``                        | False                                                     | Whether to force framework to use HTTPS for its own endpoints                                                                                                                 |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_NAME_ID_FORMAT``                     | ``urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`` | The NameID format to expose in metadata and in AuthN requests                                                                                                                 |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_WANT_NAME_ID``                       | True                                                      | Whether or not to expect NameID in response                                                                                                                                   |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_WANT_ATTRIBUTE_STATEMENT``           | False                                                     | Whether or not to expect an AttributeStatement in response                                                                                                                    |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_REQUESTED_AUTHN_CONTEXT``            | True                                                      | The ``RequestedAuthnContext`` sent in the AuthN request. ``True`` is a default of AuthContext 'exact' and 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_REQUESTED_AUTHN_CONTEXT_COMPARISON`` | ``exact``                                                 | The ``comparison`` parameter in the ``RequestedAuthnContext`` in the AuthN request.                                                                                           |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_LOWERCASE_URLENCODING``              | True                                                      | Support for lowercased URL-encoding when verifying signatures on logout responses. **Turn this on for ADFS as IdP**                                                           |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_REQUESTS_SIGNED``                    | False                                                     | Whether requests towards the IdP should be signed.                                                                                                                            |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_CERT_FILE``                          | None                                                      | Path to a public certificate file, used for signing requests.                                                                                                                 |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_KEY_FILE``                           | None                                                      | Path to private key file, used for signing requests.                                                                                                                          |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_SIGNATURE_ALGORITHM``                | ``http://www.w3.org/2001/04/xmldsig-more#rsa-sha256``     | The algorithm used for signing requests.  See https://github.com/onelogin/python3-saml#settings for available options.                                                        |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_DIGEST_ALGORITHM``                   | ``http://www.w3.org/2001/04/xmlenc#sha256``               |                                                                                                                                                                               |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_IDP_METADATA_URL``                   |                                                           | The URL to the IdPs metadata                                                                                                                                                  |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_IDP_METADATA_FILE``                  | None                                                      | The path to a file containing IdP metadata.  This parameter will override the URL parameter.                                                                                  |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_DUPLICATE_ATTRIBUTES``               | False                                                     | Adds support for handling multiple attributes with the same name in the SAML Assertion                                                                                        |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SQLALCHEMY_DATABASE_URI``                 |                                                           | A connection string used to connect to the underlying database containing sessions                                                                                            |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSION_SQLALCHEMY_TABLE``                | sessions                                                  | The name of the table containing sessions                                                                                                                                     |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSIONS_DB_USER``                        | sessions                                                  | The username of the sessions database user, note that these settings are only relevant if ``SQL_ALCHEMY_DATABASE_URI`` is not set                                             |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSIONS_DB_PASSWORD``                    | sessions                                                  | The password of the sessions database user                                                                                                                                    |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSIONS_DB_HOST``                        | localhost                                                 | The hostname of the sessions database                                                                                                                                         |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSIONS_DB_PORT``                        | 5432                                                      | The port for the sessions database                                                                                                                                            |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSIONS_DB_NAME``                        | sessions                                                  | The name of the sessions database                                                                                                                                             |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``PERMANENT_SESSION_LIFETIME``              | 2678400 (31 days)                                         | How long, in seconds, the session should be allowed to live before expiring                                                                                                   |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_SERVICE_SESSION_LIFETIME``           | 2678400 (31 days)                                         | How long, in seconds, a service session should be allowed to live before expiring                                                                                             |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SESSION_COOKIE_NAME``                     | session                                                   | The name of the session cookie/request header used to store session id.                                                                                                       |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_API_TOKEN_RESTRICT``                 | False                                                     | Restrict creation of API tokens                                                                                                                                               |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_API_TOKEN_RESTRICT_ATTR``            |                                                           | The name of the attribute containing information information on whether or not a given user can create API tokens                                                             |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ``SAML_API_TOKEN_RESTRICT_VALUE``           |                                                           | The value of the aforementioned attribute which gives a user the permission to create API tokens                                                                              |
+---------------------------------------------+-----------------------------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Logging
-------

The module performs extensive logging using the Flask app logging mechanism,
through a child logger named ``sso``.

- ``ERROR`` logs all errors that occur.
- ``INFO`` additionally provides a rough overview of the control flow.
- ``DEBUG`` additionally provides an overview of relevant variables and the various request and response XML payloads.
