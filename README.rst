Flask SAML SSO
==============

This package contains a Flask blueprint and session mechanisms for handling
SAML single sign-on with a shared SQL session store.

Configuration
-------------

The most relevant configuration settings are listed in the table below.

==================================  ==================  ============================================
Config key                          Default             Description
==================================  ==================  ============================================
``SAML_AUTH_ENABLE``                True                Whether auth should be enabled
``SAML_IDP_INSECURE``               False               Whether the certificate of the IdP metadata
                                                        should be considered insecure, e.g. when
                                                        dealing with self-signed certificates
``SAML_REQUESTS_SIGNED``            False               Whether requests towards the IdP should be
                                                        signed.
``SAML_CERT_FILE``                  None                Path to a public certificate file, used for
                                                        signing requests.
``SAML_KEY_FILE``                   None                Path to private key file, used for signing
                                                        requests.
``SAML_IDP_METADATA_URL``                               The URL to the IdPs metadata
``SAML_IDP_METADATA_FILE``          None                The path to a file containing IdP metadata.
                                                        This parameter will override the URL
                                                        parameter.
``SAML_DUPLICATE_ATTRIBUTES``       False               Adds support for handling multiple
                                                        attributes with the same name in the SAML
                                                        Assertion
``SQLALCHEMY_DATABASE_URI``                             A connection string used to connect to the
                                                        underlying database containing sessions
``SESSION_SQLALCHEMY_TABLE``        sessions            The name of the table containing sessions
``PERMANENT_SESSION_LIFETIME``      2678400 (31 days)   How long, in seconds, the session should
                                                        be allowed to live before expiring
``SAML_SERVICE_SESSION_LIFETIME``   2678400 (31 days)   How long, in seconds, a service session
                                                        should be allowed to live before expiring
``SESSION_COOKIE_NAME``             session             The name of the session cookie/request
                                                        header used to store session id.
``SAML_API_TOKEN_RESTRICT``         False               Restrict creation of API tokens
``SAML_API_TOKEN_RESTRICT_ATTR``                        The name of the attribute containing
                                                        information information on whether or not
                                                        a given user can create API tokens
``SAML_API_TOKEN_RESTRICT_VALUE``                       The value of the aforementioned attribute
                                                        which gives a user the permission to create
                                                        API tokens
==================================  ==================  ============================================

