### Login example using bottle.py

from bottle import route, response, request, redirect, debug, run

import saml

# saml.py using the logging module, and a logger called 'saml'
# use DEBUG for verbose output
import logging
logger = logging.getLogger('saml')
logger.setLevel(logging.DEBUG)
# optionally configure logging for custom output
#log_fmt = logging.Formatter("%(asctime)s:%(levelname)s:%(name)s: %(message)s")
#handler = logging.StreamHandler()
#handler.setFormatter(log_fmt)
#logger.addHandler(handler)


# First, register metadata for both parties

## Service Provider metadata
# entityID registered with the IdP
saml.SP['entityID'] = 'https://sp.test.org/shibboleth-sp'
# Assertion Consumer Server URL
saml.SP['ACS'] = 'https://sp.test.org/SSO'

# Identity Provider metadata
saml.IdP['entityID'] = 'https://idp.test.org/idp/shibboleth'
saml.IdP['SingleSignOnService'] = 'https://idp.test.org/idp/profile/SAML2/Redirect/SSO'
# the X509 certificate must in PEM form, including BEGIN and END lines
with open('idp.pem') as pem:
    saml.IdP['X509'] = pem.read()



# Accessing this path (/login) starts the authentication process.
# Calling saml.request() generates the URL for the redirect.
# The relay_state paramter is optional, and will be returned to you 
# after authentication.
@route('/login')
def login():
    final_destination = 'http://sp.test.org/some/path'
    redirect(saml.request(relay_state=final_destination))


# This is your ACS where the user agent posts the SAML Response.
# The html form data is passed to saml.login, in the form of a dict.
@route('/SSO', method='POST')
def sso():
    attrs = saml.login(request.forms)
    # attrs is a dict containing simplified SAML attributes.
    # Attribute values are returned in a list, even for single values.
    # attrs['NameID'] is the Subject/NameID.
    # The remaining values are from the AttributeStatement, e.g.
    # if attrs.get('eduPersonPrincipalName')[0] in valid_users:
    #     authenticated = True

    # An unsuccessful authentication will log errors and return
    # and empty dict.
        
    final_destination = request.forms.get('RelayState')
    print attrs
    # continue
    




debug(True)
run(reloader=True, host='127.0.0.1', port='8888')
