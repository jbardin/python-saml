#!/usr/bin/python

import sys
import time
import random
import zlib
import urllib
import M2Crypto
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from dateutil import parser as dt_parser
from dateutil.tz import tzutc
from hashlib import sha1
from base64 import b64decode, b64encode


log = logging.getLogger('saml')
log.setLevel(logging.INFO)

# seconds to cache ID for replay
replay_cache_lifetime = 3600

# seconds from IssueInstant where the Response is valid
response_window = 300

# xml namespaces for xpath
ns = {'saml2p': '{urn:oasis:names:tc:SAML:2.0:protocol}',
      'saml2': '{urn:oasis:names:tc:SAML:2.0:assertion}',
      'ds': '{http://www.w3.org/2000/09/xmldsig#}',
      'xs' : '{http://www.w3.org/2001/XMLSchema}',
      'ec' : '{http://www.w3.org/2001/10/xml-exc-c14n#}',
      'xsi' : '{http://www.w3.org/2001/XMLSchema-instance}',
    }

# xpath strings
xp_subject_nameid = '{saml2}Assertion/{saml2}Subject/{saml2}NameID'.format(**ns)
xp_attributestatement= '{saml2}Assertion/{saml2}AttributeStatement'.format(**ns)

# we only support the HTTP-POST-SimpleSign binding
HTTP_POST_SimpleSign = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign'

# SAML2 AuthnRequest template
authnRequest = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
                    'AssertionConsumerServiceURL="{ACS}" '
                    'Destination="{SingleSignOnService}" ' 
                    'ID="{RequestID}" '
                    'IssueInstant="{IssueInstant}" '
                    'ProtocolBinding="{Binding}" '
                    'Version="2.0">'
                '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
                '{entityID}'
                '</saml:Issuer>'
                '<samlp:NameIDPolicy AllowCreate="1"/>'
                '</samlp:AuthnRequest>')

# Required Metadata
SP = {'entityID': None,
      'ACS': None,
      'Binding': HTTP_POST_SimpleSign,
     }

IdP = {'entityID': None,
       'SingleSignOnService': None,
       'X509': None,
      }

# cache of response IDs for replay detection
id_cache = {}

class SAML_Error(Exception):
    pass

# Python's zlib doesn't have a deflate method.
# Luckily, it's just a zlib string without the header and checksum
def b64_deflate(string_val):
    cmp_str = zlib.compress(string_val)[2:-4]
    return b64encode(cmp_str)

def expire_cache(max_age):
    expired = time.time() + max_age
    for k, v in id_cache.items():
        if v < expired:
            del(id_cache[k])

def cache_id(id_str):
    expire_cache(replay_cache_lifetime)
    id_cache[id_str] = time.time()

def gen_id():
    id_str = str(time.time()) + hex(random.getrandbits(16))
    return sha1(id_str).hexdigest()

def timestamp():
    dt = datetime.utcnow()
    dt_str = dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:22] #cut down to millis
    return (dt_str + 'Z')

def parse_simplesign(response, sig, sigalg, relaystate=None):
    cert = M2Crypto.X509.load_cert_string(IdP['X509'])
    log.debug('Loaded X509 with fingerprint: ' + cert.get_fingerprint())
    pk = cert.get_pubkey()
    pk.reset_context(md='sha1')
    pk.verify_init()
    if relaystate:
        sign_string = 'SAMLResponse=%s&RelayState=%s&SigAlg=%s' % (response, relaystate, sigalg)
    else:
        sign_string = 'SAMLResponse=%s&SigAlg=%s' % (response, sigalg)

    pk.verify_update(sign_string)

    if pk.verify_final(b64decode(sig)) == 0:
        raise SAML_Error('Invalid SAML signature')
    log.debug('Verified Response signature')

    response_xml = ET.fromstring(response)
    if response_xml.get('ID') in id_cache:
        raise SAML_Error('Replay detected')
    log.debug('No replay detected within %d seconds' % replay_cache_lifetime)

    cache_id(response_xml.get('ID'))

    issue_inst = dt_parser.parse(response_xml.get('IssueInstant'))
    now = datetime.now(tz=tzutc())
    delta = now - issue_inst
    log.debug('IssueInstant = %s; CurrentTime = %s' % (issue_inst.ctime(), now.ctime()))
    if delta.seconds > response_window:
        raise SAML_Error('Time delta too great. IssueInstant off by %d seconds'
                         % delta.seconds)

    return response_xml
    

def request(relay_state=None):
    """
    Generate a SAML2 AuthnRequest URL for HTTP-Redirect 
    """
    md = {}
    md.update(SP)
    md['SingleSignOnService'] = IdP['SingleSignOnService']
    md['RequestID'] = gen_id()
    md['IssueInstant'] = timestamp()
    req = authnRequest.format(**md)
    SAMLRequest = urllib.quote(b64_deflate(req))
    
    log.debug('Generating AuthnRequest')
    log.debug('SingleSignOnService: ' + md['SingleSignOnService'])
    log.debug('RequestID: ' + md['RequestID'])
    log.debug('IssueInstant: ' + md['IssueInstant'])
    log.debug('AuthnRequest: ' + req)

    location = IdP['SingleSignOnService'] + '?SAMLRequest=' + SAMLRequest
    if relay_state:
        log.debug('RelayState = ' + relay_state)
        location = location + '&RelayState=' + urllib.quote(relay_state)
    
    return location


def login(form):
    """
    Process the HTTP-POST-SimpleSign form data.
    """
    attrs = {}
    response = b64decode(form.get('SAMLResponse', ''))
    sig = form.get('Signature', '')
    sigalg = form.get('SigAlg', '')
    relaystate = form.get('RelayState', '')

    log.debug('Processing SAML Response')
    log.debug('SAMLResponse: ' + response)
    log.debug('Signature: ' + sig)
    log.debug('SigAlg: ' + sigalg)
    log.debug('relayState: ' + relaystate)

    try:
        response_xml = parse_simplesign(response, sig, sigalg, relaystate)
    except SAML_Error, e:
        log.error('Authentication Error: ' + str(e))
        log.debug('Returning no attributes')
        return {}

    name_id = response_xml.find(xp_subject_nameid)
    if name_id != None:
        attrs['NameID'] = name_id.text

    for el in response_xml.find(xp_attributestatement):
        name = el.get('FriendlyName') or el.get('Name') or el.tag
        attrs[name] = []
        for av in el.findall('{saml2}AttributeValue'.format(**ns)):
            if av.text:
                attrs[name].append(av.text)
            else:
                log.debug(('Parsing XML AttributeValues for %s. '
                          'Some information may not be returned') % name)
                attrs[name] = [child.text for child in av]
   
    return attrs

