# -*- coding: utf-8 -*-
##############################################################################
#
#    UoA OAuth2.0 proxy
#    Copyright (C) 2015 P. Christeas <pchristeas@noc.uoa.gr>
#
##############################################################################

import json
import base64

def _json_encode(data):
  return json.dumps(data, separators = (',', ':'))

def _urlsafe_b64encode(raw_bytes):
  return base64.urlsafe_b64encode(raw_bytes).rstrip('=')

def make_unsigned_jwt(payload):
    """Generate unsigned JWT
    
        See: http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html
    """
    header = {'typ': 'JWT', 'alg': 'none'}

    segments = [
            _urlsafe_b64encode(_json_encode(header)),
            _urlsafe_b64encode(_json_encode(payload)),
            ''
    ]
    return '.'.join(segments)

#eof
