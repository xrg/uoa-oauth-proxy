#!/usr/bin/python
# -*- coding: utf-8 -*-
##############################################################################
#
#    UoA OAuth2.0 proxy
#    Copyright (C) 2015 P. Christeas <pchristeas@noc.uoa.gr>
#
##############################################################################


from flask import (Flask, render_template, request, redirect, make_response,
                   jsonify, Blueprint, url_for)
import json
import os
import base64
import logging
from urllib import urlencode
import httplib2
from xml.dom import minidom
import time
from collections import defaultdict
import jsonrpclib


from cas_settings import cas_settings

log = None
TOKEN_DURATION = int(3 * 3600) # say...

class RegAPI(object):
    def __init__(self):
        from regapi_settings import regapi_settings
        self.server = jsonrpclib.Server(regapi_settings['endpoint'])

    def lessons(self, year, username):
        return self.server.student.getLessons(year, username)


def _make_random(rlen=24):
    """URL-friendly random numbers. Will have 8*3/4 entropy bits

        (base64 produces 4 chars for every 3 bytes of data)
    """
    return base64.urlsafe_b64encode(os.urandom(rlen*3/4))

# Compact, self-contained data storage
class Clients(object):
    """Registered clients to this OAuth server

        Each client is a dict of: name, client_id, client_secret, [enabled], redirect_uri
    """
    def __init__(self):
        self._clients = {} # indexed by client-id
        self._dbpath = cas_settings.get('dbpath', 'data/clients.json')


    def _save(self):
        """Save `self._clients` to JSON

            We use indent for readability. We store as a list, not a dict.
        """
        fp = open(self._dbpath, 'wb')
        json.dump(self._clients.values(), fp, indent=2)
        fp.close()
        log.info("Clients saved to \"clients.json\" ")

    def _load(self):
        """Load them from a JSON file
        """
        try:
            fp = open(self._dbpath, "rb")
            clients = json.load(fp)
            fp.close()
            self._clients.clear()
            for c in clients:
                self._clients[c['client_id']] = c
        except IOError, e:
            if e.errno == 2:
                return
            log.error("IO error: %r", e)
            raise

    def __contains__(self, client_id):
        """ Handy method to check if some client_id is valid
        """
        if not self._clients:
            self._load()
        return client_id in self._clients

    def check_client(self, client_id, client_secret):
        """Check id+secret combination of a client

            @params redirect_uri If given, also check that it matches the client's
                    registered `redirect_uri`
            @return The client's name, a truthy value when successful
        """
        if not (client_id and client_secret):
            # avoid checking against empty values
            return False

        if not self._clients:
            self._load()
        c = self._clients.get(client_id, None)
        log.debug("client %s", client_id)
        if c and (c.get('client_secret', False) == client_secret) and c.get('enabled', False):

            return c['name'] or True # always a truthy value

        log.debug("Cannot verify client %s", client_id)
        return False

    def check_endpoint(self, client_id, redirect_uri):
        """Check that we can server request for client_id, redirecting to `redirect_uri`

            Variant of `check_client`
        """
        if not (client_id and redirect_uri):
            # avoid checking against empty values
            return False

        if not self._clients:
            self._load()
        c = self._clients.get(client_id, None)
        if c and c.get('enabled', False) and (c.get('redirect_uri', False) == redirect_uri):
            return c['name'] or True # always a truthy value

        log.debug("Cannot verify client %s to %s", client_id, redirect_uri)
        return False

    def new_client(self, name, redirect_uri):
        """Generates random ID+secret, saves /disabled/ client
        """
        assert redirect_uri, 'Must have a value'
        self._load()
        while True:
            nc = { 'name': name, 'redirect_uri': redirect_uri,
                  'client_id': _make_random(24),
                  'client_secret': _make_random(60),
                  'enabled': False, # not wise to enable by default
                }
            if nc['client_id'] in self._clients:
                continue
            self._clients[nc['client_id']] = nc
            self._save()
            return nc
        # end while


#    Tokens part

class Tokens(object):
    def __init__(self):
        self._tokens_by_client = defaultdict(list)
        self._pending_tokens = {} # by code, can only be used once, not active yet

    def get_grant(self, client_id):
        """Construct a new, pending, token

            @return the 'code' to access this grant

            This fn. *assumes* that `client_id` has already been checked
        """
        t = { 'client_id': client_id, 'token': _make_random(40),
             'expires': time.time() + 600,
             }
        c = _make_random(48)
        assert c not in self._pending_tokens, "Collision!"
        self._pending_tokens[c] = t
        return c


    def set(self, token):
        """ Register a token in set of active ones
            
            Token is one like in `get_grant()`
        """
        assert isinstance(token, dict), type(token)
        assert 'client_id' in token
        self._tokens_by_client[token['client_id']].append(token)

# Flask part
proxybp = Blueprint('oauth', __name__, template_folder='templates')

app = Flask(__name__)
app.debug = True
app.config['APPLICATION_ROOT'] = 'oauth/'
app.config['SERVER_NAME'] = cas_settings['server_name']
log = app.logger
the_clients = Clients()
the_tokens = Tokens()

@proxybp.route('/regapitest')
def regapitest():
    return RegAPI().lessons(2014, 'foo')

@proxybp.route('/')
def go_away():
    return 'Go away!'

@proxybp.route('/admin/new-client', methods=['GET', 'POST'])
def get_new_client():
    """ Simple POST form for a new client
    """
    error = None
    if request.method == 'POST':
        try:
            nc = the_clients.new_client(name=request.form['name'], redirect_uri=request.form['redirect_uri'])
        except Exception, e:
            nc = None
            error = str(e)
    else:
        nc = False
    return render_template('new_client.html', nc=nc, error=error)

@proxybp.route('/authorize', methods=['GET'])
def get_authorize():
    """Parse a OAuth2.0 authorize request, ask CAS for authorization

        Will use the following args:
            client_id
            state
            redirect_uri
            response_type
            [ scope ? ]
    """
    client_name = the_clients.check_endpoint(request.args['client_id'], request.args['redirect_uri'])
    if not client_name:
        return render_template('broken_endpoint.html')

    def _redir_response(**kwargs):
        uri = request.args['redirect_uri']
        if '?' in uri:
            uri += '&'
        else:
            uri += '?'
        if request.args.get('state', False):
            kwargs = kwargs.copy()
            kwargs['state'] = request.args['state']
        r = redirect(uri + urlencode(kwargs))
        r.headers['Pragma'] = 'no-cache'
        r.headers['Cache-Control'] = "no-cache"
        return r

    log.debug("Checking request for %s", client_name)

    if request.args.get('response_type',False) != 'code':
        return _redir_response(error='invalid_request')

    service_uri = url_for('.get_auth_done', client_id=request.args['client_id'], _external=True)
    if request.args.get('state', False):
        service_uri += '/' + request.args['state']
    login_uri = cas_settings['uri'] + '/login?' + urlencode({ 'service': service_uri, })
    log.debug("Redirecting to %s for login", login_uri) # remove this at production!
    r = redirect(login_uri)
    r.headers['Pragma'] = 'no-cache'
    r.headers['Cache-Control'] = "no-cache"
    return r

    # alt, with CAS+OAuth2 (TODO)
    # Note that we need to set the cookie and redirect the client
    # to CAS, asap. Not all browsers work with 302+cookie:
    # http://blog.dubbelboer.com/2012/11/25/302-cookie.html



@proxybp.route('/auth_done/<client_id>')
@proxybp.route('/auth_done/<client_id>/<state>')
def get_auth_done(client_id, state=None):
    """ This is where CAS should send our client after its login is verified

        We get the ticket from CAS here, give back our token to calling app
    """

    if client_id not in the_clients:
        return make_response(render_template('broken_endpoint.html'),403)

    def _redir_response(**kwargs):
        uri = the_clients._clients[client_id]['redirect_uri']
        if '?' in uri:
            uri += '&'
        else:
            uri += '?'
        if state:
            kwargs = kwargs.copy()
            kwargs['state'] = state
        r = redirect(uri + urlencode(kwargs))
        r.headers['Pragma'] = 'no-cache'
        r.headers['Cache-Control'] = "no-cache"
        return r

    if not request.args.get('ticket', False):
        return _redir_response(error='access_denied')

    try:
        service_uri = url_for('.get_auth_done', client_id=client_id, _external=True)
        if state:
            service_uri += '/' + state

        url = cas_settings['uri'] + '/serviceValidate?' +\
                urlencode({
                    'service': service_uri,
                    'ticket': request.args['ticket'],
                    })

        http = httplib2.Http(disable_ssl_certificate_validation=True)
        # Keep this commented, it would leak the secret key in production!
        # log.debug("Exchange code for credentials through: %s", url)
        resp, content = http.request(url, method='GET')

        if resp.status == 200 and content:
            response = minidom.parseString(content)
            failureNode = response.getElementsByTagName('cas:authenticationFailure')
            if failureNode:
                error_msg = failureNode[0].firstChild.nodeValue
                log.info("Authentication failed from CAS server: %s", error_msg)
                return _redir_response(error='access_denied', error_description=error_msg)

            successNode = response.getElementsByTagName('cas:authenticationSuccess')
            if successNode:
                log.debug('Successfully retrieved access token from %s/serviceValidate', cas_settings['uri'])
                # code response, p 4.1.2 of RFC6749
                return _redir_response(code=the_tokens.get_grant(client_id))
            else:
                return _redir_response(error='temporarily_unavailable')

        else:
            return _redir_response(error='server_error')
    except Exception:
        log.exception("Cannot get credentials:")
        return _redir_response(error='server_error')

@proxybp.route('/token', methods=['POST'])
def get_token():
    """token endpoint, exchanges code for *our* token
    
        This request /must/ be initiated by client, bearing client_id+client_secret

        See RFC6749 s 4.1.3
    """
    def _error_52(error, **kwargs):
        """Error response, like in RFC s5.2
        """
        r = jsonify(error=error, **kwargs)
        r.headers['Cache-Control'] = 'no-store'
        r.headers['Pragma'] = 'no-cache'
        r.status_code = 400
        return r

    client_name = the_clients.check_client(request.form['client_id'], request.form.get('client_secret', False))
    if not client_name:
        return _error_52('invalid_client')
    log.debug("Get request for %s", client_name)
    if request.form['redirect_uri'] != the_clients._clients[request.form['client_id']]['redirect_uri']:
        log.warning("redirect_uri mismatch for %s: %s", client_name, request.form['redirect_uri'])
        return _error_52('invalid_grant')
    
    if request.form.get('grant_type', False) != 'authorization_code' \
                or not request.form.get('code', False):
        return _error_52('invalid_request')
    
    t = the_tokens._pending_tokens.pop(request.form['code'], False)
    if not t:
        # no such code
        return _error_52('invalid_grant')
    elif t['expires'] <= time.time():
        #  expired code
        return _error_52('invalid_grant')
    elif t['client_id'] != request.form['client_id']:
        #oops, wrong client!
        return _error_52('invalid_grant')
    else:
        # ok, grant
        t['expires'] = time.time() + TOKEN_DURATION
        the_tokens.set(t)
        r = jsonify(access_token=t['token'], token_type='bearer',
                    expires_in=TOKEN_DURATION, ) # scope='play-around')
        r.headers['Cache-Control'] = 'no-store'
        r.headers['Pragma'] = 'no-cache'
        return r

app.register_blueprint(proxybp, url_prefix=cas_settings.get('url_prefix', '/oauth'))


if __name__ == '__main__':
    app.run(host='0.0.0.0')

#eof
