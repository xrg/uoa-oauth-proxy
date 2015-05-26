#!/usr/bin/python
# -*- coding: utf-8 -*

from flask import (Flask, render_template, request, redirect, make_response,
                   jsonify, Blueprint, url_for, abort)
import jsonrpclib
from regapi_settings import regapi_settings
#from cas_settings import cas_settings
import httplib2
from functools import wraps
import time
from urllib import urlencode
import json


class RegAPI(object):
    def __init__(self):
        self.server = jsonrpclib.Server(regapi_settings['endpoint'])

    def lessons(self, year, username):
        return self.server.student.getLessons(year, username)


class TokenCache(object):
    """Cache of validated tokens
    """
    def __init__(self, settings):
        self._oauth_uri = settings['oauth_uri']
        self._client_id = settings['client_id']
        self._client_secret = settings['client_secret']
        self._cache = {} # TODO: use LRU
        self._http = httplib2.Http(timeout=5.0, disable_ssl_certificate_validation=True)

    def check(self, token_id):
        """Validate token, return its full data
        """
        token =  self._cache.get(token_id, False)
        if token:
            if token['expires'] > time.time():
                del self._cache[token_id]
                return False
            else:
                return token
        else:
            # not in cache, fetch from remote
            body = urlencode({
                'client_id': self._client_id,
                'client_secret': self._client_secret,
                'access_token': token_id,
                })

            headers = {
                'content-type': 'application/x-www-form-urlencoded',
            }
            resp, content = self._http.request(self._oauth_uri, method='POST',
                                               body=body, headers=headers)
            if resp.status != 200:
                log.error("Cannot validate token at %s : got %s", self._oauth_uri, resp.status)
                log.debug("Content: %r", content)
                return False
            if resp['content-type'] != 'application/json':
                log.error("Bad content from %s: %s", self._oauth_uri,resp['content-type'])
                return False
            t = json.loads(content)
            if isinstance(t, dict) and t.get('access_token', False) == token_id:
                if 'expires_in' in t:
                    t['expires'] = time.time() + t['expires_in']
                
                # TODO: any other cleanup? Remove unspecified fields, perhaps?
                self._cache[token_id] = t
                return t

        return False


def check_same_user(tokens_inst):
    """view wrapper , checking http bearer authentication
    
        @param tokens_inst an instance of TokenCache()
    """
    def decorator(fn):
        @wraps(fn)
        def _decorated_function(user, *args, **kwargs):
            auth = request.headers.get('Authorization', False)
            if not (auth and auth.startswith('Bearer ')):
                log.info("Bad request, no Authorization: header")
                abort(403)
            token_id = auth[7:]
            log.debug("Trying token %s", token_id)
            t = tokens_inst.check(token_id)
            if not t:
                log.info("Bad token")
                abort(403)
            if t['args']['user'] != user:
                log.info("Users mismatch: %s != %s", t['args']['user'], user)
                abort(403)
            return fn(user, *args, **kwargs)
        return _decorated_function
    return decorator

app = Flask(__name__)
app.debug = True
app.config['APPLICATION_ROOT'] = regapi_settings.get('url_prefix', '/regapi')
# app.config['SERVER_NAME'] = cas_settings['server_name']
log = app.logger

regapibp = Blueprint('regapi', __name__, template_folder='templates')

@regapibp.route('/')
def index():
    return "Hai there"

@regapibp.route('/lessons/<year>/<user>')
def get_lessons(year, user):
    log.debug("retrieving lessons for %s", user)
    return render_template('lesson_list.html', lessons=RegAPI().lessons(year, user), user=user, year=year)
app.register_blueprint(regapibp, url_prefix=app.config['APPLICATION_ROOT'])

from werkzeug.debug import DebuggedApplication
debug_app = DebuggedApplication(app, evalex=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0')

#eof