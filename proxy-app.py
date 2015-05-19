#!/usr/bin/python
# -*- coding: utf-8 -*-
##############################################################################
#
#    UoA OAuth2.0 proxy
#    Copyright (C) 2015 P. Christeas <pchristeas@noc.uoa.gr>
#
##############################################################################


from flask import Flask, render_template, request
import json
import os
import base64
import logging

log = None

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


    def _save(self):
        """Save `self._clients` to JSON

            We use indent for readability. We store as a list, not a dict.
        """
        fp = open("clients.json", 'wb')
        json.dump(self._clients.values(), fp, indent=2)
        fp.close()
        log.info("Clients saved to \"clients.json\" ")

    def _load(self):
        """Load them from a JSON file
        """
        try:
            fp = open("clients.json", "rb")
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

    def check_client(self, client_id, client_secret):
        """Check id+secret combination of a client

            @return The client's name, a truthy value when successful
        """
        if not (client_id and client_secret):
            # avoid checking against empty values
            return False

        if not self._clients:
            self._load()
        c = self._clients.get(client_id, None)
        if c and (c.get('client_secret', False) == client_secret) and c.get('enabled', False):
            return c['name'] or True # always a truthy value

        log.debug("Cannot verify client %s", client_id)
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
        self._tokens_by_client = {}

    # TODO


# Flask part
app = Flask(__name__)
app.debug = True
log = app.logger
the_clients = Clients()
the_tokens = Tokens()

@app.route('/')
def go_away():
    return 'Go away!'

@app.route('/admin/new-client', methods=['GET', 'POST'])
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

if __name__ == '__main__':
    app.run(host='0.0.0.0')

#eof
