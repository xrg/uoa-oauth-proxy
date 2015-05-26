#!/usr/bin/python
# -*- coding: utf-8 -*

from flask import (Flask, render_template, request, redirect, make_response,
                   jsonify, Blueprint, url_for)
import jsonrpclib
from regapi_settings import regapi_settings
#from cas_settings import cas_settings

class RegAPI(object):
    def __init__(self):
        self.server = jsonrpclib.Server(regapi_settings['endpoint'])

    def lessons(self, year, username):
        return self.server.student.getLessons(year, username)


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