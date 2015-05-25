from flask import (Flask, render_template, request, redirect, make_response,
                   jsonify, Blueprint, url_for)
import jsonrpclib
from proxyapp import app as proxyapp
from regapi_settings import regapi_settings

class RegAPI(object):
    def __init__(self):
        self.server = jsonrpclib.Server(regapi_settings['endpoint'])

    def lessons(self, year, username):
        return self.server.student.getLessons(year, username)


app = Flask(__name__)
app.debug = True
app.config['APPLICATION_ROOT'] = cas_settings['url_prefix']
app.config['SERVER_NAME'] = cas_settings['server_name']
log = app.logger

regapibp = Blueprint('regapi', __name__, template_folder='templates')

@regapibp.route('/lessons/<year>/<user>')
def get_lessons(year, user):
    lessons = RegAPI().lessons(year, user)
    return ",".join(repr(lessons))
app.register_blueprint(regapibp, url_prefix=regapi_settings.get(url_prefix, '/regapi'))

from werkzeug.debug import DebuggedApplication
debug_app = DebuggedApplication(app, evalex=True)
