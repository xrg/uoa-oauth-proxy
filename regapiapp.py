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

regapibp = Blueprint('regapi', __name__, template_folder='templates')

@regapibp.route('/lessons/<year>/<user>')
def get_lessons(year, user):
    lessons = RegAPI().lessons(year, user)
    return ",".join(repr(lessons))

proxyapp.register_blueprint(regapibp, url_prefix=regapi_settings.get(url_prefix, '/regapi'))
