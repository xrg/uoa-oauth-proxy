from werkzeug.debug import DebuggedApplication
from proxy-app import app
app = DebuggedApplication(app, evalex=True)
