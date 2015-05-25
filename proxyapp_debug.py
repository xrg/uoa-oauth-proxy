from werkzeug.debug import DebuggedApplication
from proxyapp import app
app = DebuggedApplication(app, evalex=True)
