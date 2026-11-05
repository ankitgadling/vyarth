import os

import app.defaults as defaults
import app.middleware  # noqa: F401  # keeps the module imported so an unused helper stays visible
from app.defaults import DSN

DSN = os.environ.get("DSN", DSN)
for _name in dir(defaults):
    if _name.isupper():
        globals()[_name] = getattr(defaults, _name)

INSTALLED_APPS = ["app"]
MIDDLEWARE = [
    "app.middleware.ProxyGuard",
    "django.middleware.common.CommonMiddleware",
]
SECRET_KEY = "x"
