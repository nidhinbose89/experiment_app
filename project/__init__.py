import os

from flask import Flask
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from flask_restful import Api


# config
app = Flask(__name__)

app.config.from_object(os.environ['APP_SETTINGS'])

# extensions
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

api = Api(app)

from views import (UserViews, ResourceViews, ListResourceViews,
                  AdminViews, LoginViews, LogoutViews)  # noqa

api.add_resource(UserViews,
                 '/user',
                 '/user/<int:user_id>'
                 )
api.add_resource(ResourceViews,
                 '/user/<int:user_id>/resource',
                 '/user/<int:user_id>/resource/<int:resource_id>',
                 )
api.add_resource(ListResourceViews,
                 '/user/<int:user_id>/resources'
                 )
api.add_resource(AdminViews,
                 '/user/<int:user_id>/sub-users'
                 )
api.add_resource(LoginViews,
                 '/login'
                 )
api.add_resource(LogoutViews,
                 '/logout'
                 )
