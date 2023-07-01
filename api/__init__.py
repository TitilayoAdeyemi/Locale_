from flask import Flask
from mongoengine import Document
from flask_restx import Api
from .config.config import config_dict
from flask_jwt_extended import JWTManager
from werkzeug.exceptions import NotFound, MethodNotAllowed
from .geo_info.views import cache
from http import HTTPStatus
from .auth.view import auth_routes
from .geo_info.views import geo_routes

# app = Flask(__name__)


def create_app(config=config_dict['dev']):

    app = Flask(__name__)
    app.config.from_object(config)
    app.config['JWT_SECRET_KEY']=config.JWT_SECRET_KEY
    
    jwt = JWTManager(app)

    cache.init_app(app)

    authorizations= {
    'Bearer Auth' : {
    'type' : 'apiKey',
    'in' : 'header',
    'name' : 'Authorization',
    'description' : 'Add a JWT with ** Bearer &lt;JWT&gt; to authorize'
    }
            }

    api = Api(app,
               title='Locale',
                authorizations=authorizations,
                description= "An API for retrieving Nigeria's geographical information",
                security= 'Bearer Auth'
                )
    
    api.register_blueprint(auth_routes, name='auth')
    api.register_blueprint(geo_routes, name='geo')

    @api.errorhandler(MethodNotAllowed)
    def method_not_alowed():
        return {'error' : 'Method not allowed'}, 405

    @api.errorhandler(NotFound)
    def not_found(error):
        return {'error' : 'Not Found'}, 404
    
    @app.errorhandler(429)
    def handle_rate_limit_exception(e):
      return {'message': 'Rate limit exceeded. Too many requests'}, HTTPStatus.TOO_MANY_REQUESTS
  
    return app