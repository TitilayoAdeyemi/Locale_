from datetime import timedelta 
import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))


# 

class Config():
    SECRET_KEY = os.environ.get("SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(minutes=30)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    MONGO_URI = os.environ.get('MONGODB_URI')



class DevConfig(Config):
    DEBUG = True
    

class TestConfig(Config):
    TESTING = True

class ProdConfig(Config):
    DEBUG = False



config_dict = {
    'dev': DevConfig,
    'test': TestConfig,
    'prod': ProdConfig
}
