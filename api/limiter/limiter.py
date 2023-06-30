import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv, find_dotenv



load_dotenv(find_dotenv())


limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.environ.get('REDIS_URL'),
    default_limits=["3 per minute"]
)
