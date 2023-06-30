import json
from flask import jsonify, Blueprint
from http import HTTPStatus
import os
from flask import Flask
from flask.views import MethodView
from flask_jwt_extended import jwt_required, JWTManager, get_jwt_identity, get_jwt_header
from http import HTTPStatus 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv, find_dotenv
from flask_caching import Cache
from ..caching.cache import cache
from ..limiter.limiter import limiter

load_dotenv(find_dotenv())


current_directory = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_directory, 'dataset.json')

app =  Flask(__name__)

geo_routes = Blueprint('auth_routes', __name__)


with open(r'C:\Users\USER\Desktop\LOCALE1\api\models\dataset.json', 'r') as json_file:
    data = json.load(json_file)

    
class Regions(MethodView):
    @jwt_required(locations=["headers"])
    @cache.cached(timeout=300)
    @limiter.limit('3/minute')
    # Retrieve every region
    def get(self):
        try :
            regions = data.get('Regions')
            response = {"All regions in Nigeria": regions}
            return jsonify(response), 200
            
        except:
            raise HTTPStatus.UNAUTHORIZED
        
        
    
regions_view = Regions.as_view("regions")
geo_routes.add_url_rule("/api/geo/regions",view_func=regions_view,methods=["GET"])



class States(MethodView):
    @jwt_required()
    @cache.cached(timeout=300)
    @limiter.limit('3/minute')
    # Retrieve all states
    def get(self):
        try :
            states = data.get('States')
            response = {"All states in Nigeria": states}
            return jsonify(response), 200
        
            
        except:
            raise HTTPStatus.UNAUTHORIZED
    
states_view = States.as_view("states")
geo_routes.add_url_rule("/api/geo/states",view_func=cache.cached(timeout=300)(states_view),methods=["GET"])



class LGAs(MethodView):
    @jwt_required()
    @cache.cached(timeout=300)
    @limiter.limit('3/minute')
    # Retrieve all LGAs
    def get(self):
        try :
            lgas = data.get('LGAs')
            response = {"All LGAs in Nigeria": lgas}
            return jsonify(response), 200
            
        except:
            raise HTTPStatus.UNAUTHORIZED
        
        
    
lgas_view = LGAs.as_view("lgas")
geo_routes.add_url_rule("/api/geo/lgas",view_func=lgas_view,methods=["GET"])



class StatesInRegion(MethodView):
    @jwt_required()
    @cache.cached(timeout=300)
    @limiter.limit('3/minute')

    def get(self, region_id):
        states = data.get('States')
        # Filter states based on region_id and return every state in a region
        
        region_states = [state for state in states if int(state['region_id']) == region_id]
        
        if region_id > 6:
            return {'message' : f'Region {region_id} does not exist'}
        
        return {f'states in region {region_id}': region_states}

geo_routes.add_url_rule('/api/geo/states/<int:region_id>', view_func=StatesInRegion.as_view('states_in_region'), methods = ['GET'])



class LgasInState(MethodView):
    @jwt_required()
    @cache.cached(timeout=300)
    def get(self, state_id):
        lgas = data.get('lgas')
        
        # Filter LGAs based on state_id and return every LGA in a state
        state_lgas = [lga for lga in lgas if int(lga['state_id']) == state_id]
        
        if state_id > 36:
            return {'message' : f"State {state_id} does not exist"}
        
        return {f'LGAs in state {state_id}': state_lgas}

geo_routes.add_url_rule('/api/geo/lgas/<int:state_id>', view_func=LgasInState.as_view('lgas_in_state'), methods = ['GET'])
