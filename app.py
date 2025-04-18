from flask import Flask, redirect, request, session, jsonify, url_for
from flask_cors import CORS
from requests_oauthlib import OAuth2Session
from pymongo import MongoClient
from dotenv import load_dotenv
import uuid
import time
import os
import requests

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
CORS(app, supports_credentials=True, origins=["http://127.0.0.1:8000"], methods=["GET", "POST", "PUT"])

# MongoDB
mongo_client = MongoClient(os.getenv("MONGO_URI"))
db = mongo_client.get_database("spotify-sync")
rooms_collection = db.rooms
tokens_collection = db.tokens

# Spotify
client_id = os.getenv("SPOTIFY_CLIENT_ID")
client_secret = os.getenv("SPOTIFY_CLIENT_SECRET")
redirect_uri = os.getenv("SPOTIFY_REDIRECT_URI")
authorization_base_url = 'https://accounts.spotify.com/authorize'
token_url = 'https://accounts.spotify.com/api/token'
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Scopes for OAuth2
scopes = ["user-read-playback-state", "user-read-private", "user-modify-playback-state", "streaming" ]



def refresh_token_if_expired(token):
    # Check if the token is expired
    if token.get('expires_at') and token['expires_at'] < int(time.time()):
        extra = {
            'client_id': client_id,
            'client_secret': client_secret,
        }
        oauth = OAuth2Session(client_id, token=token)
        new_token = oauth.refresh_token(token_url, refresh_token=token['refresh_token'], **extra)
        
        # Ensure user_id is part of the token when updating in DB
        if 'user_id' in token:
            tokens_collection.update_one({'user_id': token['user_id']}, {'$set': {'token': new_token}})
        else:
            # If 'user_id' is not found, you need to retrieve or store it elsewhere (e.g., session or user profile)
            print("Warning: User ID is missing, cannot update token.")
        
        return new_token
    return token

@app.route('/')
def index():
    return "Spotify Sync Backend"

@app.route('/login')
def login():
    spotify = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scopes)
    authorization_url, state = spotify.authorization_url(authorization_base_url)
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    # Retrieve the OAuth state stored during the initial authorization request
    spotify = OAuth2Session(client_id, redirect_uri=redirect_uri, state=session.get('oauth_state'))
    
    try:
        # Fetch the access token using the callback response
        token = spotify.fetch_token(token_url, client_secret=client_secret, authorization_response=request.url)
        
        # Log the token for debugging purposes
        print(f"Fetched Token: {token}")
        
        # Store the token in the session
        session['token'] = token

        # Fetch the user's Spotify info (e.g., display_name, user_id)
        user_info = spotify.get("https://api.spotify.com/v1/me").json()
        
        # Log the user info for debugging purposes
        print(f"User Info: {user_info}")
        
        # Store the user ID in the session
        session['user_id'] = user_info['id']
        
        # Store the token in the database, linked to the user_id
        tokens_collection.update_one(
            {'user_id': user_info['id']}, 
            {'$set': {'token': token}}, 
            upsert=True  # Create a new document if the user doesn't exist
        )
        
        # Redirect to the dashboard page after successful login
        return redirect('http://127.0.0.1:8000/dashboard.html')

    except Exception as e:
        # Handle any exceptions, log and return an error response
        print(f"Error during callback: {e}")
        return f"Error during callback: {e}", 500


@app.route('/me')
def me():
    token = session.get('token')
    if not token:
        return jsonify({"error": "No token found in session"}), 401
    
    # Refresh token if expired
    token = refresh_token_if_expired(token)
    if not token:
        return jsonify({"error": "Token expired or invalid"}), 401
    
    headers = {
        'Authorization': f'Bearer {token["access_token"]}'
    }

    spotify = OAuth2Session(client_id, token=token)
    response = spotify.get("https://api.spotify.com/v1/me", headers=headers)

    if response.status_code != 200:
        return jsonify({
            "error": f"Error {response.status_code}: {response.text}",
            "response": response.json()
        }), response.status_code

    return response.json()

@app.route('/create-room', methods=['POST'])
def create_room():
    token = session.get('token')
    if not token:
        return {"error": "Unauthorized"}, 401
    spotify = OAuth2Session(client_id, token=token)
    user_info = spotify.get("https://api.spotify.com/v1/me").json()
    room_id = str(uuid.uuid4())[:8]

    room_data = {
        'room_id': room_id,
        'host_id': user_info['id'],
        'host_name': user_info['display_name'],
        'members': [user_info['id']]
    }
    rooms_collection.insert_one(room_data)
    return {'room_id': room_id, 'host': user_info['display_name']}

@app.route('/room/<room_id>', methods=['GET'])
def get_room(room_id):
    room = rooms_collection.find_one({'room_id': room_id}, {'_id': 0})
    if not room:
        return {"error": "Room not found"}, 404
    return jsonify(room)

def get_token_for_user(user_id):
    user_doc = tokens_collection.find_one({'user_id': user_id})
    if not user_doc:
        return None
    token = user_doc['token']
    token = refresh_token_if_expired(token)  # Refresh token if expired
    return token['access_token'] if token else None

@app.route('/room/<room_id>/admin-now-playing', methods=['GET'])
def admin_now_playing(room_id):
    room = rooms_collection.find_one({'room_id': room_id})
    if not room:
        return {"error": "Room not found"}, 404
    
    admin_token = get_token_for_user(room['host_id'])
    if not admin_token:
        return {"error": "Admin not authenticated"}, 401

    headers = {"Authorization": f"Bearer {admin_token}"}
    r = requests.get("https://api.spotify.com/v1/me/player/currently-playing", headers=headers)
    if r.status_code != 200:
        return jsonify({"error": "Unable to fetch playback data"}), r.status_code

    # Extract track URI and playback position (progress_ms)
    track_data = r.json()
    track_uri = track_data['item']['uri']
    progress_ms = track_data['progress_ms']

    # Update room's playback data
    rooms_collection.update_one(
        {'room_id': room_id},
        {'$set': {'current_playback': {'track_uri': track_uri, 'progress_ms': progress_ms}}}
    )

    return jsonify(track_data), r.status_code

@app.route('/room/<room_id>/update-playback', methods=['POST'])
def update_playback(room_id):
    room = rooms_collection.find_one({'room_id': room_id})
    if not room:
        return {"error": "Room not found"}, 404

    # Get playback data from the request body (track URI and progress_ms)
    playback_data = request.json
    track_uri = playback_data.get('track_uri')
    progress_ms = playback_data.get('progress_ms')

    # Update the room's playback data
    rooms_collection.update_one(
        {'room_id': room_id},
        {'$set': {'current_playback': {'track_uri': track_uri, 'progress_ms': progress_ms}}}
    )

    return jsonify({"message": "Playback data updated"}), 200

@app.route('/room/<room_id>/current-playback', methods=['GET'])
def get_current_playback(room_id):
    room = rooms_collection.find_one({'room_id': room_id})
    if not room:
        return {"error": "Room not found"}, 404
    
    # Check if there's current playback data in the room
    current_playback = room.get('current_playback')
    if not current_playback:
        return {"error": "No playback data available"}, 404
    
    return jsonify(current_playback)

@app.route('/check-session', methods=['GET'])
def check_session():
    if 'token' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    return jsonify({'message': 'Session valid'}), 200


@app.route('/spotify-token')
def spotify_token():
    print(session)
    token_info = session.get('token')

    if not token_info:
        return jsonify({'error': 'Unauthorized'}), 401

    # Optionally refresh the token if expired
    if token_info['expires_at'] - int(time.time()) < 60:
        token_info = refresh_token_if_expired(token_info)
        session['token_info'] = token_info
    print(token_info['access_token'])
    return jsonify({'access_token': token_info['access_token']})


@app.route('/get_device_id')
def get_device_id():
    token = session.get('token')
    if not token:
        return jsonify({"error": "No token found in session"}), 401
    
    # Refresh token if expired
    token = refresh_token_if_expired(token)
    if not token:
        return jsonify({"error": "Token expired or invalid"}), 401
    
    headers = {
        'Authorization': f'Bearer {token["access_token"]}'
    }

    spotify = OAuth2Session(client_id, token=token)
    response = spotify.get("https://api.spotify.com/v1/me/player/devices", headers=headers)

    if response.status_code != 200:
        return jsonify({
            "error": f"Error {response.status_code}: {response.text}",
            "response": response.json()
        }), response.status_code

    return response.json()


if __name__ == '__main__':
    app.run(debug=True)
