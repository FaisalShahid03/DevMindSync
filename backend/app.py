import os
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Configure session
app.secret_key = os.urandom(24)

# GitHub OAuth configuration
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = 'http://localhost:5000/api/auth/github/callback'

@app.route('/api/auth/github', methods=['GET'])
def github_login():
    return jsonify({
        'url': f'https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}'
    })

@app.route('/api/auth/github/callback', methods=['GET'])
def github_callback():
    code = request.args.get('code')
    
    # Exchange code for access token
    response = requests.post(
        'https://github.com/login/oauth/access_token',
        headers={'Accept': 'application/json'},
        data={
            'client_id': GITHUB_CLIENT_ID,
            'client_secret': GITHUB_CLIENT_SECRET,
            'code': code
        }
    )
    
    access_token = response.json().get('access_token')
    
    # Get user data
    user_response = requests.get(
        'https://api.github.com/user',
        headers={
            'Authorization': f'token {access_token}',
            'Accept': 'application/json'
        }
    )
    
    user_data = user_response.json()
    session['user'] = user_data
    
    return jsonify(user_data)

@app.route('/api/auth/user', methods=['GET'])
def get_user():
    user = session.get('user')
    if user:
        return jsonify(user)
    return jsonify({'error': 'Not authenticated'}), 401

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'Logged out successfully'})

if __name__ == '__main__':
    app.run(debug=True)