from flask import Flask, request, jsonify, session, redirect
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import uuid, requests
from dropbox import DropboxOAuth2Flow, Dropbox, files, DropboxOAuth2FlowNoRedirect
import json
import dropbox
from flask import make_response
from oauthlib.oauth2 import WebApplicationClient
import os
import requests
from flask import url_for, session
from cryptography.fernet import Fernet
key = Fernet.generate_key()  # Store this key securely!
cipher_suite = Fernet(key)

with open('developer/dropbox.json') as f:
    data = json.load(f)
with open('developer/google.json') as f:
    gdata = json.load(f)




GOOGLE_CLIENT_ID = gdata['web']['client_id']
GOOGLE_CLIENT_SECRET = gdata['web']['client_secret']
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

client = WebApplicationClient(GOOGLE_CLIENT_ID)

APP_KEY = data['App_key']
APP_SECRET = data['App_secret']
DB_REDIRECT_URI = 'http://localhost:80/dropbox-auth-finish'







app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://0.0.0.0/postgres?user=postgres&password=mysecretpassword' #env later
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret'  #env later
db = SQLAlchemy(app)
jwt = JWTManager(app)
app.config['SESSION_TYPE'] = 'filesystem' 
Session(app)


# Initialize Dropbox OAuth2Flow
# flow = DropboxOAuth2Flow(
#     APP_KEY,
#     DB_REDIRECT_URI,
#     session=session,
#     #scope=['read_account', 'write_account', 'create_folder', 'write_content', 'write_shared_links', 'create_shared_link', 'write_shared_folder', 'create_shared_folder', 'write_public_folder', 'create_public_folder', 'write_team_folder', 'create_team_folder', 'write_shared_content', 'create_shared_content', 'write_public_content'],
#     csrf_token_session_key="custom_csrf_token_key",
#     consumer_secret=APP_SECRET
# )



flow = DropboxOAuth2FlowNoRedirect(APP_KEY,
                                        consumer_secret=APP_SECRET,
                                        token_access_type='legacy',
                                        )




class User(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=True)
    provider_token = db.Column(db.JSON, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    provider = db.Column(db.String(20), nullable=False, default='local') # 'local', 'gmail', 'dropbox'
    provider_id = db.Column(db.String(120), nullable=True) # id provided by 'gmail' or 'dropbox'


    def __init__(self, email, first_name, last_name, phone_number, password, is_active, provider, provider_id, provider_token):
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.phone_number = phone_number
        self.password_hash = generate_password_hash(password)
        self.is_active = is_active
        self.provider = provider
        self.provider_id = provider_id
        self.provider_token = provider_token
        
    
    def __repr__(self):
        return '<User {}>'.format(self.email)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def get_jwt_token(self):
        return create_access_token(identity={'id': self.id, 'email': self.email, 'first_name': self.first_name, 'last_name': self.last_name, 'phone_number': self.phone_number, 'is_active': self.is_active, 'created_at': self.created_at, 'updated_at': self.updated_at, 'provider': self.provider, 'provider_id': self.provider_id})
    
#HELPER
def login_user(data):
    new_user = User(email=data['email'], 
                    first_name=data['first_name'], 
                    last_name=data['last_name'], 
                    phone_number=data['phone_number'], 
                    password=data['password'], 
                    is_active=True, 
                    provider=data['provider'], 
                    provider_id=data['provider_id'])
    db.session.add(new_user)
    db.session.commit()
def list_files_and_folders(folder_path, access_token, file_types=None):
    if not access_token:
        return jsonify({'error': 'Dropbox authentication required'})

    dbx = Dropbox(access_token)
    try:
        files_and_folders = []
        for entry in dbx.files_list_folder(folder_path).entries:
            if isinstance(entry, files.FolderMetadata):
                files_and_folders.append({'name': entry.name, 'is_directory': True})
            elif isinstance(entry, files.FileMetadata):
                if not file_types or entry.name.endswith(tuple(file_types)):
                    files_and_folders.append({'name': entry.name, 'is_directory': False})
        return jsonify({'files_and_folders': files_and_folders})
    except Exception as e:
        return jsonify({'error': str(e)})


#-------ENDPOINTS----------#
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    new_user = User(email=data['email'], first_name=data['first_name'], last_name=data['last_name'], phone_number=data['phone_number'], password=data['password'], is_active=True, provider='local', provider_id=None)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully', 'token': new_user.get_jwt_token(), 'user_id': new_user.id}), 201

@app.route('/user', methods=['GET', 'PUT'])
@jwt_required()
def manage_user():
    user_id = get_jwt_identity()["id"]
    user = User.query.get(user_id)
    if request.method == 'GET':
        if user:
            return jsonify({'id': user.id, 'email': user.email, 'first_name': user.first_name, 'last_name': user.last_name, 'phone_number': user.phone_number, 'is_active': user.is_active, 'created_at': user.created_at, 'updated_at': user.updated_at, 'provider': user.provider, 'provider_id': user.provider_id, 'provider_token':user.provider_token}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    elif request.method == 'PUT':
        data = request.get_json()
        if 'email' in data:
            user.email = data['email']
        if 'first_name' in data:
            user.first_name = data['first_name']
        if 'last_name' in data:
            user.last_name = data['last_name']
        if 'phone_number' in data:
            user.phone_number = data['phone_number']
        db.session.commit()
        return jsonify({'message': 'User updated successfully'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and user.check_password(data['password']):
        db.session.add(user)
        db.session.commit()
        return jsonify({'token': user.get_jwt_token(), 'user_id': user.id}), 200
    else:
        return jsonify({'message': 'Invalid email or password'}), 401
    
    
#-----GOOGLE AUTH AUTHENTICATION-----
#https://127.0.0.1:80/google_start
#https://127.0.0.1:80//google_signup
@app.route("/google_signup", methods=["GET"]) #yet to be tested
def google_login_new():
    # Find out what URL to hit for Google login
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=gdata['web']["redirect_uris"][0],
        scope=["openid", "email", "profile", "https://www.googleapis.com/auth/drive"],
        access_type='offline'
    )
    return redirect(request_uri)
@app.route("/google_connect", methods=["GET"])
@jwt_required()
def google_login_old():
    user_id = get_jwt_identity()["id"]

    # Encrypt the user's ID
    encrypted_user_id = cipher_suite.encrypt(user_id.encode()).decode()
    # Find out what URL to hit for Google login
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri = gdata['web']["redirect_uris"][0] + '?user_id=' + encrypted_user_id,
        scope=["openid", "email", "profile", "https://www.googleapis.com/auth/drive"],
        access_type='offline'
    )
    return redirect(request_uri)

@app.route("/google_finish", methods=["GET"])
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    google_provider_cfg = requests.get(GOOGLE_DISCOVERY_URL).json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    client.parse_request_body_response(json.dumps(token_response.json()))

    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        
    else:
        return "User email not available or not verified by Google.", 400

    # Doesn't exist? Add it to the database.
    # Get the encrypted user's ID from the query parameters of the request URL
    existing_user = User.query.filter_by(email=users_email).first()
    encrypted_user_id = request.args.get('user_id')
    
    
    if  encrypted_user_id:
        # Get the encrypted user's ID from the query parameters of the request URL
        # Decrypt the user's ID
        user_id = cipher_suite.decrypt(encrypted_user_id.encode()).decode()
        user = User.query.get(user_id)
        if user:
            db.session.add(user)
            db.session.commit()
            provider_token = {
                "access_token": token_response.json()["access_token"],
                "id_token": token_response.json()["id_token"],
                "token_type": token_response.json()["token_type"],
                "expires_in": token_response.json()["expires_in"]
            }
            user.provider_token = json.dumps(provider_token)
            return jsonify({'token': user.get_jwt_token(), 'user_id': user.id}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
        
        
    elif existing_user: #email already in db
        user = existing_user
        db.session.add(user)
        db.session.commit()
        provider_token = {
            "access_token": token_response.json()["access_token"],
            "id_token": token_response.json()["id_token"],
            "token_type": token_response.json()["token_type"],
            "expires_in": token_response.json()["expires_in"]
        }
        user.provider_token = json.dumps(provider_token)
        return jsonify({'token': user.get_jwt_token(), 'user_id': user.id}), 200
            
        
    else: #new user
        # print("TOKEN: ", token_response.json())
        provider_token = {
            "access_token": token_response.json()["access_token"],
            "id_token": token_response.json()["id_token"],
            "token_type": token_response.json()["token_type"],
            "expires_in": token_response.json()["expires_in"]
        }
        
        user = User(email=users_email, first_name=users_name, last_name="", phone_number="", password="password", is_active=True, provider='google', provider_id=unique_id, provider_token=json.dumps(provider_token))
        db.session.add(user)
        db.session.commit()
        return jsonify({'token': user.get_jwt_token(), 'user_id': user.id}), 200
    
    
    

 
    
#-----DROPBOX AUTHENTICATION-----

#http://127.0.0.1:80/dropbox-auth-start
@app.route('/dropbox-auth-start')
@jwt_required()
# def dropbox_auth_start():
#     authorize_url = flow.start()
#     csrf_token_encrypted =cipher_suite.encrypt(flow.csrf_token_session_key.encode()).decode()
#     authorize_url = authorize_url + '?user_id=' + csrf_token_encrypted
#     response = make_response(redirect(authorize_url))
    
#     return response

def dropbox_auth_start():
    authorize_url = flow.start()
    if authorize_url:
        return jsonify({'url': authorize_url}), 200
    

@app.route('/dropbox-auth-finish', methods=['POST', 'GET'])
@jwt_required()
def dropbox_auth_finish():
    data = request.get_json()
    user_id = get_jwt_identity()["id"]
    auth_code = data['auth_code']
    try:
        result = flow.finish(auth_code)
        provider_token = {"access_token": result.access_token}
    except Exception as e:
        return jsonify({'message': 'Something went wrong'}), 401
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.provider_token = json.dumps(provider_token)
        db.session.commit()
        return jsonify({'token': user.get_jwt_token(), 'user_id': user.id}), 200
    else:
       return jsonify({'message': 'Something went wrong'}), 401


@app.route('/list-files', methods=['GET'])
@jwt_required()
def list_files():
    data = request.get_json()
    user_id = get_jwt_identity()["id"]
    user = User.query.filter_by(id=user_id).first()
    if user:
        provider_token = json.loads(user.provider_token)
        access_token = provider_token['access_token']
        return  list_files_and_folders(data['folder_path'],access_token, data.get('file_types'))
    else:
        return jsonify({'message': 'User not found'}), 404
    
    

    
# @app.route('/logout')
# @jwt_required
# def logout():
#     access_token = request.cookies.get('access_token')
#     if access_token:
#         response = requests.post('https://accounts.google.com/o/oauth2/revoke', headers={'Authorization': 'Bearer'+ access_token})
#         return jsonify({'message': 'Logged out successfully'}), 200
#     else:
#         return jsonify({'message': 'Invalid token'}), 401
    

 
if __name__ == '__main__':
    
    with app.app_context():
        #db.drop_all()  # Drop all tables
        db.create_all()  # Create all tables
    app.run(host='0.0.0.0', port=80, debug=True,
            #ssl_context=('cert.pem', 'key.pem')
            )



