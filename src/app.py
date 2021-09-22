# flask imports
import json
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import os

# creates Flask object
app = Flask(__name__)
base = os.path.dirname(os.path.realpath(__file__))
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = '128939hb1r7g'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# creates SQLALCHEMY object
db = SQLAlchemy(app)


# Database ORMs
class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50))
    name = db.Column(db.String())
    val = db.Column(db.String())


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'JWT Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            with open(os.path.join(base, 'UserCred.json'), 'r') as load:
                cred = json.load(load)
            if cred['public_id'] != data['public_id']:
                raise RuntimeError()
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        # returns the current logged in users context to the routes
        return f(data['public_id'], *args, **kwargs)

    return decorated


# User Database Route
# this route sends back list of users users
@app.route('/data', methods=['POST'])
@token_required
def create_data(public_id):
    user_data = request.get_json()
    # database ORM objects
    data_list = []
    for entry in user_data:
        parse = [tup[1] for tup in list(filter(
            lambda item: item[0].endswith('Val') or item[0].endswith('name'),
            entry.items()))]
        print(f"parse[0] name = {parse[0]}")
        print(f"parse[1] val = {parse[1]}")
        print(f"public_id = {public_id}")
        data = Data(
            public_id=public_id,
            name=parse[0],
            val=parse[1]
        )

        data_list.append(data)
        print(data)
        db.session.add(data)

    db.session.commit()

    # converting the query objects
    # to list of jsons
    output = {}
    for d in data_list:
        output[f'{d.name}'] = d.val

    return jsonify(output)


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form

    if not auth or not auth.get('user') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm ="Login required !!"'}
        )

    # Get the user credentials
    with open(os.path.join(base, 'UserCred.json'), 'r') as load:
        cred = json.load(load)
    if check_password_hash(cred.get('password'), auth.get('password')):
        # generates the JWT Token
        token = jwt.encode({
            'public_id': cred.get('public_id'),
            'exp': datetime.utcnow() + timedelta(minutes=30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token': token.decode('UTF-8')}), 201)
    # returns 403 if password is wrong
    return make_response(
        'Could not verify',
        403,
        {'WWW-Authenticate': 'Basic realm ="Wrong Password !!"'}
    )


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    name, password = data.get('name'), data.get('password')

    # database ORM object
    user_cred = {
        "public_id": str(uuid.uuid4()),
        "name": name,
        "password": generate_password_hash(password)
    }
    with open(os.path.join(base, 'UserCred.json'), 'w') as upload:
        # save user cred
        json.dump(user_cred, upload)
        return make_response('Successfully registered.', 201)


if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debuger shell
    # if you hit an error while running the server
    db.create_all()
    app.run(debug=True)
