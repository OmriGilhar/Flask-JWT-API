from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, make_response
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import json
import uuid
import jwt
import os

app = Flask(__name__)
base = os.path.dirname(os.path.realpath(__file__))
# This is an Demo app so no need for .env file.
app.config['SECRET_KEY'] = '128939hb1r7g'
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

# creates SQLALCHEMY object
db = SQLAlchemy(app)


class Data(db.Model):
    """
    Database ORMs
    """
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50))
    name = db.Column(db.String())
    val = db.Column(db.String())


# decorator for verifying the JWT
def token_required(func):
    """ A decorator for testing user authentication
    :param func: The wrapped function
    """
    @wraps(func)
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
        return func(data['public_id'], *args, **kwargs)

    return decorated


# User Database Route
# this route sends back list of users users
@app.route('/data', methods=['POST'])
@token_required
def create_data(public_id):
    """ POST Request for saving the data

    The route will save the relevant content, for example:
    for a body like this:
    ```
    [
        {
            "name": "device",
            "strVal": "iPhone",
            "metadata": "not interesting"
        },
        {
            "name": "isAuthorized",
            "boolVal": "false",
            "lastSeen": "not interesting"
        }
    ]
    ```

    it will save 2 Data object with the following attributes:
    D1:
        name: device
        val: iPhone
    D2:
        name: isAuthorized
        val: false

    all other json keys will be omitted.

    :param public_id: The user authentication public id
    :return: A json response including the necessary content
    """
    user_data = request.get_json()

    # database ORM objects
    data_list = []
    for entry in user_data:
        # Parsing with oneliner
        parse = [tup[1] for tup in list(filter(
            lambda item: item[0].endswith('Val') or item[0].endswith('name'),
            entry.items()))]
        data = Data(
            public_id=public_id,
            name=parse[0] if entry['name'] == parse[0] else parse[1],
            val=parse[1] if entry['name'] == parse[0] else parse[0]
        )

        data_list.append(data)
        db.session.add(data)

    db.session.commit()

    # converting the query objects to list of jsons
    output = {}
    for d in data_list:
        output[f'{d.name}'] = d.val

    return jsonify(output)


# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    """ POST Route for Login

    By sending the Username & Password you will get an JWT Token for
    later authentication.

    :return: if login was successfully return JTW token, otherwise, return
    403 with wrong password.
    """
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
        # generates the JWT Token, Also adding a infra for expiration date
        # for the token
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
    """ POST Route for Signing up

    Using a local json file to save the user details.

    :return: indication for registration (201 code).
    """
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
    db.create_all()
    app.run(debug=False)
