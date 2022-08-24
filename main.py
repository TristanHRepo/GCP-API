from google.cloud import datastore
from flask import Flask, request, make_response
import requests
import json
import constants
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, request, redirect, render_template, session, url_for, jsonify

from six.moves.urllib.request import urlopen
from six.moves.urllib.parse import urlencode
from jose import jwt

from os import environ as env
from werkzeug.exceptions import HTTPException


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

client = datastore.Client()

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=env.get("CLIENT_ID"),
    client_secret=env.get("CLIENT_SECRET"),
    api_base_url="https://" + env.get("DOMAIN"),
    access_token_url="https://" + env.get("DOMAIN") + "/oauth/token",
    authorize_url="https://" + env.get("DOMAIN") + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{env.get("DOMAIN")}/.well-known/openid-configuration'

)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                             "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + env.get("DOMAIN") + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=env.get("CLIENT_ID"),
                issuer="https://" + env.get("DOMAIN") + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Unable to parse authentication"
                                 " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                             "No RSA key in JWKS"}, 401)


@app.route("/")
def home():
    if session.get('user') is None:
        payload = []
    else:
        payload = session.get('user')["id_token"]

        name = session.get('user')['userinfo']['name']
        sub = session.get('user')['userinfo']['sub']

        query = client.query(kind=constants.users)
        results = list(query.fetch())
        print(results)

        for user in results:
            if name == user["name"] and sub == user["sub"]:
                return render_template("home.html", session=session.get('user'), pretty=payload, indent=4)

        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({"name": name, "sub": sub})
        client.put(new_user)

    return render_template("home.html", session=session.get('user'), pretty=payload, indent=4)


@app.route("/users", methods=['GET'])
def users_get():

    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        query = client.query(kind=constants.users)
        results = list(query.fetch())
        for e in results:
            e["id"] = e.key.id

        output = {"users": results}

        return json.dumps(output), 200

    else:
        error = {"Error": "Method Not Allowed"}
        res = make_response(json.dumps(error))
        res.mimetype = 'application/json'
        res.status_code = 405
        return res


@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():

    if request.method == 'POST':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        payload = verify_jwt(request)
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(constants.boats))
        try:
            new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"],
                             "loads": [], "owner": payload['sub']})
            client.put(new_boat)
            new_boat["id"] = new_boat.key.id
            new_boat["self"] = request.base_url + "/" + str(new_boat.key.id)
            return json.dumps(new_boat), 201

        except:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return json.dumps(error), 400

    elif request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        try:
            payload = verify_jwt(request)
            sap = payload['sub']
            print(sap)
            query = client.query(kind=constants.boats)
            query.add_filter("owner", "=", str(sap))
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + '/' + str(e.key.id)
            output = {"boats": results}
            if next_url:
                output["next"] = next_url

            return json.dumps(output), 200

        except:
            query = client.query(kind=constants.boats)
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + '/' + str(e.key.id)
            output = {"boats": results}
            if next_url:
                output["next"] = next_url

            return json.dumps(output), 200

    else:
        error = {"Error": "Method Not Allowed"}
        res = make_response(json.dumps(error))
        res.mimetype = 'application/json'
        res.status_code = 405
        return res


@app.route('/boats/<boat_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def boats_get_put_patch_delete(boat_id):

    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        if boat is not None:
            boat["id"] = boat.key.id
            boat["self"] = request.base_url
            return json.dumps(boat), 200
        else:
            error = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

    elif request.method == 'DELETE':
        payload = verify_jwt(request)
        sub = payload['sub']
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        if boat is None:
            error = {"Error": "No boat with this boat_id exists"}
            return json.dumps(error), 404

        if boat['owner'] == sub:
            # Check Loads
            loads = boat["loads"]
            for item in loads:
                load_key = client.key(constants.loads, int(item["id"]))
                load = client.get(key=load_key)
                load.update({"carrier": None})
                client.put(load)

            client.delete(boat_key)
            return "", 204

        else:
            error = {"Error": "Cannot delete this boat since it is owned by another user"}
            return json.dumps(error), 403

    elif request.method == 'PATCH':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        payload = verify_jwt(request)
        sub = payload['sub']
        content = request.get_json()
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        if boat is None:
            error = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

        if boat['owner'] != sub:
            error = {"Error": "Cannot update this boat since it is owned by another user"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res

        try:
            # Create json for update
            edit_keys = list(content.keys())
            update_dict = {}
            for key in edit_keys:
                update_dict[key] = content[key]

            # Update data
            boat.update(update_dict)
            client.put(boat)
            boat["id"] = boat.key.id
            boat["self"] = request.base_url

            # Create response
            res = make_response(json.dumps(boat))
            res.mimetype = 'application/json'
            res.status_code = 200
            res.location = boat["self"]
            return res

        except:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res

    elif request.method == 'PUT':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        payload = verify_jwt(request)
        sub = payload['sub']
        content = request.get_json()
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        if boat is None:
            error = {"Error": "No boat with this boat_id exists"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

        if boat['owner'] != sub:
            error = {"Error": "Cannot update this boat since it is owned by another user"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res

        try:
            # Edit boat content
            boat.update({"name": content["name"], "type": content["type"], "length": content["length"]})
            client.put(boat)
            boat["id"] = boat.key.id
            boat["self"] = request.base_url

            # Create response
            res = make_response(json.dumps(boat))
            res.mimetype = 'application/json'
            res.status_code = 200
            res.location = boat["self"]
            return res

        except:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res

    else:
        error = {"Error": "Method Not Allowed"}
        res = make_response(json.dumps(error))
        res.mimetype = 'application/json'
        res.status_code = 405
        return res


@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def boats_loads_put_delete(boat_id, load_id):

    if request.method == 'PUT':

        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)

        if boat is None or load is None:
            error = {"Error": "The specified boat and/or load does not exist"}
            return json.dumps(error), 404

        if load['carrier'] is None:
            loads = boat["loads"]
            load_self = request.url_root + "loads/" + str(load_id)
            boat_self = request.url_root + "boats/" + str(boat_id)
            loads.append({"self": load_self, "id": load_id})
            boat.update({"loads": loads})
            client.put(boat)
            load.update({"carrier": {"id": boat_id,
                                     "name": boat["name"],
                                     "self": boat_self}})
            client.put(load)
            return '', 204

        else:
            error = {"Error": "The load is already loaded on another boat"}
            return json.dumps(error), 403

    elif request.method == 'DELETE':

        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)

        # if boat or load id does not exist, return error
        if boat is None or load is None:
            error = {"Error": "boat_id or load_id does not exist"}
            return json.dumps(error), 404

        # find load if it is in the loads the boat is carrying
        loads = boat["loads"]
        load_pos = None
        for item in loads:
            if int(item["id"]) == int(load_id):
                load_pos = loads.index(item)

        # if load not on boat, return error
        if load_pos is None:
            error = {"Error": "No boat with this boat_id is loaded with the load with this load_id"}
            return json.dumps(error), 404

        # if the load carrier id is the boat id, delete from boat and return 204
        if load['carrier']['id'] == boat_id:

            # remove load with correct id
            loads.pop(load_pos)

            boat.update({"loads": loads})
            client.put(boat)
            load.update({"carrier": None})
            client.put(load)
            return '', 204

    else:
        error = {"Error": "Method Not Allowed"}
        res = make_response(json.dumps(error))
        res.mimetype = 'application/json'
        res.status_code = 405
        return res


@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():

    if request.method == 'POST':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        content = request.get_json()
        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        try:
            new_load.update({"volume": content["volume"], "carrier": None, "item": content["item"], "creation_date": content["creation_date"]})
            client.put(new_load)
            new_load["id"] = new_load.key.id
            new_load["self"] = request.base_url + "/" + str(new_load.key.id)
            return json.dumps(new_load), 201
        except:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            return json.dumps(error), 400

    elif request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        query = client.query(kind=constants.loads)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for e in results:
            e["id"] = e.key.id
            e["self"] = request.base_url + '/' + str(e.key.id)
        output = {"loads": results}
        if next_url:
            output["next"] = next_url

        return json.dumps(output), 200

    else:
        error = {"Error": "Method Not Allowed"}
        res = make_response(json.dumps(error))
        res.mimetype = 'application/json'
        res.status_code = 405
        return res


@app.route('/loads/<id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def loads_get_put_patch_delete(id):

    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load is not None:
            load["id"] = load.key.id
            load["self"] = request.base_url
            return json.dumps(load), 200
        else:
            error = {"Error": "No load with this load_id exists"}
            return json.dumps(error), 404

    elif request.method == 'DELETE':
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        if load is None:
            error = {"Error": "No load with this load_id exists"}
            return json.dumps(error), 404

        if load['carrier'] is not None:
            boat_key = client.key(constants.boats, int(load["carrier"]["id"]))
            boat = client.get(key=boat_key)
            loads = boat["loads"]
            load_pos = None
            for item in loads:
                if int(item["id"]) == int(load.key.id):
                    load_pos = loads.index(item)
            loads.pop(load_pos)
            boat.update({"loads": loads})
            client.put(boat)

        client.delete(load_key)
        return '', 204

    elif request.method == 'PATCH':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        content = request.get_json()
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        if load is None:
            error = {"Error": "No load with this load_id exists"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

        try:
            # Create json for update
            edit_keys = list(content.keys())
            update_dict = {}
            for key in edit_keys:
                update_dict[key] = content[key]

            # Update data
            load.update(update_dict)
            client.put(load)
            load["id"] = load.key.id
            load["self"] = request.base_url

            # Create response
            res = make_response(json.dumps(load))
            res.mimetype = 'application/json'
            res.status_code = 200
            res.location = load["self"]
            return res

        except:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res

    elif request.method == 'PUT':

        if 'application/json' not in request.accept_mimetypes:
            error = {"Error": "Not Acceptable MIME type"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res

        content = request.get_json()
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        if load is None:
            error = {"Error": "No load with this load_id exists"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res

        try:
            # Edit boat content
            load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"]})
            client.put(load)
            load["id"] = load.key.id
            load["self"] = request.base_url

            # Create response
            res = make_response(json.dumps(load))
            res.mimetype = 'application/json'
            res.status_code = 200
            res.location = load["self"]
            return res

        except:
            error = {"Error": "The request object is missing at least one of the required attributes"}
            res = make_response(json.dumps(error))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res

    else:
        error = {"Error": "Method Not Allowed"}
        res = make_response(json.dumps(error))
        res.mimetype = 'application/json'
        res.status_code = 405
        return res


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        content = request.get_json()
        username = content["username"]
        password = content["password"]
        body = {'grant_type': 'password', 'username': username,
                'password': password,
                'client_id': env.get("CLIENT_ID"),
                'client_secret': env.get("CLIENT_SECRET")
                }
        headers = {'content-type': 'application/json'}
        url = 'https://' + env.get("DOMAIN") + '/oauth/token'
        r = requests.post(url, json=body, headers=headers)
        return r.text, 200, {'Content-Type': 'application/json'}

    elif request.method == 'GET':
        return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))

    else:
        return 'Method not recognized'


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout", methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
