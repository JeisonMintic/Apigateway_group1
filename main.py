# Flask
from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
from waitress import serve
# Utils
import json
import requests
import datetime
import re
# Token JWT
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

# ------------------------- Setting Flask App -------------------------------
app = Flask(__name__)
cors = CORS(app)

def loadFileConfig():
    with open("config.json") as f:
        data = json.load(f)
    return data
dataConfig = loadFileConfig()


# ------------------------- Middleware -------------------------------

def format_url():
    parts = request.path.split("/")
    url = request.path
    for part in parts:
        if re.search('\\d', part):
            url = url.replace(part, "?")
    return url

@app.before_request
def before_request_callback():
    excluded_routes = ["/login","/signup"]
    if request.path not in excluded_routes:
        # Token
        if not verify_jwt_in_request():
            return jsonify({"msg": "Permission Denied"}), 401
        # Roles and Permissions
        user = get_jwt_identity()
        print(user)
        if user["rol"] is None:
            return jsonify({"msg": "Permission Denied"}), 401
        else:
            role_id = user["rol"]["id"]
            route = format_url()
            method = request.method
            has_permission = validate_permission(role_id, route, method)
            if not has_permission:
                return jsonify({"msg": "Permission Denied"}), 401


def validate_permission(role_id, route, method):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/permission-role/validate/role/" + role_id
    body = {"url": route, "method": method}
    print(body)
    response = requests.post(url, json=body, headers=headers)
    print(response)
    try:
        data = response.json()
        if "id" in data:
            return True
    except:
        return False


# ------------------------- Setting JWT Token -------------------------------
app.config["JWT_SECRET_KEY"] = dataConfig["jwt-key"]
jwt = JWTManager(app)


# ------------------------- Endpoints -------------------------------
@app.route("/home", methods=["GET"])
def test():
    return jsonify({"msg": "This is a home page"})


    
@app.route("/login", methods=["POST"])
def login():
    # FE -> AGW
    data = request.get_json()
    # AGW -> MS
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/validate"
    response = requests.post(url, json=data, headers=headers)
    if response.status_code == 401:
        return jsonify({"msg": "Usuario o contraseña incorrectos"}), 401
    elif response.status_code == 500:
        return jsonify({"msg": "Error inesperado"}), 500
    elif response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60*60*24)
        access_token = create_access_token(identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["id"]})


"""
---------------------------
    ENDPOINTS USER
--------------------------
"""
@app.route("/users", methods=["GET"])
def get_users():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/users"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/user/<string:id>", methods=["GET"])
def get_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user/" + id
    response = requests.get(url, headers=headers)
    return response.json()


@app.route("/signup", methods=["POST"])
def create_user():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user"
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return response.json()


@app.route("/user/<string:id>", methods=["PUT"])
def update_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user/" + id
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return response.json()


@app.route("/user/<string:id>", methods=["DELETE"])
def delete_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user/" + id
    response = requests.delete(url, headers=headers)
    return response.json()


"""
---------------------------
    ENDPOINTS PARTY
--------------------------
"""

@app.route("/parties", methods=["GET"])
def get_parties():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/parties"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/party/<string:id>", methods=["GET"])
def get_party(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party/" + id
    response = requests.get(url, headers=headers)
    return response.json()


@app.route("/party", methods=["POST"])
def create_party():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party"
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return response.json()


@app.route("/party/<string:id>", methods=["PUT"])
def update_party(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party/" + id
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return response.json()


@app.route("/party/<string:id>", methods=["DELETE"])
def delete_party(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party/" + id
    response = requests.delete(url, headers=headers)
    return response.json()

"""
---------------------------
    ENDPOINTS CANDIDATE
--------------------------
"""


"""
---------------------------
    ENDPOINTS TABLE
--------------------------
"""


"""
---------------------------
    ENDPOINTS RESULT
--------------------------
"""


"""
---------------------------
    ENDPOINTS REPORTS
--------------------------
"""

# ------------------------- Server -------------------------------

url = "http://" + dataConfig["url-apigateway"] + ":" + dataConfig["port-apigateway"];
print("Server running: " + url)
serve(app, host=dataConfig["url-apigateway"], port=dataConfig["port-apigateway"])

