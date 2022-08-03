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
    excluded_routes = ["/login","/signin","/user/email/<string:email>"]
    excluded_methods = ["OPTIONS"]
    if request.path not in excluded_routes and request.method not in excluded_methods:
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
        return jsonify({"token": access_token, "user_id": user["id"], "name": user["nickname"], "email": user["email"]})


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
    return jsonify(response.json())


@app.route("/signin", methods=["POST"])
def create_user():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user"
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/user/<string:id>", methods=["PUT"])
def update_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user/" + id
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/user/<string:id>", methods=["DELETE"])
def delete_user(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user/" + id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())


@app.route("/user/email/<string:email>", methods=["GET"])
def get_email_user(email):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-security"] + "/user/email/" + email
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


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
    return jsonify(response.json())


@app.route("/party", methods=["POST"])
def create_party():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party"
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/party/<string:id>", methods=["PUT"])
def update_party(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party/" + id
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/party/<string:id>", methods=["DELETE"])
def delete_party(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/party/" + id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())

"""
---------------------------
    ENDPOINTS CANDIDATE
--------------------------
"""
@app.route("/candidates", methods=["GET"])
def get_candidates():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/candidates"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/candidate/<string:id>", methods=["GET"])
def get_candidate(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/candidate/" + id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/candidate/party/<string:id_party>", methods=["POST"])
def create_candidate(id_party):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/candidate" + id_party
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/candidate/<string:id>", methods=["PUT"])
def update_candidate(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/candidate/" + id
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/candidate/<string:id>", methods=["DELETE"])
def delete_candidate(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/candidate/" + id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())

"""
---------------------------
    ENDPOINTS TABLE
--------------------------
"""
@app.route("/tables", methods=["GET"])
def get_tables():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/tables"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/table/<string:id>", methods=["GET"])
def get_table(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/table/" + id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/table", methods=["POST"])
def create_table():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/table"
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/table/<string:id>", methods=["PUT"])
def update_table(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/table/" + id
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/table/<string:id>", methods=["DELETE"])
def delete_table(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/table/" + id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())

"""
---------------------------
    ENDPOINTS RESULT
--------------------------
"""
@app.route("/results", methods=["GET"])
def get_results():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/results"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/result/<string:id>", methods=["GET"])
def get_result(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/" + id
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/result/table/<string:id_table>/candidate/<string:id_candidate>", methods=["POST"])
def create_result(id_table, id_candidate):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/table/" + id_table + "/candidate/" + id_candidate
    body = request.get_json()
    response = requests.post(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/result/<string:id>/table/<string:id_table>/candidate/<string:id_candidate>", methods=["PUT"])
def update_result(id, id_table, id_candidate):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/" + id + "/table/" + id_table + "/candidate/" + id_candidate
    body = request.get_json()
    response = requests.put(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/result/<string:id>", methods=["DELETE"])
def delete_result(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/" + id
    response = requests.delete(url, headers=headers)
    return jsonify(response.json())

@app.route("/result/party/<string:id_party>", methods=["GET"])
def get_result_by_party(id_party):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/party/" + id_party
    response = requests.get(url, headers=headers)
    return jsonify(response.json())

"""
---------------------------
    ENDPOINTS REPORTS
--------------------------
"""
@app.route("/result/votesxcandidates", methods=["GET"])
def get_result_votesxcandidates():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/votesxcandidates"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/result/votesxcandidates/table/<string:id_table>", methods=["GET"])
def get_result_votesxcandidates_table(id_table):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/votesxcandidates/table/" + id_table
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


@app.route("/result/votesxtables", methods=["GET"])
def get_result_total_votesxtables():
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/votesxtables/" 
    body = request.get_json()
    response = requests.get(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/result/votesxtable/<string:id_table>", methods=["GET"])
def get_result_total_votesxtable(id_table):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/votesxtable/" + id_table 
    body = request.get_json()
    response = requests.get(url, json=body, headers=headers)
    return jsonify(response.json())


@app.route("/result/votesxparties", methods=["GET"])
def get_result_total_votesxparties(id):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/votesxparties"
    response = requests.get(url, headers=headers)
    return jsonify(response.json())

@app.route("/result/votesxparty/table/<string:id_table>", methods=["GET"])
def get_result_total_votesxparty(id_table):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-entities"] + "/result/votesxparty/table/" + id_table
    response = requests.get(url, headers=headers)
    return jsonify(response.json())


# ------------------------- Server -------------------------------
url = "http://" + dataConfig["url-apigateway"] + ":" + dataConfig["port-apigateway"];
print("Server running: " + url)
serve(app, host=dataConfig["url-apigateway"], port=dataConfig["port-apigateway"])

