from flask import Flask, render_template, request, jsonify, redirect, session, Response, send_file
import flask
import json
import redis
import os
import environment
import logging
from flask_session import Session
from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession
import base64
import db
from hashlib import sha256
import random
import string
import message
import wallet_provider



logging.basicConfig(level=logging.INFO)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'achille'
mode = environment.currentMode(myenv)


app = Flask(__name__)
app.secret_key = json.load(open("keys.json", "r"))["appSecretKey"]
app.config['UPLOAD_FOLDER'] = 'logos'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}
app.config.update(
    # your application redirect uri. Must not be used in your code
    OIDC_REDIRECT_URI=mode.server+"/redirect",
    # your application secret code for session, random
    SECRET_KEY=json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
)
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis'  # Redis server side session
app.config['SESSION_FILE_THRESHOLD'] = 100
sess = Session()
sess.init_app(app)

"""
Init OpenID Connect client PYOIDC with the 3 bridge parameters :  client_id, client_secret and issuer URL
"""

client_metadata = ClientMetadata(
    client_id='hvxitrgzbc',
    client_secret=json.load(open("keys.json", "r"))["client_secret"],
    # post_logout_redirect_uris=['http://127.0.0.1:4000/logout']
    # your post logout uri (optional)
)
provider_config = ProviderConfiguration(issuer='https://talao.co/sandbox/verifier/app',
                                        client_metadata=client_metadata)
auth = OIDCAuthentication({'default': provider_config}, app)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def generate_random_string(length):
    characters = string.ascii_uppercase  # + string.digits + string.ascii_lowercase
    return ''.join(random.choice(characters) for _ in range(length))


def get_payload_from_token(token):
    """
    For verifier
    check the signature and return None if failed
    """
    payload = token.split('.')[1]
    # solve the padding issue of the base64 python lib
    payload += "=" * ((4 - len(payload) % 4) % 4)
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def init_app(app, red):
    app.add_url_rule('/',  view_func=login,
                     methods=['GET'])
    app.add_url_rule('/login_password',  view_func=login_password,
                     methods=['POST'])
    app.add_url_rule('/dashboard',  view_func=dashboard,
                     methods=['GET'])
    app.add_url_rule('/setup',  view_func=setup,
                     methods=['GET'])
    app.add_url_rule('/set_config', view_func=set_config, methods=['POST'])
    app.add_url_rule('/add_user', view_func=add_user, methods=['POST'])
    app.add_url_rule('/logout', view_func=logout, methods=['POST'])
    app.add_url_rule('/dashboard_talao',
                     view_func=dashboard_talao, methods=['GET'])
    app.add_url_rule('/add_organisation',
                     view_func=add_organisation, methods=['POST'])
    return


@app.errorhandler(500)
def error_500(e):
    """
    For testing purpose
    Send an email if problems
    """
    if mode.server in ['https://talao.co/']:
        email = 'contact@talao.io'

        message.email('Error 500 wallet provider',
                      email, str(e))
    return redirect(mode.server + '/')


@auth.oidc_auth('default')
def login():
    user_session = UserSession(flask.session)
    logging.info(user_session.userinfo["vp_token_payload"]
                 ["verifiableCredential"]["credentialSubject"]["email"])
    session["email"] = user_session.userinfo["vp_token_payload"]["verifiableCredential"]["credentialSubject"]["email"]
    # session["email"] = "achille@talao.io"
    return (render_template("login.html"))


def login_password():
    password = request.get_json().get("password")
    verif = db.verify_password_admin(session.get("email"), password)
    if not verif:
        return "Not found", 404
    organisation = db.read_organisation(session.get("email"))
    configured = db.read_configured(organisation)
    if not organisation:
        return "Not found", 404
    elif organisation == "Talao":
        session["organisation"] = organisation
        return {"organisation": "Talao"}, 200
    else:
        session["organisation"] = organisation
        session["configured"] = configured
        return {"organisation": organisation, "configured": configured}, 200


def setup():
    if not session.get("organisation") or session.get("organisation") == "Talao":
        return "Unauthorized", 401
    organisation = session["organisation"]
    return render_template("setup.html")


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower(
           ) in app.config['ALLOWED_EXTENSIONS']


def set_config():
    wallet_provier_configuration = json.load(
        open('./wallet-provider-configuration.json', 'r'))
    wallet_provier_configuration["generalOptions"]["walletType"] = request.form.to_dict()[
        "walletType"]
    wallet_provier_configuration["generalOptions"]["companyName"] = request.form.to_dict()[
        "companyName"]
    wallet_provier_configuration["generalOptions"]["companyWebsite"] = request.form.to_dict()[
        "companyWebsite"]
    wallet_provier_configuration["generalOptions"]["profileName"] = request.form.to_dict()[
        "profileName"]
    wallet_provier_configuration["generalOptions"]["profileVersion"] = request.form.to_dict()[
        "profileVersion"]
    if request.form.to_dict().get("displayProfile"):
        wallet_provier_configuration["settingsMenu"]["displayProfile"] = True
    else:
        wallet_provier_configuration["settingsMenu"]["displayProfile"] = False
    if request.form.to_dict().get("displayDeveloperMode"):
        wallet_provier_configuration["settingsMenu"]["displayDeveloperMode"] = True
    else:
        wallet_provier_configuration["settingsMenu"]["displayDeveloperMode"] = False
    if request.form.to_dict().get("displayHelpCenter"):
        wallet_provier_configuration["settingsMenu"]["displayHelpCenter"] = True
    else:
        wallet_provier_configuration["settingsMenu"]["displayHelpCenter"] = False
    if request.form.to_dict().get("displaySecurityAdvancedSettings"):
        wallet_provier_configuration["walletSecurityOptions"]["displaySecurityAdvancedSettings"] = True
    else:
        wallet_provier_configuration["walletSecurityOptions"]["displaySecurityAdvancedSettings"] = False
    if request.form.to_dict().get("verifySecurityIssuerWebsiteIdentity"):
        wallet_provier_configuration["walletSecurityOptions"]["verifySecurityIssuerWebsiteIdentity"] = True
    else:
        wallet_provier_configuration["walletSecurityOptions"]["verifySecurityIssuerWebsiteIdentity"] = False

    if request.form.to_dict().get("confirmSecurityVerifierAccess"):
        wallet_provier_configuration["walletSecurityOptions"]["confirmSecurityVerifierAccess"] = True
    else:
        wallet_provier_configuration["walletSecurityOptions"]["confirmSecurityVerifierAccess"] = False
    if request.form.to_dict().get("secureSecurityAuthenticationWithPinCode"):
        wallet_provier_configuration["walletSecurityOptions"]["secureSecurityAuthenticationWithPinCode"] = True
    else:
        wallet_provier_configuration["walletSecurityOptions"]["secureSecurityAuthenticationWithPinCode"] = False
    if request.form.to_dict().get("tezosSupport"):
        wallet_provier_configuration["blockchainOptions"]["tezosSupport"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["tezosSupport"] = False
    if request.form.to_dict().get("ethereumSupport"):
        wallet_provier_configuration["blockchainOptions"]["ethereumSupport"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["ethereumSupport"] = False
    if request.form.to_dict().get("hederaSupport"):
        wallet_provier_configuration["blockchainOptions"]["hederaSupport"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["hederaSupport"] = False
    if request.form.to_dict().get("bnbSupport"):
        wallet_provier_configuration["blockchainOptions"]["bnbSupport"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["bnbSupport"] = False
    if request.form.to_dict().get("fantomSupport"):
        wallet_provier_configuration["blockchainOptions"]["fantomSupport"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["fantomSupport"] = False
    if request.form.to_dict().get("polygonSupport"):
        wallet_provier_configuration["blockchainOptions"]["polygonSupport"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["polygonSupport"] = False
    if request.form.to_dict().get("tzproRpcNode"):
        wallet_provier_configuration["blockchainOptions"]["tzproRpcNode"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["tzproRpcNode"] = False
    if request.form.to_dict().get("infuraRpcNode"):
        wallet_provier_configuration["blockchainOptions"]["infuraRpcNode"] = True
    else:
        wallet_provier_configuration["blockchainOptions"]["infuraRpcNode"] = False
    wallet_provier_configuration["blockchainOptions"]["tzproApiKey"] = request.form.to_dict()[
        "tzproApiKey"]
    wallet_provier_configuration["blockchainOptions"]["infuraApiKey"] = request.form.to_dict()[
        "infuraApiKey"]
    if request.form.to_dict().get("displayManageDecentralizedId"):
        wallet_provier_configuration["selfSovereignIdentityOptions"]["displayManageDecentralizedId"] = True
    else:
        wallet_provier_configuration["selfSovereignIdentityOptions"]["displayManageDecentralizedId"] = False
    if request.form.to_dict().get("displaySsiAdvancedSettings"):
        wallet_provier_configuration["selfSovereignIdentityOptions"]["displaySsiAdvancedSettings"] = True
    else:
        wallet_provier_configuration["selfSovereignIdentityOptions"]["displaySsiAdvancedSettings"] = False
    if request.form.to_dict().get("displayVerifiableDataRegistry"):
        wallet_provier_configuration["selfSovereignIdentityOptions"]["displayVerifiableDataRegistry"] = True
    else:
        wallet_provier_configuration["selfSovereignIdentityOptions"]["displayVerifiableDataRegistry"] = False
    if request.form.to_dict().get("cryptoHolderBinding"):
        wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["cryptoHolderBinding"] = True
    else:
        wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["cryptoHolderBinding"] = False
    if request.form.to_dict().get("scope"):
        wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["scope"] = True
    else:
        wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["scope"] = False
    if request.form.to_dict().get("displayChatSupport"):
        wallet_provier_configuration["helpCenterOptions"]["displayChatSupport"] = True
    else:
        wallet_provier_configuration["helpCenterOptions"]["displayChatSupport"] = False
    if request.form.to_dict().get("customChatSupport"):
        wallet_provier_configuration["helpCenterOptions"]["customChatSupport"] = True
    else:
        wallet_provier_configuration["helpCenterOptions"]["customChatSupport"] = False
    if request.form.to_dict().get("displayEmailSupport"):
        wallet_provier_configuration["helpCenterOptions"]["displayEmailSupport"] = True
    else:
        wallet_provier_configuration["helpCenterOptions"]["displayEmailSupport"] = False
    if request.form.to_dict().get("customEmailSupport"):
        wallet_provier_configuration["helpCenterOptions"]["customEmailSupport"] = True
    else:
        wallet_provier_configuration["helpCenterOptions"]["customEmailSupport"] = False
    wallet_provier_configuration["selfSovereignIdentityOptions"]["oidv4vcProfile"] = request.form.to_dict()[
        "oidv4vcProfile"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["securityLevel"] = request.form.to_dict()[
        "securityLevel"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["userPinDigits"] = request.form.to_dict()[
        "userPinDigits"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["defaultDid"] = request.form.to_dict()[
        "defaultDid"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["subjectSyntaxeType"] = request.form.to_dict()[
        "subjectSyntaxeType"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["clientAuthentication"] = request.form.to_dict()[
        "clientAuthentication"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["client_id"] = request.form.to_dict()[
        "client_id"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["client_secret"] = request.form.to_dict()[
        "client_secret"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["oidc4vciDraft"] = request.form.to_dict()[
        "oidc4vciDraft"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["oidc4vpDraft"] = request.form.to_dict()[
        "oidc4vpDraft"]
    wallet_provier_configuration["selfSovereignIdentityOptions"]["customOidc4vcProfile"]["siopv2Draft"] = request.form.to_dict()[
        "siopv2Draft"]
    wallet_provier_configuration["helpCenterOptions"]["customChatSupportName"] = request.form.to_dict()[
        "customChatSupportName"]
    wallet_provier_configuration["helpCenterOptions"]["customEmail"] = request.form.to_dict()[
        "customEmail"]
    file = request.files.get('file')
    if file and allowed_file(file.filename):
        filename = session["organisation"] + \
            "."+file.filename.rsplit('.', 1)[1].lower()
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    db.update_config(json.dumps(wallet_provier_configuration),
                     session["organisation"])
    return redirect("/dashboard")


def dashboard():
    if not session.get("organisation"):
        return "Unauthorized", 401
    if db.read_configured(session.get("organisation")) == 0:
        return redirect("/setup")
    users = db.read_users(session.get("organisation"))
    return render_template("dashboard.html", organisation=session.get("organisation"), rows=users)


def dashboard_talao():
    if session.get("organisation") != "Talao":
        return "Unauthorized", 401
    return render_template("dashboard_talao.html")


def add_user():
    email = request.get_json().get("email")
    organisation = session["organisation"]
    password = generate_random_string(6)
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    db.create_user(email, sha256_hash, organisation)
    message.messageHTML("Your altme password", email,
                        'code_auth_en', {'code': str(password)})
    return ("ok")


def add_organisation():
    organisation = request.get_json().get("organisation")
    email = request.get_json().get("emailAdmin")
    first_name = request.get_json().get("firstNameAdmin")
    last_name = request.get_json().get("lastNameAdmin")
    company_name = request.get_json().get("companyName")
    company_website = request.get_json().get("companyWebsite")
    password = generate_random_string(10)
    sha256_hash = sha256(password.encode('utf-8')).hexdigest()
    db.create_admin(email, sha256_hash, organisation)
    message.messageHTML("Your altme password", email,
                        'code_auth_en', {'code': str(password)})
    db.create_organisation(organisation)
    return ("ok")


def logout():
    session["organisation"] = None
    session["configured"] = None
    user_session = UserSession(flask.session)
    user_session.clear()
    session.clear()
    return ("ok")


init_app(app, red)
wallet_provider.init_app(app, red, mode)

if __name__ == '__main__':
    logging.info("app init")
    
    app.run(host=mode.IP, port=mode.port, debug=True)
