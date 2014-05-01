try:
    from urlparse import urlparse, urlunparse
except ImportError:
    from urllib.parse import urlparse, urlunparse

import uuid
from werkzeug.utils import redirect
from flask import Flask
from flask.json import jsonify
from flask.templating import render_template
from flask.helpers import url_for
from flask.globals import session, request

from pybitid import bitid
from models.user import User
from models.nonce import Nonce
from services.fake_user_db_service import FakeUserDbService
from services.fake_nonce_db_service import FakeNonceDbService


# Constant indicating if we run the app against Bitcoin test network or main network
USE_TESTNET = False

# Initializes the flask app
app = Flask(__name__)

# Initializes a secret key used to encrypt data in cookies
app.secret_key = '\xfd{H\xe5<\x95\xf9\xe3\x96.5\xd1\x01O<!\xd5\xa2\xa0\x9fR"\xa1\xa8'

# Initializes services to access databases or services
# For this toy project we use fake dbs storing data in memory
nonce_db_service = FakeNonceDbService()
user_db_service = FakeUserDbService()


@app.route("/", methods=["GET"])
@app.route("/home", methods=["GET"])
def home():
    '''
    Prepares rendering of home page
    '''
    params_tpl = {}
    # Checks if user is already logged
    if session.get("auth", False):
        # Gets the user from db
        user = user_db_service.get_user_by_uid(session["uid"])
        if not user is None: params_tpl["user_login"] = user.login
    else:
        # Initializes a new session id and stores it in the session cookie
        session["sid"]  = str(uuid.uuid4())
        session["uid"] = None
        session["auth"] = False        
    # Renders the home page
    params_tpl["basic_auth_uri"] = url_for("basic_auth")
    params_tpl["signup_uri"] = url_for("signup")
    return render_template('index.html', params_tpl=params_tpl)


@app.route("/signup", methods=["POST"])
def signup():
    '''
    Callback for validation of signup
    '''
    # Extracts data from the posted request
    container = request.get_json(False, True, False) if request.mimetype == "application/json" else request.form
    login = container["login"]
    password = container["password"]
    email = container["email"]
    # Checks parameters are filled
    if (not login) or (not password) or (not email): 
        return jsonify(message = "Login, password and email must be filled."), 400
    # Checks if a user with given login already exists in db
    if not user_db_service.get_user_by_login(login) is None:
        return jsonify(message = "This login is already used."), 400
    
    #
    # Here we should check that email is valid and not already registered in db.
    # Then we would send a email to this address with an hyperlink to allow the user to confirm her address.
    # For the sake of simplicity, let's forget all this stuff and let's validate the account
    #
    
    # Registers user in db
    user = User(login, password, email)
    user.signin_count += 1
    user_db_service.create_user(user)
    # Everything is ok, let's finalize the authentication 
    session["uid"] = user.uid
    session["auth"] = True
    # Redirects to user page
    return jsonify(redirect_uri = url_for("user")) 


@app.route("/tfa_activation", methods=["GET"])
def tfa_activation():
    '''
    Prepares a bitid challenge for activation of 2FA
    '''
    # Checks that user is already authenticated
    if not session.get("auth", False): return redirect(url_for("home")), 401  
    # Sets the callback uri
    callback_uri = get_callback_uri("/tfa_activation_callback")
    # Prepares the challenge
    params_tpl = prepare_bitid_challenge(callback_uri)
    # Completes template parameters
    params_tpl["action"] = "tfa_activation"
    # Renders the bitid challenge page
    return render_template('tfa.html', params_tpl=params_tpl)


@app.route("/tfa_activation_callback", methods=["POST"])
def tfa_activation_callback():
    '''
    Callback for validation of bitid challenge during activation of 2FA
    '''
    # Retrieves the callback uri
    callback_uri = get_callback_uri("/tfa_activation_callback")
    # Checks the signature
    (sig_ok, nonce, address, msg) = check_signature(callback_uri)
    if not sig_ok: return jsonify(message = msg), 401
    # Gets the user from db
    user = user_db_service.get_user_by_uid(nonce.uid)
    if user is None: return jsonify(message = "Ooops ! Something went wrong"), 500
    # Registers the address as user's 2FA address in db
    user.set_tfa_address(address)
    user_db_service.update_user(user)
    # Finalizes authentication: Stores address and redirection uri in the nonce
    nonce.tfa_address = address
    nonce.redirect_uri = url_for("user")
    if not nonce_db_service.update_nonce(nonce): return jsonify(message = "Ooops ! Something went wrong"), 500
    return jsonify(address = address, nonce = nonce.sid)       


@app.route("/tfa_challenge", methods=["GET"])
def tfa_challenge():
    '''
    Prepares a bitid challenge for 2FA
    '''
    # Checks that user has passed basic authentication
    if not session.get("uid", ""): return redirect(url_for("home")), 401
    # Sets the callback uri
    callback_uri = get_callback_uri("/tfa_callback")
    # Prepares the challenge
    params_tpl = prepare_bitid_challenge(callback_uri)
    # Completes template parameters
    params_tpl["action"] = "tfa_challenge"
    # Renders the bitid challenge page
    return render_template('tfa.html', params_tpl=params_tpl)
    

@app.route("/tfa_callback", methods=["POST"])
def tfa_callback():
    '''
    Callback for validation of bitid challenge during 2FA
    '''
    # Retrieves the callback uri
    callback_uri = get_callback_uri("/tfa_callback")
    # Checks the signature
    (sig_ok, nonce, address, msg) = check_signature(callback_uri)
    if not sig_ok: return jsonify(message = msg), 401
    # Gets the user from db
    user = user_db_service.get_user_by_uid(nonce.uid)
    if user is None: return jsonify(message = "Ooops ! Something went wrong"), 500
    # Checks that user has activated 2FA
    if not user.tfa_activited(): return jsonify(message = "2FA is not activated for this account"), 500
    # Checks that address used for challenge matches with address associated to the user
    if not address == user.get_tfa_address(): return jsonify(message = "Invalid address"), 500
    # Finalizes authentication: Stores address and redirection uri in the nonce
    nonce.tfa_address = address
    nonce.redirect_uri = url_for("user")
    if not nonce_db_service.update_nonce(nonce): return jsonify(message = "Ooops ! Something went wrong"), 500
    return jsonify(address = address, nonce = nonce.sid)      
    

@app.route("/basic_auth", methods=["POST"])
def basic_auth():
    '''
    Checks basic authentication by login/password
    '''
    # Extracts data from the posted request
    container = request.get_json(False, True, False) if request.mimetype == "application/json" else request.form
    login = container["login"]
    password = container["password"]
    # Checks parameters are filled
    if (not login) or (not password): return jsonify(message = "Login, password and email are mandatory"), 400
    # Checks if user with given login exists in db
    user = user_db_service.get_user_by_login(login)
    if user is None: return jsonify(message = "Wrong login and password combination."), 400
    # Checks user password
    if not user.check_password(password): return jsonify(message = "Wrong login and password combination."), 400
    # Registers user id in session
    session["uid"] = user.uid
    # Checks if 2fa is activated
    if user.tfa_activited():
        # 2FA activated - Redirects to tfa_challenge page
        return jsonify(redirect_uri = url_for("tfa_challenge"))
    else:
        # Basic auth only
        # Let's increase the sign_in counter in user object (for demo purpose only)
        user.signin_count += 1
        user_db_service.update_user(user)
        # Everything is ok, let's finalize the authentication 
        session["auth"] = True
        # Redirects to user page
        return jsonify(redirect_uri = url_for("user"))


@app.route("/tfa_auth", methods=["GET"])
def tfa_auth():
    '''
    Checks if a bitid challenge has been validated
    Challenges are used during 2FA activation and during user authentication with 2FA activated
    '''
    # Checks that session id is set
    if not session["sid"]:
        return jsonify(auth = 0)
    # Gets the nonce associated to the session id
    nonce = nonce_db_service.get_nonce_by_sid(session["sid"])
    if nonce is None: return jsonify(auth = 0)
    # Checks if the nonce has a user id and a 2fa address associated
    if (nonce.uid is None) or (nonce.tfa_address is None): return jsonify(auth = 0)
    # Gets the user from db
    user = user_db_service.get_user_by_uid(nonce.uid)
    if user is None: return jsonify(auth = 0)
    # Let's increase the sign_in counter in user object (for demo purpose only)
    user.signin_count += 1
    user_db_service.update_user(user)
    # Everything is ok, let's finalize the authentication  
    redirect_uri = nonce.redirect_uri  
    session["auth"] = True
    nonce_db_service.delete_nonce(nonce)
    return jsonify(auth = 1, redirect_uri = redirect_uri)


@app.route("/user", methods=["GET"])
def user():
    '''
    Prepares rendering of /user page
    '''
    # Checks if user is logged
    if not session.get("auth", False): return redirect(url_for("home")), 401    
    # Gets the user from db
    user = user_db_service.get_user_by_uid(session["uid"])
    if user is None: return redirect(url_for("home")), 401    
    # Gets user's data and add them to dictionary of template parameters
    params_tpl = {"user_login": user.login,
                  "user_signin_count": user.signin_count,
                  "user_tfa": user.tfa_activited(),
                  "user_tfa_address": user.get_tfa_address()}
    # Renders the template
    return render_template("user.html", params_tpl=params_tpl)


@app.route("/sign_out", methods=["GET"])
def sign_out():
    '''
    Sign out
    '''
    session.pop("auth", None)
    return redirect(url_for("home"))



'''
Utils functions
'''
@app.template_filter("escape_slash")
def escape_slash_filter(s):
    return str.replace(s, "/", "\\/")


def prepare_bitid_challenge(callback_uri):
    # Creates a new nonce associated to this session
    nonce = Nonce(session["sid"])
    nonce.uid = session.get("uid", None)
    # Stores the nonce in database
    nonce_db_service.create_nonce(nonce)
    # Builds the challenge (bitid uri) 
    bitid_uri = bitid.build_uri(callback_uri, nonce.nid)
    # Gets the qrcode uri
    qrcode = bitid.qrcode(bitid_uri)
    # Returns a dictionary storing data related to the challenge
    return {"callback_uri": callback_uri, "bitid_uri": bitid_uri, "qrcode": qrcode}


def get_callback_uri(path_callback):
    '''
    Returns callback uri for 2FA actions
    '''
    callback_uri = url_for("home", _external=True)
    parsed = urlparse(callback_uri)
    scheme = parsed.scheme
    netloc = parsed.netloc
    return urlunparse((scheme, netloc, path_callback, "", "", ""))


def check_signature(callback_uri):
    # Extracts data from the posted request (from form of from json data according to the method used by the client)
    container = request.get_json(False, True, False) if request.mimetype == "application/json" else request.form
    bitid_uri = container["uri"]
    signature = container["signature"]
    address   = container["address"]
    # Checks the address
    if not bitid.address_valid(address, USE_TESTNET):
        return (False, None, address, "Address is invalid or not legal")
    # Checks the bitid uri
    if not bitid.uri_valid(bitid_uri, callback_uri):
        return (False, None, address, "BitID URI is invalid or not legal")
    # Checks the signature
    if not bitid.signature_valid(address, signature, bitid_uri, callback_uri, USE_TESTNET):
        return (False, None, address, "Signature is incorrect")
    
    # Note that the previous 3 steps could also be done in 1 step with following code:
    # if not bitid.challenge_valid(address, signature, bitid_uri, callback_uri, USE_TESTNET):
    #    return (False, "Sorry but something does not match")
    
    # Checks the nonce
    nid = bitid.extract_nonce(bitid_uri)
    # Tries to retrieve the nonce from db
    nonce = nonce_db_service.get_nonce_by_nid(nid)
    if nonce is None:
        return (False, None, address, "NONCE is illegal")
    elif nonce.has_expired():
        nonce_db_service.delete_nonce(nonce)
        return (False, None, address, "NONCE has expired")
    # Everything is  ok
    return (True, nonce, address, "")


if __name__ == "__main__":
    # Comment/uncomment following lines to switch production / debug mode
    # Note that using BitId with a smartphone is not possible in debug mode (server only accessible by local machine)
    app.run(host='0.0.0.0')
    #app.run(debug=True)