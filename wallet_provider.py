import uuid
import json
from flask import jsonify, request, Response
from datetime import datetime
import logging
from jwcrypto import jwk, jwt
import base64
import copy
import sys
import requests
from flask_limiter import Limiter,util
import db # db manager for wallet-provider

logging.basicConfig(level=logging.INFO)

try:
    WALLET_PROVIDER_KEY = json.load(open('keys.json', 'r'))['wallet_provider_key']
except Exception:
    logging.info('wallet provider keys missing')
    sys.exit()

TRUSTED_LIST = ['did:web:talao.co']
WALLET_PROVIDER_PUBLIC_KEY =  copy.copy(WALLET_PROVIDER_KEY)
del WALLET_PROVIDER_PUBLIC_KEY['d']
WALLET_PROVIDER_VM = 'did:web:talao.co#key-2'
WALLET_PROVIDER_DID = 'did:web:talao.co'
WALLET_API_VERSION = '0.2.2'


def init_app(app, red, mode):
    # endpoints for OpenId customer application
    limiter = Limiter(util.get_remote_address, app=app, storage_uri="redis://127.0.0.1:6379")
    app.add_url_rule('/nonce',  view_func=nonce, methods=['GET'], defaults={'red': red, 'limiter': limiter})
    app.add_url_rule('/token',  view_func=wallet_attestation_endpoint, methods=['POST'], defaults={'red': red})
    app.add_url_rule('/configuration',  view_func=wallet_configuration_endpoint, methods=['POST'])
    app.add_url_rule('/wallet_api_version',  view_func=wallet_api_version, methods=['GET'], defaults={'limiter': limiter})


def thumbprint(key):
    signer_key = jwk.JWK(**key) 
    return signer_key.thumbprint()


def get_payload_from_token(token) -> dict:
    payload = token.split('.')[1]
    payload += '=' * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def get_header_from_token(token):
    header = token.split('.')[0]
    header += '=' * ((4 - len(header) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(header).decode())


def resolve_did(vm) -> dict:
    did = vm.split('#')[0]
    url = 'https://unires.talao.co/1.0/identifiers/' + did
    try:
        r = requests.get(url, auth=('unires','test'))
        did_document = r.json()['didDocument']
        logging.info('Talao Universal Resolver used')
    except Exception:
        try:
            url = 'https://dev.uniresolver.io/1.0/identifiers/' + did
            r = requests.get(url)
            did_document = r.json()['didDocument']
            logging.info('DIF Universal Resolver used')
        except Exception:
            logging.error('Cannot access to resolvers')

    for verification_method in did_document['verificationMethod']:
        if vm == verification_method['id'] or '#' + vm.split('#')[1] == verification_method['id']:
            jwk = verification_method.get('publicKeyJwk')
            if not jwk:
                publicKeyBase58 = verification_method.get('publicKeyBase58')
                logging.info('publiccKeyBase48 = %s', publicKeyBase58)
                return publicKeyBase58
            else:  
                logging.info('publicKeyJwk = %s', jwk)
                return jwk
    return


def verif_token(token):
    header = get_header_from_token(token)
    payload = get_payload_from_token(token)
    if header.get('typ') == 'wiar+jwt':
        dict_key = payload['cnf']['jwk']
    elif header.get('typ') == 'wallet-attestation+jwt':
        dict_key = resolve_did(header['kid'])
    else:
        raise Exception('Cannot resolve public key for this typ')
    if not dict_key:
        raise Exception('Cannot resolve public key')
    a = jwt.JWT.from_jose_token(token)
    issuer_key = jwk.JWK(**dict_key)
    a.validate(issuer_key)
    return True


def manage_error(error, error_description, status=400):
    """
    Return error code to wallet
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-error-response
    """
    # console
    logging.warning('manage error = %s', error_description)
    # wallet
    payload = {
        "error": error,
        "error_description": error_description,
    }
    headers = {'Cache-Control': 'no-store', 'Content-Type': 'application/json'}
    return {'response': json.dumps(payload), 'status': status, 'headers': headers}


def get_payload_from_jwt(token) -> dict:
    payload = token.split('.')[1]
    payload += '=' * ((4 - len(payload) % 4) % 4) # solve the padding issue of the base64 python lib
    return json.loads(base64.urlsafe_b64decode(payload).decode())


def sign_jwt(nonce, payload, typ, aud=None, jti=True, duration=365*24*60*60):
    header = {
        'typ':typ,
        'kid': WALLET_PROVIDER_VM,
        'alg': 'ES256'
    }
    logging.info('header = %s', header)
    data = {
        'iss': WALLET_PROVIDER_DID,
        'iat': datetime.timestamp(datetime.now().replace(second=0, microsecond=0)),
        'exp': datetime.timestamp(datetime.now().replace(second=0, microsecond=0)) + duration
    }
    if nonce:
        data['nonce'] = nonce  
    if jti:
        data['jti'] = str(uuid.uuid1())
    if aud:
        data['aud'] = aud
    data.update(payload)
    token = jwt.JWT(header=header, claims=data, algs=['ES256'])
    signer_key = jwk.JWK(**WALLET_PROVIDER_KEY) 
    try:
        token.make_signed_token(signer_key)
    except Exception:
        return
    return token.serialize()


def wallet_api_version(limiter):
    try:
       with limiter.limit("1/seconde"):
           pass
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Exceed rate limit-> ' + str(e)))
    return jsonify(WALLET_API_VERSION)


def nonce(red, limiter):
    try:
       with limiter.limit("1/seconde"):
           pass
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Exceed rate limit-> ' + str(e)))
    nonce = str(uuid.uuid1())
    red.setex(nonce, 10, request.host )
    logging.info('nonce is sent to wallet')
    return jsonify({'nonce': nonce})
  

def wallet_attestation_endpoint(red):
    """
    https://italia.github.io/eudi-wallet-it-docs/versione-corrente/en/wallet-instance-attestation.html#id1

    """
    try:
        assertion = request.form['assertion']
        grant_type = request.form['grant_type']
    except Exception:
        return Response(**manage_error('invalid_request', 'assertion or grant_type missing'))
    if grant_type != 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        return Response(**manage_error('invalid_grant', 'Assertion expected'))

    try:
        wallet_request = get_payload_from_jwt(assertion)
        wallet_cnf =  copy.copy(wallet_request['cnf'])
        wallet_cnf['jwk'].update({'kid': wallet_request['iss']})
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Assertion format is incorrect -> ' + str(e)))

    # check wallet request signature
    try:
        result = verif_token(assertion)
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Assertion signature check failed : ' + str(e)))
    if not result:
        return Response(**manage_error('invalid_request', 'Assertion signature check failed'))

    logging.info('wallet request signature is ok')
    
    # check wallet request nonce
    nonce = wallet_request['nonce']
    if not red.get(nonce):
        return Response(**manage_error('invalid_request', 'Nonce incorrect'))
    red.delete(nonce)

    # build and send wallet attestation
    payload = {
        "sub": wallet_request['iss'],
        "cnf": wallet_cnf,
        "authorization_endpoint": "https://app.altme.io/app/download./authorize:",
        "response_types_supported": [
            "vp_token",
            "id_token"
        ],
        "response_modes_supported": [
            "form_post.jwt"
        ],
        "vp_formats_supported": {
            "vc+sd-jwt": {
                "sd-jwt_alg_values": [
                    "ES256",
                ]
            }
        },
        "request_object_signing_alg_values_supported": [
            "ES256"
        ],
        "presentation_definition_uri_supported": True,
    }   
    typ = 'wallet-attestation+jwt'
    wallet_attestation = sign_jwt(nonce, payload, typ, jti=False)
    if not wallet_attestation:
        return Response(**manage_error("server_error", "Wallet attestation failed to be signed"))
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    logging.info('wallet attestation is sent to wallet')
    return Response(wallet_attestation, headers=headers)


def wallet_configuration_endpoint():
    try:
        user_email = request.authorization['username']
        user_password = request.authorization['password']
    except Exception as e:
        return Response(**manage_error('invalid_request', 'basic authentication missing or incorrect -> ' + str(e)))
    
    # check user and password
    try:
        check = db.verify_password_user(user_email, user_password)
    except Exception:
        return Response(**manage_error('server_error', 'verify_password_user DB call failed'))
    if not check:
        Response(**manage_error('invalid_request', 'user not found'))
    logging.info('logging/password is fine for %s', user_email)

    try:
        wallet_attestation = get_payload_from_jwt(request.form['assertion'])
    except Exception as e:
        return Response(**manage_error('invalid_request', 'assertion missing -> ' + str(e)))

     # check wallet attestation signature
    try:
        verif_token(request.form['assertion'])
        logging.info('wallet attestation signature is ok')
    except Exception as e:
        return Response(**manage_error('invalid_request', 'Wallet attestation signature check failed ->' + str(e)))
    
    # check wallet attestation format
    try:
        iss = wallet_attestation['iss']
        exp = wallet_attestation['exp']
        user_jwk = wallet_attestation['cnf']['jwk']
        user_sub = wallet_attestation['sub']
    except Exception as e:
        return Response(**manage_error('invalid_request', 'incorrect wallet attestation format -> ' + str(e))) 
        
    if iss not in TRUSTED_LIST:
        return Response(**manage_error('invalid_request', 'Wallet attestation is not issued by trusted wallet provider'))
    if exp < datetime.timestamp(datetime.now().replace(second=0, microsecond=0)):
        return Response(**manage_error('invalid_request', 'Wallet attestation expired'))
    
    # Update user data with user wallet attestation data
    user_data = db.read_data_user(user_email) # -> dict
    if not user_data:
        return Response(**manage_error('invalid_request', 'user not found'))
    user_data.update(
        {        
            "wallet_instance_key_thumbprint": user_sub,
            "wallet_cnf_jwk": user_jwk,
            "attestation_iat": datetime.timestamp(datetime.now().replace(second=0, microsecond=0)),
        })
    try:
        check = db.update_data_user(user_email, json.dumps(user_data))
    except Exception as e:
        return Response(**manage_error('server_error', 'user data update failed -> ' + str(e)))
    logging.info('user data is now updated')

    # Build and sign configuration jwt for user wallet 
    config = {}
    try:
        config = db.read_config(user_email) # -> dict
    except Exception:
        return Response(**manage_error('server_error', 'incorrect configuration file'))
    if not config:
        return Response(**manage_error('invalid_request', 'configuration is not found for this user ' + user_email))
    payload = sign_jwt(None, config, 'JWT', duration=90*24*60*60 )
    if not payload:
        return Response(**manage_error('server_error', 'Configuration fails to be signed'))
    headers = { 
        "Content-Type": "application/jwt",
        "Cache-Control": "no-cache"
    }
    logging.info('Configuration is sent to wallet')
    return Response(payload, headers=headers)


