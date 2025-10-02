#!/usr/bin/env python
import os
import jwt
import sys
import base64
import boto3

# Set AWS credentials and region to match localstack
if 'AWS_ACCESS_KEY_ID' not in os.environ:
    os.environ['AWS_ACCESS_KEY_ID'] = 'key'
if 'AWS_SECRET_ACCESS_KEY' not in os.environ:
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'secret'
if 'AWS_DEFAULT_REGION' not in os.environ:
    os.environ['AWS_DEFAULT_REGION'] = 'eu-west-1'

def verify_jwt_with_kms(incoming_token):
    # Split JWT into header, payload, and signature
    try:
        header_b64, payload_b64, signature_b64 = incoming_token.split('.')
    except ValueError:
        print("Token format invalid")
        return False

    # The message is the header and payload joined by a period.
    message = f"{header_b64}.{payload_b64}".encode('utf-8')

    # Fix padding for base64 decoding and decode signature (base64url encoded)
    padding = '=' * (-len(signature_b64) % 4)
    signature = base64.urlsafe_b64decode(signature_b64 + padding)

    # Extract info from header
    unverified_header = jwt.get_unverified_header(incoming_token)
    kid = unverified_header.get('kid')
    alg = unverified_header.get('alg')

    if not kid or not alg:
        print("Missing 'kid' or 'alg' in token header")
        return False

    # Map JWT alg to KMS signing algorithm
    if alg == 'PS256':
        signing_alg = 'RSASSA_PSS_SHA_256'
    elif alg == 'PS384':
        signing_alg = 'RSASSA_PSS_SHA_384'
    elif alg == 'PS512':
        signing_alg = 'RSASSA_PSS_SHA_512'
    elif alg == 'RS256':
        signing_alg = 'RSASSA_PKCS1_V1_5_SHA_256'
    elif alg == 'RS384':
        signing_alg = 'RSASSA_PKCS1_V1_5_SHA_384'
    elif alg == 'RS512':
        signing_alg = 'RSASSA_PKCS1_V1_5_SHA_512'
    elif alg == 'ES256':
        signing_alg = 'ECDSA_SHA_256'
    elif alg == 'ES384':
        signing_alg = 'ECDSA_SHA_384'
    elif alg == 'ES512':
        signing_alg = 'ECDSA_SHA_512'
    else:
        print(f"Unsupported signing algorithm: {alg}")
        return False

    # Instantiate the KMS client
    session = boto3.Session()
    kms_client = session.client('kms', endpoint_url='http://localstack:4566')

    # Use KMS verify to check the signature.
    try:
        response = kms_client.verify(
            KeyId=kid,
            Message=message,
            Signature=signature,
            SigningAlgorithm=signing_alg,
            MessageType='RAW'
        )
    except Exception as e:
        print(f"KMS verify call failed: {e}")
        return False

    if response.get('SignatureValid'):
        print("JWT signature is valid according to KMS")
        return True
    else:
        print("JWT signature is invalid according to KMS")
        return False

if len(sys.argv) < 2 or len(sys.argv[1]) < 3:
    print("Please provide the incoming JWT as a command line argument")
    sys.exit(1)

incoming_token = sys.argv[1]
verification_result = verify_jwt_with_kms(incoming_token)

if verification_result:
    print("JWT verified successfully")
else:
    print("JWT verification failed")