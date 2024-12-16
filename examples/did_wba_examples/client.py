# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

# This is a client example used to test whether your server supports DID WBA authentication.
# It uses a pre-created DID document and private key to access a test interface on your server.
# If it returns 200, it indicates that the server supports DID WBA authentication.

import asyncio
import json
import logging
import aiohttp
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from agent_connect.authentication.did_wba import (
    resolve_did_wba_document,
    generate_auth_header
)
from agent_connect.utils.log_base import set_log_color_level

# THIS IS A TEST DID DOCUMENT AND PRIVATE KEY
CLIENT_DID = "did:wba:agent-network-protocol.com:wba:user:2a6e7861bb3277cd"
CLIENT_DID_DOCUMENT = '''
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1",
    "https://w3id.org/security/suites/secp256k1-2019/v1"
  ],
  "id": "did:wba:agent-network-protocol.com:wba:user:2a6e7861bb3277cd",
  "verificationMethod": [
    {
      "id": "did:wba:agent-network-protocol.com:wba:user:2a6e7861bb3277cd#key-1",
      "type": "EcdsaSecp256k1VerificationKey2019",
      "controller": "did:wba:agent-network-protocol.com:wba:user:2a6e7861bb3277cd",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "secp256k1",
        "x": "rDiSI-FZPwoTRWVl6ABuAphAErjpOHdy8yN9tJGMLdI",
        "y": "5sGQrDJRJWOZwky_VG1QML_HpuUcgcUbYvcJWGvTqPQ",
        "kid": "jJ9iDppRoHShKnSXYxLNT3lNYqSTWn9uJFLtXKICIwY"
      }
    }
  ],
  "authentication": [
    "did:wba:agent-network-protocol.com:wba:user:2a6e7861bb3277cd#key-1"
  ]
}'''

CLIENT_PRIVATE_KEY = '''-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgopMqAyzVPtU6yDK4gHmu
2So23XgnwwTMgoXKTLHNaVGhRANCAASsOJIj4Vk/ChNFZWXoAG4CmEASuOk4d3Lz
I320kYwt0ubBkKwyUSVjmcJMv1RtUDC/x6blHIHFG2L3CVhr06j0
-----END PRIVATE KEY-----
'''

# TODO: Change to your own server domain.
TEST_DOMAIN = "agent-network-protocol.com"

def load_private_key(private_key_pem: str) -> ec.EllipticCurvePrivateKey:
    """Load private key from PEM string"""
    return serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

def sign_callback(content: bytes, method_fragment: str) -> bytes:
    """Sign content using private key"""
    private_key = load_private_key(CLIENT_PRIVATE_KEY)
    signature = private_key.sign(
        content,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

async def test_did_auth(url: str, auth_header: str) -> tuple[bool, str]:
    """Test DID authentication and get token"""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers={'Authorization': auth_header}
            ) as response:
                token = response.headers.get('Authorization', '')
                if token.startswith('Bearer '):
                    token = token[7:]  # Remove 'Bearer ' prefix
                return response.status == 200, token
    except Exception as e:
        logging.error("DID authentication test failed: %s", e)
        return False, ''

async def main():
    # 1. Generate authentication header
    logging.info("Generating authentication header...")
    did_document = json.loads(CLIENT_DID_DOCUMENT)
    auth_header = generate_auth_header(
        did_document,
        TEST_DOMAIN,
        sign_callback
    )
    
    # 2. Test DID authentication
    test_url = f"https://{TEST_DOMAIN}/wba/test"
    logging.info("Testing DID authentication at %s", test_url)
    auth_success, token = await test_did_auth(test_url, auth_header)
    
    if auth_success:
        logging.info("DID authentication test successful!")
        logging.info(f"Received token: {token}")
    else:
        logging.error("DID authentication test failed")

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())




