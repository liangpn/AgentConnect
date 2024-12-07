# AgentConnect: https://github.com/chgaowei/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.
'''
Generate DID document
Generate secure JWT
Send HTTP request
'''
from typing import Dict, Tuple, Optional, List, Callable, Union
import urllib.parse
import base64
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import aiohttp
import asyncio
import json
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from canonicaljson import encode_canonical_json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
import re
from cryptography.hazmat.primitives.asymmetric import ed25519
import base58  # Need to add this dependency

logger = logging.getLogger(__name__)

# 添加曲线映射字典
CURVE_MAPPING = {
    'secp256k1': ec.SECP256K1(),
    'P-256': ec.SECP256R1(),
    'P-384': ec.SECP384R1(),
    'P-521': ec.SECP521R1(),
}

def _encode_base64url(data: bytes) -> str:
    """Encode bytes data to base64url format"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def _public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> Dict:
    """Convert secp256k1 public key to JWK format"""
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "secp256k1",
        "x": _encode_base64url(numbers.x.to_bytes(32, 'big')),
        "y": _encode_base64url(numbers.y.to_bytes(32, 'big')),
        "kid": _encode_base64url(public_key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.CompressedPoint
        ))
    }

def create_did_wba_document(
    hostname: str,
    port: Optional[int] = None,
    path_segments: Optional[List[str]] = None
) -> Tuple[Dict, Dict]:
    """
    Generate DID document and corresponding private key dictionary
    
    Args:
        hostname: Hostname
        port: Optional port number
        path_segments: Optional DID path segments list, e.g. ['user', 'alice']
    
    Returns:
        Tuple[Dict, Dict]: Returns a tuple containing two dictionaries:
            - First dict is the DID document 
            - Second dict is the private keys dictionary where key is DID fragment (e.g. "key-1") 
              and value is the private key in PEM format
    """
    logger.info(f"Creating DID WBA document for hostname: {hostname}")
    
    # Build base DID
    did_base = f"did:wba:{hostname}"
    if port is not None:
        encoded_port = urllib.parse.quote(f":{port}")
        did_base = f"{did_base}{encoded_port}"
        logger.debug(f"Added port to DID base: {did_base}")
    
    did = did_base
    if path_segments:
        did_path = ":".join(path_segments)
        did = f"{did_base}:{did_path}"
        logger.debug(f"Added path segments to DID: {did}")
    
    # Generate secp256k1 key pair
    logger.debug("Generating secp256k1 key pair")
    secp256k1_private_key = ec.generate_private_key(ec.SECP256K1())
    secp256k1_public_key = secp256k1_private_key.public_key()
    
    # Build verification method
    verification_method = {
        "id": f"{did}#key-1",
        "type": "EcdsaSecp256k1VerificationKey2019",
        "controller": did,
        "publicKeyJwk": _public_key_to_jwk(secp256k1_public_key)
    }
    
    # Build DID document
    did_document = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1"
        ],
        "id": did,
        "verificationMethod": [verification_method],
        "authentication": [verification_method["id"]]
    }
    
    # Build private keys dictionary (serialize private key to PEM format)
    private_keys = {
        "key-1": secp256k1_private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
    }
    
    logger.info(f"Successfully created DID document with ID: {did}")
    return did_document, private_keys

async def resolve_did_wba_document(did: str) -> Dict:
    """
    Resolve DID document from Web DID asynchronously

    Args:
        did: DID to resolve, e.g. did:wba:example.com:user:alice

    Returns:
        Dict: Resolved DID document

    Raises:
        ValueError: If DID format is invalid
        aiohttp.ClientError: If HTTP request fails
    """
    logger.info(f"Resolving DID document for: {did}")

    # Validate DID format
    if not did.startswith("did:wba:"):
        raise ValueError("Invalid DID format: must start with 'did:wba:'")

    # Extract domain and path from DID
    did_parts = did.split(":", 3)
    if len(did_parts) < 4:
        raise ValueError("Invalid DID format: missing domain")

    domain = did_parts[2]
    path_segments = did_parts[3].split(":") if len(did_parts) > 3 else []

    try:
        # Create HTTP client
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Build URL
            url = f"https://{domain}"
            if path_segments:
                url += '/' + '/'.join(path_segments)
            else:
                url += '/.well-known/did.json'

            logger.debug(f"Requesting DID document from URL: {url}")

            async with session.get(
                url,
                headers={
                    'Accept': 'application/json'
                },
                ssl=True
            ) as response:
                response.raise_for_status()
                did_document = await response.json()

                # Verify document ID
                if did_document.get('id') != did:
                    raise ValueError(
                        f"DID document ID mismatch. Expected: {did}, "
                        f"Got: {did_document.get('id')}"
                    )

                logger.info(f"Successfully resolved DID document for: {did}")
                return did_document

    except aiohttp.ClientError as e:
        logger.error(f"Failed to resolve DID document: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Failed to resolve DID document: {str(e)}")
        raise

# Add a sync wrapper for backward compatibility
def resolve_did_wba_document_sync(did: str) -> Dict:
    """
    Synchronous wrapper for resolve_did_wba_document

    Args:
        did: DID to resolve, e.g. did:wba:example.com:user:alice

    Returns:
        Dict: Resolved DID document
    """
    return asyncio.run(resolve_did_wba_document(did))

def generate_auth_header(
    did_document: Dict,
    service_domain: str,
    sign_callback: Callable[[bytes, str], str]
) -> str:
    """
    Generate the Authorization header for DID authentication.
    
    Args:
        did_document: DID document dictionary.
        service_domain: Server domain.
        sign_callback: Signature callback function that takes the content to sign and the verification method fragment as parameters.
            callback(content_to_sign: bytes, verification_method_fragment: str) -> str
            
    Returns:
        str: Value of the Authorization header. Do not include "Authorization:" prefix.
        
    Raises:
        ValueError: If the DID document format is invalid.
    """
    logger.info("Starting to generate DID authentication header.")
    
    # Validate DID document
    did = did_document.get('id')
    if not did:
        raise ValueError("DID document is missing the id field.")
        
    # Get the fragment of the first verification method
    verification_methods = did_document.get('verificationMethod', [])
    if not verification_methods:
        raise ValueError("DID document is missing verification methods.")
    
    # Extract fragment from verification method ID
    method_id = verification_methods[0]['id']
    verification_method_fragment = method_id.split('#')[-1]
    
    # Generate a 16-byte random nonce
    nonce = secrets.token_hex(16)
    
    # Generate ISO 8601 formatted UTC timestamp
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Construct the data to sign
    data_to_sign = {
        "nonce": nonce,
        "timestamp": timestamp,
        "service": service_domain,
        "did": did
    }
    
    # Normalize JSON using JCS
    canonical_json = encode_canonical_json(data_to_sign)
    
    # Calculate SHA-256 hash
    content_hash = hashlib.sha256(canonical_json).digest()
    
    # Sign using the callback function
    signature = sign_callback(content_hash, verification_method_fragment)
    
    # Construct the Authorization header
    auth_header = (
        f"DID {did} "
        f"Nonce {nonce} "
        f"Timestamp {timestamp} "
        f"VerificationMethod {verification_method_fragment} "
        f"Signature {signature}"
    )
    
    logger.info("Successfully generated DID authentication header.")
    logger.debug(f"Generated Authorization header: {auth_header}")
    
    return auth_header

def _find_verification_method(did_document: Dict, verification_method_id: str) -> Optional[Dict]:
    """
    Find verification method in DID document by ID.
    Searches in both verificationMethod and authentication arrays.
    
    Args:
        did_document: DID document
        verification_method_id: Full verification method ID
        
    Returns:
        Optional[Dict]: Verification method if found, None otherwise
    """
    # Search in verificationMethod array
    for method in did_document.get('verificationMethod', []):
        if method['id'] == verification_method_id:
            return method
            
    # Search in authentication array
    for auth in did_document.get('authentication', []):
        # Handle both reference string and embedded verification method
        if isinstance(auth, str):
            if auth == verification_method_id:
                # If it's a reference, look up in verificationMethod
                for method in did_document.get('verificationMethod', []):
                    if method['id'] == verification_method_id:
                        return method
        elif isinstance(auth, dict) and auth.get('id') == verification_method_id:
            return auth
            
    return None

def _extract_ec_public_key_from_jwk(jwk: Dict) -> ec.EllipticCurvePublicKey:
    """
    Extract EC public key from JWK format.
    
    Args:
        jwk: JWK dictionary
        
    Returns:
        ec.EllipticCurvePublicKey: Public key
        
    Raises:
        ValueError: If JWK format is invalid or curve is unsupported
    """
    if jwk.get('kty') != 'EC':
        raise ValueError("Invalid JWK: kty must be EC")
        
    crv = jwk.get('crv')
    if not crv:
        raise ValueError("Missing curve parameter in JWK")
        
    curve = CURVE_MAPPING.get(crv)
    if curve is None:
        raise ValueError(f"Unsupported curve: {crv}. Supported curves: {', '.join(CURVE_MAPPING.keys())}")
        
    try:
        x = int.from_bytes(base64.b64decode(jwk['x'] + '=='), 'big')
        y = int.from_bytes(base64.b64decode(jwk['y'] + '=='), 'big')
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, curve)
        return public_numbers.public_key()
    except Exception as e:
        raise ValueError(f"Invalid JWK parameters: {str(e)}")

def _extract_ed25519_public_key_from_multibase(multibase: str) -> ed25519.Ed25519PublicKey:
    """
    Extract Ed25519 public key from multibase format.
    
    Args:
        multibase: Multibase encoded string
        
    Returns:
        ed25519.Ed25519PublicKey: Public key
        
    Raises:
        ValueError: If multibase format is invalid
    """
    if not multibase.startswith('z'):
        raise ValueError("Unsupported multibase encoding")
    try:
        key_bytes = base58.b58decode(multibase[1:])
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        raise ValueError(f"Invalid multibase key: {str(e)}")

def _extract_ed25519_public_key_from_base58(base58_key: str) -> ed25519.Ed25519PublicKey:
    """
    Extract Ed25519 public key from base58 format.
    
    Args:
        base58_key: Base58 encoded string
        
    Returns:
        ed25519.Ed25519PublicKey: Public key
        
    Raises:
        ValueError: If base58 format is invalid
    """
    try:
        key_bytes = base58.b58decode(base58_key)
        return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
    except Exception as e:
        raise ValueError(f"Invalid base58 key: {str(e)}")

def _extract_secp256k1_public_key_from_multibase(multibase: str) -> ec.EllipticCurvePublicKey:
    """
    从multibase格式提取secp256k1公钥
    
    Args:
        multibase: multibase编码的字符串 (z开头的base58btc格式)
        
    Returns:
        ec.EllipticCurvePublicKey: secp256k1公钥对象
        
    Raises:
        ValueError: 如果multibase格式无效
    """
    if not multibase.startswith('z'):
        raise ValueError("不支持的multibase编码格式，必须以'z'开头(base58btc)")
    
    try:
        # 解码base58btc (移除z前缀)
        key_bytes = base58.b58decode(multibase[1:])
        
        # secp256k1压缩格式公钥为33字节:
        # 1字节前缀(0x02或0x03) + 32字节X坐标
        if len(key_bytes) != 33:
            raise ValueError("无效的secp256k1公钥长度")
            
        # 从压缩格式恢复公钥
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            key_bytes
        )
    except Exception as e:
        raise ValueError(f"无效的multibase密钥: {str(e)}")

def _extract_public_key(verification_method: Dict) -> Union[ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]:
    """
    Extract public key from verification method.
    
    Supported verification method types:
    - EcdsaSecp256k1VerificationKey2019 (JWK, Multibase)
    - Ed25519VerificationKey2020 (JWK, Base58, Multibase)
    - Ed25519VerificationKey2018 (JWK, Base58, Multibase)
    - JsonWebKey2020 (JWK)
    
    Args:
        verification_method: Verification method dictionary
        
    Returns:
        Union[ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey]: Public key
        
    Raises:
        ValueError: If key format or type is unsupported or invalid
    """
    method_type = verification_method.get('type')
    if not method_type:
        raise ValueError("Verification method missing 'type' field")
        
    # Handle EcdsaSecp256k1VerificationKey2019
    if method_type == 'EcdsaSecp256k1VerificationKey2019':
        if 'publicKeyJwk' in verification_method:
            jwk = verification_method['publicKeyJwk']
            if jwk.get('crv') != 'secp256k1':
                raise ValueError("Invalid curve for EcdsaSecp256k1VerificationKey2019")
            return _extract_ec_public_key_from_jwk(jwk)
        elif 'publicKeyMultibase' in verification_method:
            return _extract_secp256k1_public_key_from_multibase(
                verification_method['publicKeyMultibase']
            )
            
    # Handle Ed25519 verification methods
    elif method_type in ['Ed25519VerificationKey2020', 'Ed25519VerificationKey2018']:
        if 'publicKeyJwk' in verification_method:
            jwk = verification_method['publicKeyJwk']
            if jwk.get('kty') != 'OKP' or jwk.get('crv') != 'Ed25519':
                raise ValueError(f"Invalid JWK parameters for {method_type}")
            try:
                key_bytes = base64.b64decode(jwk['x'] + '==')
                return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)
            except Exception as e:
                raise ValueError(f"Invalid Ed25519 JWK: {str(e)}")
        elif 'publicKeyBase58' in verification_method:
            return _extract_ed25519_public_key_from_base58(
                verification_method['publicKeyBase58']
            )
        elif 'publicKeyMultibase' in verification_method:
            return _extract_ed25519_public_key_from_multibase(
                verification_method['publicKeyMultibase']
            )
            
    # Handle JsonWebKey2020
    elif method_type == 'JsonWebKey2020':
        if 'publicKeyJwk' in verification_method:
            return _extract_ec_public_key_from_jwk(verification_method['publicKeyJwk'])
            
    raise ValueError(
        f"Unsupported verification method type or missing required key format: {method_type}"
    )

def verify_auth_header_signature(
    auth_header: str,
    did_document: Dict,
    service_domain: str
) -> Tuple[bool, str]:
    """
    Verify the signature in DID authentication header.
    Note: This function only verifies the signature. It does not validate timestamp or nonce.
    
    Args:
        auth_header: Authorization header value (without "Authorization:" prefix)
        did_document: DID document
        service_domain: Server domain
        
    Returns:
        Tuple[bool, str]: (verification success, reason message)
    """
    logger.info("Starting DID authentication header verification")
    
    try:
        # Convert header to lowercase for case-insensitive matching
        auth_header = auth_header.lower()
        
        # Define required fields and their patterns
        required_fields = {
            'did': r'did\s+([\S]+)',
            'nonce': r'nonce\s+([\S]+)',
            'timestamp': r'timestamp\s+([\S]+)',
            'method': r'verificationmethod\s+([\S]+)',
            'signature': r'signature\s+([\S]+)'
        }
        
        # Extract all fields
        header_parts = {}
        for field, pattern in required_fields.items():
            match = re.search(pattern, auth_header)
            if not match:
                return False, f"Missing required field: {field}"
            header_parts[field] = match.group(1)
        
        client_did = header_parts['did']
        nonce = header_parts['nonce']
        timestamp_str = header_parts['timestamp']
        verification_method = header_parts['method']
        signature = header_parts['signature']
         
        # Verify DID
        if did_document.get('id') != client_did:
            return False, "DID mismatch"
            
        # Construct data to verify
        data_to_verify = {
            "nonce": nonce,
            "timestamp": timestamp_str,
            "service": service_domain,
            "did": client_did
        }
        
        # Normalize JSON using JCS
        canonical_json = encode_canonical_json(data_to_verify)
        
        # Calculate SHA-256 hash
        content_hash = hashlib.sha256(canonical_json).digest()
        
        # Get verification method from DID document
        verification_method_id = f"{client_did}#{verification_method}"
        
        # Find verification method
        method = _find_verification_method(did_document, verification_method_id)
        if not method:
            return False, "Verification method not found"
            
        # Extract public key
        try:
            public_key = _extract_public_key(method)
        except ValueError as e:
            return False, f"Invalid or unsupported key format: {str(e)}"
        except Exception as e:
            return False, f"Error extracting public key: {str(e)}"
            
        # Decode signature
        try:
            signature_bytes = base64.b64decode(signature + '==')
            r_length = len(signature_bytes) // 2
            r = int.from_bytes(signature_bytes[:r_length], 'big')
            s = int.from_bytes(signature_bytes[r_length:], 'big')
            signature_der = utils.encode_dss_signature(r, s)
        except Exception as e:
            return False, f"Invalid signature format: {str(e)}"
        
        # Verify signature
        try:
            public_key.verify(
                signature_der,
                content_hash,
                ec.ECDSA(hashes.SHA256())
            )
            logger.info("DID authentication signature verification successful")
            return True, "Verification successful"
        except InvalidSignature:
            return False, "Signature verification failed"
            
    except Exception as e:
        logger.error(f"Error during verification process: {str(e)}")
        return False, f"Verification process error: {str(e)}"

