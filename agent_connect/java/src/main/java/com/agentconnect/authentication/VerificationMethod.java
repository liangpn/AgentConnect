package com.agentconnect.authentication;

import io.github.novacrypto.base58.Base58;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Interface for verification methods
 */
public interface VerificationMethod {
    /**
     * Verify signature
     *
     * @param content   Content to verify
     * @param signature Signature in base64url format
     * @return true if signature is valid, false otherwise
     */
    boolean verifySignature(byte[] content, String signature);

    /**
     * Encode signature bytes to base64url format
     *
     * @param signatureBytes Raw signature bytes
     * @return base64url encoded signature
     */
    static String encodeSignature(byte[] signatureBytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
    }

    /**
     * Factory method to create verification method from DID document method entry
     *
     * @param methodDict Verification method entry from DID document
     * @return Appropriate VerificationMethod implementation
     */
    static VerificationMethod createVerificationMethod(Map<String, Object> methodDict) {
        String methodType = (String) methodDict.get("type");
        if (methodType == null) {
            throw new IllegalArgumentException("Missing verification method type");
        }

        switch (methodType) {
            case "EcdsaSecp256k1VerificationKey2019":
                return EcdsaSecp256k1VerificationKey2019.fromDict(methodDict);
            case "Ed25519VerificationKey2018":
                return Ed25519VerificationKey2018.fromDict(methodDict);
            default:
                throw new IllegalArgumentException("Unsupported verification method type: " + methodType);
        }
    }
}

/**
 * AgentConnect: https://github.com/agent-network-protocol/AgentConnect
 * Author: GaoWei Chang
 * Email: chgaowei@gmail.com
 * Website: https://agent-network-protocol.com/
 *
 * This project is open-sourced under the MIT License. For details, please see the LICENSE file.
 *
 * EcdsaSecp256k1VerificationKey2019 implementation
 */
class EcdsaSecp256k1VerificationKey2019 implements VerificationMethod {
    private static final Logger logger = LoggerFactory.getLogger(EcdsaSecp256k1VerificationKey2019.class);
    private final ECPublicKey publicKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Constructor
     *
     * @param publicKey EC public key
     */
    public EcdsaSecp256k1VerificationKey2019(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Verify signature
     *
     * @param content   Content to verify
     * @param signature Signature in base64url format
     * @return true if signature is valid, false otherwise
     */
    @Override
    public boolean verifySignature(byte[] content, String signature) {
        try {
            // Decode base64url signature
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signature + "==");

            // Create ECDSA signature verification
            Signature ecdsaVerify = Signature.getInstance("SHA256withECDSA", "BC");
            ecdsaVerify.initVerify(publicKey);
            ecdsaVerify.update(content);

            return ecdsaVerify.verify(signatureBytes);
        } catch (Exception e) {
            logger.error("Secp256k1 signature verification failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Create instance from verification method dictionary
     *
     * @param methodDict Verification method entry from DID document
     * @return EcdsaSecp256k1VerificationKey2019 instance
     */
    @SuppressWarnings("unchecked")
    public static EcdsaSecp256k1VerificationKey2019 fromDict(Map<String, Object> methodDict) {
        if (methodDict.containsKey("publicKeyJwk")) {
            return new EcdsaSecp256k1VerificationKey2019(
                    extractPublicKeyFromJwk((Map<String, Object>) methodDict.get("publicKeyJwk")));
        } else if (methodDict.containsKey("publicKeyMultibase")) {
            return new EcdsaSecp256k1VerificationKey2019(
                    extractPublicKeyFromMultibase((String) methodDict.get("publicKeyMultibase")));
        }
        throw new IllegalArgumentException("Unsupported key format for EcdsaSecp256k1VerificationKey2019");
    }

    /**
     * Extract public key from JWK format
     *
     * @param jwk JWK dictionary
     * @return EC public key
     */
    @SuppressWarnings("unchecked")
    private static ECPublicKey extractPublicKeyFromJwk(Map<String, Object> jwk) {
        try {
            if (!"EC".equals(jwk.get("kty")) || !"secp256k1".equals(jwk.get("crv"))) {
                throw new IllegalArgumentException("Invalid JWK parameters for Secp256k1");
            }

            // Decode base64url x and y coordinates
            String xBase64 = (String) jwk.get("x");
            String yBase64 = (String) jwk.get("y");
            
            byte[] xBytes = Base64.getUrlDecoder().decode(xBase64 + "==");
            byte[] yBytes = Base64.getUrlDecoder().decode(yBase64 + "==");

            // Create EC parameter spec for secp256k1
            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
            
            // Create EC point from x and y coordinates
            ECPoint point = params.getCurve().createPoint(
                    new java.math.BigInteger(1, xBytes),
                    new java.math.BigInteger(1, yBytes)
            );
            
            // Create EC public key
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, params);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            
            return (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (Exception e) {
            logger.error("Error extracting public key from JWK: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract public key from JWK", e);
        }
    }

    /**
     * Extract public key from multibase format
     *
     * @param multibase Multibase encoded public key
     * @return EC public key
     */
    private static ECPublicKey extractPublicKeyFromMultibase(String multibase) {
        try {
            if (!multibase.startsWith("z")) {
                throw new IllegalArgumentException("Unsupported multibase encoding");
            }
            
            // Decode base58 (after removing the 'z' prefix)
            byte[] keyBytes = Base58.base58Decode(multibase.substring(1));
            
            // Create EC public key from encoded point
            ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
            ECPoint point = params.getCurve().decodePoint(keyBytes);
            
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, params);
            KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
            
            return (ECPublicKey) keyFactory.generatePublic(pubSpec);
        } catch (Exception e) {
            logger.error("Error extracting public key from multibase: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract public key from multibase", e);
        }
    }
}

/**
 * Ed25519VerificationKey2018 implementation
 */
class Ed25519VerificationKey2018 implements VerificationMethod {
    private static final Logger logger = LoggerFactory.getLogger(Ed25519VerificationKey2018.class);
    private final PublicKey publicKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Constructor
     *
     * @param publicKey Ed25519 public key
     */
    public Ed25519VerificationKey2018(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Verify signature
     *
     * @param content   Content to verify
     * @param signature Signature in base64url format
     * @return true if signature is valid, false otherwise
     */
    @Override
    public boolean verifySignature(byte[] content, String signature) {
        try {
            // Decode base64url signature
            byte[] signatureBytes = Base64.getUrlDecoder().decode(signature + "==");
            
            // Create Ed25519 signature verification
            Signature ed25519Verify = Signature.getInstance("Ed25519", "BC");
            ed25519Verify.initVerify(publicKey);
            ed25519Verify.update(content);
            
            return ed25519Verify.verify(signatureBytes);
        } catch (Exception e) {
            logger.error("Ed25519 signature verification failed: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Create instance from verification method dictionary
     *
     * @param methodDict Verification method entry from DID document
     * @return Ed25519VerificationKey2018 instance
     */
    @SuppressWarnings("unchecked")
    public static Ed25519VerificationKey2018 fromDict(Map<String, Object> methodDict) {
        if (methodDict.containsKey("publicKeyJwk")) {
            return new Ed25519VerificationKey2018(
                    extractPublicKeyFromJwk((Map<String, Object>) methodDict.get("publicKeyJwk")));
        } else if (methodDict.containsKey("publicKeyMultibase")) {
            return new Ed25519VerificationKey2018(
                    extractPublicKeyFromMultibase((String) methodDict.get("publicKeyMultibase")));
        } else if (methodDict.containsKey("publicKeyBase58")) {
            return new Ed25519VerificationKey2018(
                    extractPublicKeyFromBase58((String) methodDict.get("publicKeyBase58")));
        }
        throw new IllegalArgumentException("Unsupported key format for Ed25519VerificationKey2018");
    }

    /**
     * Extract public key from JWK format
     *
     * @param jwk JWK dictionary
     * @return Ed25519 public key
     */
    private static PublicKey extractPublicKeyFromJwk(Map<String, Object> jwk) {
        try {
            if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
                throw new IllegalArgumentException("Invalid JWK parameters for Ed25519");
            }
            
            // Decode base64url x coordinate
            String xBase64 = (String) jwk.get("x");
            byte[] keyBytes = Base64.getUrlDecoder().decode(xBase64 + "==");
            
            // Create Ed25519 public key
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            logger.error("Error extracting Ed25519 public key from JWK: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract Ed25519 public key from JWK", e);
        }
    }

    /**
     * Extract public key from multibase format
     *
     * @param multibase Multibase encoded public key
     * @return Ed25519 public key
     */
    private static PublicKey extractPublicKeyFromMultibase(String multibase) {
        try {
            if (!multibase.startsWith("z")) {
                throw new IllegalArgumentException("Unsupported multibase encoding");
            }
            
            // Decode base58 (after removing the 'z' prefix)
            byte[] keyBytes = Base58.base58Decode(multibase.substring(1));
            
            // Create Ed25519 public key
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            logger.error("Error extracting Ed25519 public key from multibase: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract Ed25519 public key from multibase", e);
        }
    }

    /**
     * Extract public key from base58 format
     *
     * @param base58Key Base58 encoded public key
     * @return Ed25519 public key
     */
    private static PublicKey extractPublicKeyFromBase58(String base58Key) {
        try {
            // Decode base58
            byte[] keyBytes = Base58.base58Decode(base58Key);
            
            // Create Ed25519 public key
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", "BC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            logger.error("Error extracting Ed25519 public key from base58: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract Ed25519 public key from base58", e);
        }
    }
} 