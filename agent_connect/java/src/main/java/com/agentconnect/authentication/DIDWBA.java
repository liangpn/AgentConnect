package com.agentconnect.authentication;

import com.agentconnect.utils.CryptoTool;
import org.json.JSONObject;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.novacrypto.base58.Base58;
import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.DefaultAsyncHttpClient;
import org.asynchttpclient.Response;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The DIDWBA class provides utilities for working with Web DID Authentication.
 */
public class DIDWBA {
    private static final Logger logger = LoggerFactory.getLogger(DIDWBA.class);
    private static final ObjectMapper objectMapper = new ObjectMapper();
    
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Checks if a hostname is an IP address.
     * 
     * @param hostname the hostname to check
     * @return true if the hostname is an IP address, false otherwise
     */
    private static boolean isIpAddress(String hostname) {
        // IPv4 pattern
        String ipv4Pattern = "^(\\d{1,3}\\.){3}\\d{1,3}$";
        // IPv6 pattern (simplified)
        String ipv6Pattern = "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$";
        
        return hostname.matches(ipv4Pattern) || hostname.matches(ipv6Pattern);
    }

    /**
     * Encodes bytes data to base64url format.
     * 
     * @param data the bytes to encode
     * @return the base64url encoded string
     */
    private static String encodeBase64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Converts a secp256k1 public key to JWK format.
     * 
     * @param publicKey the public key to convert
     * @return the JWK as a map
     */
    private static Map<String, Object> publicKeyToJwk(ECPublicKey publicKey) {
        try {
            // Extract x and y coordinates
            byte[] encoded = publicKey.getEncoded();
            
            // Note: This is a simplified implementation. In a real application,
            // you would need to extract the actual x and y coordinates from the key
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(encoded);
            byte[] keyId = sha256.digest();
            
            Map<String, Object> jwk = new HashMap<>();
            jwk.put("kty", "EC");
            jwk.put("crv", "secp256k1");
            jwk.put("x", encodeBase64url(Arrays.copyOfRange(encoded, 1, 33)));
            jwk.put("y", encodeBase64url(Arrays.copyOfRange(encoded, 33, 65)));
            jwk.put("kid", encodeBase64url(keyId));
            
            return jwk;
        } catch (Exception e) {
            logger.error("Failed to convert public key to JWK: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to convert public key to JWK", e);
        }
    }

    /**
     * Creates a DID WBA document.
     * 
     * @param hostname the hostname
     * @param port the port (optional)
     * @param pathSegments the path segments (optional)
     * @param agentDescriptionUrl the agent description URL (optional)
     * @return a map containing the DID document and keys
     */
    public static Map<String, Object> createDIDWBADocument(
            String hostname,
            Integer port,
            List<String> pathSegments,
            String agentDescriptionUrl) {
        
        if (hostname == null || hostname.isEmpty()) {
            throw new IllegalArgumentException("Hostname cannot be empty");
        }
        
        if (isIpAddress(hostname)) {
            throw new IllegalArgumentException("Hostname cannot be an IP address");
        }
        
        logger.info("Creating DID WBA document for hostname: {}", hostname);
        
        // Build base DID
        String didBase = "did:wba:" + hostname;
        if (port != null) {
            String encodedPort = URLEncoder.encode(":" + port, StandardCharsets.UTF_8);
            didBase = didBase + encodedPort;
            logger.debug("Added port to DID base: {}", didBase);
        }
        
        String did = didBase;
        if (pathSegments != null && !pathSegments.isEmpty()) {
            String didPath = String.join(":", pathSegments);
            did = didBase + ":" + didPath;
            logger.debug("Added path segments to DID: {}", did);
        }
        
        try {
            // Generate secp256k1 key pair
            logger.debug("Generating secp256k1 key pair");
            Map<String, Object> keyPair = CryptoTool.generateEcKeyPair("secp256k1");
            ECPrivateKey privateKey = (ECPrivateKey) keyPair.get("privateKey");
            ECPublicKey publicKey = (ECPublicKey) keyPair.get("publicKey");
            
            // Build verification method
            Map<String, Object> verificationMethod = new HashMap<>();
            verificationMethod.put("id", did + "#key-1");
            verificationMethod.put("type", "EcdsaSecp256k1VerificationKey2019");
            verificationMethod.put("controller", did);
            verificationMethod.put("publicKeyJwk", publicKeyToJwk(publicKey));
            
            // Build DID document
            Map<String, Object> didDocument = new HashMap<>();
            didDocument.put("@context", Arrays.asList(
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/suites/jws-2020/v1",
                "https://w3id.org/security/suites/secp256k1-2019/v1"
            ));
            didDocument.put("id", did);
            didDocument.put("verificationMethod", Collections.singletonList(verificationMethod));
            didDocument.put("authentication", Collections.singletonList(verificationMethod.get("id")));
            
            // Add agent description if URL is provided
            if (agentDescriptionUrl != null) {
                Map<String, Object> service = new HashMap<>();
                service.put("id", did + "#ad");
                service.put("type", "AgentDescription");
                service.put("serviceEndpoint", agentDescriptionUrl);
                
                didDocument.put("service", Collections.singletonList(service));
            }
            
            // Build keys dictionary
            Map<String, Object> keys = new HashMap<>();
            keys.put("key-1", new Object[] {
                CryptoTool.getPemFromPrivateKey(privateKey),
                publicKey.getEncoded()
            });
            
            // Return result
            Map<String, Object> result = new HashMap<>();
            result.put("didDocument", didDocument);
            result.put("keys", keys);
            
            logger.info("Successfully created DID document with ID: {}", did);
            return result;
        } catch (Exception e) {
            logger.error("Failed to create DID WBA document: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to create DID WBA document", e);
        }
    }

    /**
     * Resolves a DID WBA document asynchronously.
     * 
     * @param did the DID to resolve
     * @return a CompletableFuture that will complete with the resolved DID document
     */
    public static CompletableFuture<Map<String, Object>> resolveDIDWBADocument(String did) {
        logger.info("Resolving DID document for: {}", did);
        
        // Validate DID format
        if (!did.startsWith("did:wba:")) {
            return CompletableFuture.failedFuture(
                new IllegalArgumentException("Invalid DID format: must start with 'did:wba:'"));
        }
        
        // Extract domain and path from DID
        String[] didParts = did.split(":", 3);
        if (didParts.length < 3) {
            return CompletableFuture.failedFuture(
                new IllegalArgumentException("Invalid DID format: missing domain"));
        }
        
        try {
            String domain = java.net.URLDecoder.decode(didParts[2], StandardCharsets.UTF_8);
            String[] pathSegments = new String[0];
            if (didParts.length > 3) {
                pathSegments = didParts[3].split(":");
            }
            
            // Create HTTP client
            AsyncHttpClient client = new DefaultAsyncHttpClient();
            
            // Create URL
            StringBuilder url = new StringBuilder();
            url.append("https://").append(domain);
            
            if (pathSegments.length > 0) {
                for (String segment : pathSegments) {
                    url.append('/').append(segment);
                }
                url.append("/did.json");
            } else {
                url.append("/.well-known/did.json");
            }
            
            logger.debug("Requesting DID document from URL: {}", url);
            
            // Send request
            return client.prepareGet(url.toString())
                .execute()
                .toCompletableFuture()
                .thenApply(response -> {
                    try {
                        if (response.getStatusCode() == 200) {
                            String body = response.getResponseBody();
                            return objectMapper.readValue(body, Map.class);
                        } else {
                            throw new RuntimeException("Failed to resolve DID document: " + 
                                response.getStatusCode() + " " + response.getResponseBody());
                        }
                    } catch (Exception e) {
                        throw new RuntimeException("Failed to parse DID document", e);
                    } finally {
                        try {
                            client.close();
                        } catch (Exception e) {
                            logger.warn("Failed to close HTTP client", e);
                        }
                    }
                });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Resolves a DID WBA document synchronously.
     * 
     * @param did the DID to resolve
     * @return the resolved DID document
     */
    public static Map<String, Object> resolveDIDWBADocumentSync(String did) {
        try {
            return resolveDIDWBADocument(did).get();
        } catch (Exception e) {
            logger.error("Failed to resolve DID document synchronously: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to resolve DID document", e);
        }
    }

    /**
     * Functional interface for signing callback
     */
    @FunctionalInterface
    public interface SignCallback {
        byte[] sign(byte[] content, String methodFragment);
    }

    /**
     * Generate authentication header for DID document.
     * 
     * @param didDocument the DID document
     * @param serviceDomain the service domain
     * @param signCallback the signing callback
     * @return the authentication header
     */
    public static String generateAuthHeader(
            Map<String, Object> didDocument,
            String serviceDomain,
            SignCallback signCallback) {
        
        try {
            logger.info("Generating auth header for DID: {} and domain: {}", 
                didDocument.get("id"), serviceDomain);
            
            // Find a suitable verification method
            Map<String, Object> verificationMethodInfo = selectAuthenticationMethod(didDocument);
            String methodFragment = (String) verificationMethodInfo.get("fragment");
            
            // Get DID
            String did = (String) didDocument.get("id");
            if( did == null|| did.isEmpty() ) {
                throw new IllegalArgumentException("DID document missing id field");
            }
            
            // Generate nonce
            String nonce = UUID.randomUUID().toString();
            
            // Get current timestamp
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            
            // Create content to sign
            String signContent = String.join(".", did, serviceDomain, nonce, timestamp);
            
            // Sign content
            byte[] signature = signCallback.sign(signContent.getBytes(StandardCharsets.UTF_8), methodFragment);
            
            // Encode signature
            String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            
            // Create auth header
            return "DID " + String.join(".", did, methodFragment, nonce, timestamp, signatureBase64);
        } catch (Exception e) {
            logger.error("Failed to generate auth header: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate auth header", e);
        }
    }

    /**
     * Find verification method in DID document.
     * 
     * @param didDocument the DID document
     * @param verificationMethodId the verification method ID
     * @return the verification method or null if not found
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> findVerificationMethod(
            Map<String, Object> didDocument, 
            String verificationMethodId) {
        
        List<Map<String, Object>> verificationMethods = 
            (List<Map<String, Object>>) didDocument.get("verificationMethod");
        
        if (verificationMethods != null) {
            for (Map<String, Object> method : verificationMethods) {
                if (verificationMethodId.equals(method.get("id"))) {
                    return method;
                }
            }
        }
        
        return null;
    }

    /**
     * Select authentication method from DID document.
     * 
     * @param didDocument the DID document
     * @return map containing the selected method and fragment
     */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> selectAuthenticationMethod(Map<String, Object> didDocument) {
        List<Object> authentications = (List<Object>) didDocument.get("authentication");
        if (authentications == null || authentications.isEmpty()) {
            throw new IllegalArgumentException("No authentication methods found in DID document");
        }
        
        // Try to find the first valid authentication method
        for (Object auth : authentications) {
            String authId;
            Map<String, Object> method;
            
            if (auth instanceof String) {
                // Reference to method
                authId = (String) auth;
                method = findVerificationMethod(didDocument, authId);
            } else if (auth instanceof Map) {
                // Embedded method
                method = (Map<String, Object>) auth;
                authId = (String) method.get("id");
                if (authId == null) {
                    throw new RuntimeException("Embedded verification method missing 'id' field");
                }
            } else {
                continue;
            }
            
            if (method != null) {
                // Extract fragment
                String methodId = (String) method.get("id");
                String fragment = methodId.substring(methodId.indexOf("#") + 1);
                
                Map<String, Object> result = new HashMap<>();
                result.put("method", method);
                result.put("fragment", fragment);
                
                return result;
            }
        }
        
        throw new IllegalArgumentException("No valid authentication methods found in DID document");
    }

    /**
     * Extract parts from an authentication header.
     * 
     * @param authHeader the authentication header
     * @return array containing [did, methodFragment, nonce, timestamp, signature]
     */
    public static String[] extractAuthHeaderParts(String authHeader) {
        try {
            // Remove "DID " prefix if present
            if (authHeader.startsWith("DID ")) {
                authHeader = authHeader.substring(4);
            }
            
            // Split by dots
            String[] parts = authHeader.split("\\.");
            if (parts.length != 5) {
                throw new IllegalArgumentException(
                    "Invalid auth header format: expected 5 parts, got " + parts.length);
            }
            
            return parts;
        } catch (Exception e) {
            logger.error("Failed to extract auth header parts: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to extract auth header parts", e);
        }
    }

    /**
     * Verify authentication header signature.
     * 
     * @param authHeader the authentication header
     * @param didDocument the DID document
     * @param serviceDomain the service domain
     * @return map containing verification result (success/error)
     */
    public static Map<String, Object> verifyAuthHeaderSignature(
            String authHeader, 
            Map<String, Object> didDocument,
            String serviceDomain) {
        
        try {
            // Extract parts
            String[] parts = extractAuthHeaderParts(authHeader);
            String did = parts[0];
            String methodFragment = parts[1];
            String nonce = parts[2];
            String timestamp = parts[3];
            String signature = parts[4];
            
            // Validate DID
            if (!did.equals(didDocument.get("id"))) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", "DID in auth header doesn't match DID document");
                return result;
            }
            
            // Build verification method ID
            String verificationMethodId = did + "#" + methodFragment;
            
            // Find verification method
            Map<String, Object> verificationMethod = findVerificationMethod(didDocument, verificationMethodId);
            if (verificationMethod == null) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", "Verification method not found: " + verificationMethodId);
                return result;
            }
            
            // Create verification method instance
            VerificationMethod verifier = VerificationMethod.createVerificationMethod(verificationMethod);
            
            // Create content to verify
            String verifyContent = String.join(".", did, serviceDomain, nonce, timestamp);
            
            // Verify signature
            boolean isValid = verifier.verifySignature(
                verifyContent.getBytes(StandardCharsets.UTF_8), signature);
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", isValid);
            result.put("error", isValid ? "" : "Invalid signature");
            
            return result;
        } catch (Exception e) {
            logger.error("Failed to verify auth header signature: {}", e.getMessage(), e);
            Map<String, Object> result = new HashMap<>();
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        }
    }

    /**
     * Generate authentication JSON.
     * 
     * @param didDocument the DID document
     * @param serviceDomain the service domain
     * @param signCallback the signing callback
     * @return the authentication JSON string
     */
    public static String generateAuthJson(
            Map<String, Object> didDocument,
            String serviceDomain,
            SignCallback signCallback) {
        
        try {
            logger.info("Generating auth JSON for DID: {} and domain: {}", 
                didDocument.get("id"), serviceDomain);
            
            // Find a suitable verification method
            Map<String, Object> verificationMethodInfo = selectAuthenticationMethod(didDocument);
            String methodFragment = (String) verificationMethodInfo.get("fragment");
            
            // Get DID
            String did = (String) didDocument.get("id");
            
            // Generate nonce
            String nonce = UUID.randomUUID().toString();
            
            // Get current timestamp
            String timestamp = String.valueOf(Instant.now().getEpochSecond());
            
            // Create auth JSON
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode authJson = mapper.createObjectNode();
            
            authJson.put("did", did);
            authJson.put("domain", serviceDomain);
            authJson.put("nonce", nonce);
            authJson.put("timestamp", timestamp);
            
            // Create canonicalized JSON (simplified implementation)
            byte[] canonicalizedBytes = canonicalizeJson(authJson).getBytes(StandardCharsets.UTF_8);
            
            // Sign content
            byte[] signature = signCallback.sign(canonicalizedBytes, methodFragment);
            
            // Encode signature
            String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
            
            // Add signature and method
            authJson.put("signature", signatureBase64);
            authJson.put("method", methodFragment);
            
            // Return JSON string
            return mapper.writeValueAsString(authJson);
        } catch (Exception e) {
            logger.error("Failed to generate auth JSON: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate auth JSON", e);
        }
    }

    /**
     * Verify authentication JSON signature.
     * 
     * @param authJson the authentication JSON
     * @param didDocument the DID document
     * @param serviceDomain the service domain
     * @return map containing verification result (success/error)
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyAuthJsonSignature(
            Object authJson,
            Map<String, Object> didDocument,
            String serviceDomain) {
        
        try {
            Map<String, Object> authMap;
            if (authJson instanceof String) {
                // Parse JSON string
                authMap = objectMapper.readValue((String) authJson, Map.class);
            } else if (authJson instanceof Map) {
                // Already a map
                authMap = (Map<String, Object>) authJson;
            } else {
                throw new IllegalArgumentException("authJson must be a string or a map");
            }
            
            // Extract values
            String did = (String) authMap.get("did");
            String domain = (String) authMap.get("domain");
            String nonce = (String) authMap.get("nonce");
            String timestamp = (String) authMap.get("timestamp");
            String signature = (String) authMap.get("signature");
            String methodFragment = (String) authMap.get("method");
            
            // Validate DID
            if (!did.equals(didDocument.get("id"))) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", "DID in auth JSON doesn't match DID document");
                return result;
            }
            
            // Validate domain
            if (!domain.equals(serviceDomain)) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", "Domain in auth JSON doesn't match service domain");
                return result;
            }
            
            // Build verification method ID
            String verificationMethodId = did + "#" + methodFragment;
            
            // Find verification method
            Map<String, Object> verificationMethod = findVerificationMethod(didDocument, verificationMethodId);
            if (verificationMethod == null) {
                Map<String, Object> result = new HashMap<>();
                result.put("success", false);
                result.put("error", "Verification method not found: " + verificationMethodId);
                return result;
            }
            
            // Create verification method instance
            VerificationMethod verifier = VerificationMethod.createVerificationMethod(verificationMethod);
            
            // Create content to verify
            Map<String, Object> verifyContent = new HashMap<>();
            verifyContent.put("did", did);
            verifyContent.put("domain", domain);
            verifyContent.put("nonce", nonce);
            verifyContent.put("timestamp", timestamp);
            
            // Create canonicalized JSON (simplified implementation)
            byte[] canonicalizedBytes = canonicalizeJson(verifyContent).getBytes(StandardCharsets.UTF_8);
            
            // Verify signature
            boolean isValid = verifier.verifySignature(canonicalizedBytes, signature);
            
            Map<String, Object> result = new HashMap<>();
            result.put("success", isValid);
            result.put("error", isValid ? "" : "Invalid signature");
            
            return result;
        } catch (Exception e) {
            logger.error("Failed to verify auth JSON signature: {}", e.getMessage(), e);
            Map<String, Object> result = new HashMap<>();
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        }
    }

    /**
     * Simple JSON canonicalization function.
     * This is a simplified implementation that sorts keys alphabetically.
     * 
     * @param object Object to canonicalize
     * @return Canonicalized JSON string
     */
    @SuppressWarnings("unchecked")
    private static String canonicalizeJson(Object object) {
        try {
            if (object instanceof Map) {
                Map<String, Object> map = (Map<String, Object>) object;
                JSONObject jsonObject = new JSONObject();
                
                // Get keys and sort them
                List<String> keys = new ArrayList<>(map.keySet());
                Collections.sort(keys);
                
                // Add keys in sorted order
                for (String key : keys) {
                    Object value = map.get(key);
                    if (value instanceof Map || value instanceof List) {
                        jsonObject.put(key, new JSONObject(canonicalizeJson(value)));
                    } else {
                        jsonObject.put(key, value);
                    }
                }
                
                return jsonObject.toString();
            } else if (object instanceof List) {
                List<Object> list = (List<Object>) object;
                StringBuilder result = new StringBuilder("[");
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) {
                        result.append(",");
                    }
                    Object value = list.get(i);
                    if (value instanceof Map || value instanceof List) {
                        result.append(canonicalizeJson(value));
                    } else {
                        result.append(new JSONObject().put("value", value).get("value"));
                    }
                }
                result.append("]");
                return result.toString();
            } else {
                return new ObjectMapper().writeValueAsString(object);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to canonicalize JSON", e);
        }
    }
} 