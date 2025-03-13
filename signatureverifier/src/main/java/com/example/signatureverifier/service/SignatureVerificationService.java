package com.example.signatureverifier.service;

import com.example.signatureverifier.model.SignaturePayload;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Service
public class SignatureVerificationService {

    private final PublicKey publicKey;
    private final ObjectMapper objectMapper;

    public SignatureVerificationService(@Value("classpath:public_key.pem") Resource publicKeyResource,
            ObjectMapper objectMapper) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.objectMapper = objectMapper;
        String publicKeyContent = new String(publicKeyResource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

        // Remove PEM headers and decode
        String publicKeyPEM = publicKeyContent
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));

        System.out.println("Java - Public key loaded: " + publicKey.getAlgorithm() + " " + publicKey.getFormat());
    }

    public boolean verifySignature(SignaturePayload payload) {
        try {
            Map<String, Object> content = payload.getContent();
            String signatureBase64 = payload.getSignature();

            // IMPORTANT: Sort the keys to ensure consistent ordering
            String jsonString = objectMapper.writer().withDefaultPrettyPrinter()
                    .withFeatures(com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                    .writeValueAsString(content);

            // Remove all whitespace (pretty print adds spaces)
            jsonString = objectMapper.writeValueAsString(
                    objectMapper.readValue(jsonString, Map.class));

            byte[] jsonBytes = jsonString.getBytes(StandardCharsets.UTF_8);

            System.out.println("Java - Content being verified (as string): " + jsonString);
            System.out.println("Java - Content being verified (as bytes): " + bytesToString(jsonBytes));
            System.out.println("Java - Content being verified (hex): " + bytesToHex(jsonBytes));

            // The SHA-256 hash that will be verified
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(jsonBytes);
            System.out.println("Java - SHA-256 digest of content (hex): " + bytesToHex(hashBytes));

            // Decode the signature
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            System.out.println("Java - Received signature (hex): " + bytesToHex(signatureBytes));
            System.out.println("Java - Received signature length: " + signatureBytes.length + " bytes");

            // Try different salt lengths
            for (int saltLength : new int[] { 20, 32, 0, 64, 128, 190, 222, 254, 255 }) {
                try {
                    // Initialize signature verification with explicit PSS parameters
                    Signature signature = Signature.getInstance("RSASSA-PSS");

                    // Set up the PSS parameters
                    PSSParameterSpec pssParams = new PSSParameterSpec(
                            "SHA-256",
                            "MGF1",
                            MGF1ParameterSpec.SHA256,
                            saltLength,
                            1 // trailer field (standard value)
                    );

                    signature.setParameter(pssParams);
                    signature.initVerify(publicKey);
                    signature.update(jsonBytes);

                    // Verify the signature
                    boolean result = signature.verify(signatureBytes);
                    System.out.println("Java - Verification result with salt length " + saltLength + ": " + result);

                    if (result) {
                        System.out.println("Java - SUCCESSFUL VERIFICATION with salt length: " + saltLength);
                        return true;
                    }
                } catch (Exception e) {
                    System.out.println("Java - Error with salt length " + saltLength + ": " + e.getMessage());
                }
            }

            System.out.println("Java - All verification attempts failed");
            return false;

        } catch (Exception e) {
            System.out.println("Java - Exception during verification: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private static String bytesToString(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}