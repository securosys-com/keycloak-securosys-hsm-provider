/**
 * Copyright (c)2025 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p>
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 **/
package com.securosys.hsm.util;

import com.securosys.hsm.dto.ModifyPolicyDto;
import com.securosys.hsm.dto.SignatureDto;
import com.securosys.hsm.enums.CipherAlgorithm;
import com.securosys.hsm.enums.HsmRequestType;
import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;
import com.securosys.hsm.exception.TechnicalException;
import com.securosys.hsm.exception.TechnicalReason;
import com.securosys.primus.jce.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.MessageDigestAlgorithms;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * This class offers various helper methods for using crypto operations in Java. Generally this class should only offer methods
 * that are not specific to the JCE. But it may offer methods that uses JCE specific objects like a BLS public key which is
 * a public key object. In this case the method does not separate the different public keys but works for all public keys in
 * general.
 */
public class CryptoUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(CryptoUtil.class);

    private static final String RNG_ALGORITHM = "SHA1PRNG";

    private static final String X509_CERTIFICATE_TYPE = "X.509";

    private CryptoUtil() {

    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
    public static String getHashAlgorithm(String hash){
        String[] parts=hash.split(":",2);
        if(parts.length==1){
            return MessageDigestAlgorithms.SHA_256;
        }else{
            switch(parts[0].toLowerCase()){
                case "sha224":
                    return MessageDigestAlgorithms.SHA_224;
                case "sha256":
                    return MessageDigestAlgorithms.SHA_256;
                case "sha1":
                    return MessageDigestAlgorithms.SHA_1;
                case "sha384":
                    return MessageDigestAlgorithms.SHA_384;
                case "sha512":
                    return MessageDigestAlgorithms.SHA_512;
                case "md5":
                    return MessageDigestAlgorithms.MD5;
                case "md2":
                    return MessageDigestAlgorithms.MD2;
                case "sha3224":
                    return MessageDigestAlgorithms.SHA3_224;
                case "sha3256":
                    return MessageDigestAlgorithms.SHA3_256;
                case "sha3384":
                    return MessageDigestAlgorithms.SHA3_384;
                case "sha3512":
                    return MessageDigestAlgorithms.SHA3_512;
            }
        }
        return "SHA-256";
    }
    public static String getHash(String hash){
        String[] parts=hash.split(":",2);
        if(parts.length==1){
            return parts[0];
        }else {
            return parts[1];
        }
    }
    public static String calcFileSHA256(File file){
        return CryptoUtil.calcFileFingerprint(file,"SHA-256");
    }
    public static String calcFileFingerprint(File file, String algorithm) {
        try (InputStream fis = new FileInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[8192]; // Read in 8KB chunks
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }

            return bytesToHex(digest.digest());
        } catch (Exception e) {
            throw new RuntimeException("Error computing "+algorithm+" hash", e);
        }
    }


    public static String calcSHA256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(input);
            return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    public static String encodeBase64(byte[] input) {
        return Base64.getEncoder().encodeToString(input);
    }

    public static String encodeBase64(String input) {
        byte[] utf8Bytes = null;
        try {
                utf8Bytes = input.getBytes("ISO_8859_1");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return Base64.getEncoder().encodeToString(utf8Bytes);
    }
    public static boolean isBase64String(String input){
        if (input == null || input.trim().isEmpty()) return false;
        try {
            // Decode and re-encode to verify integrity
            byte[] decoded = Base64.getDecoder().decode(input);
            String encoded = Base64.getEncoder().encodeToString(decoded);
            return encoded.equals(input.replaceAll("\\s+", ""));
        } catch (IllegalArgumentException e) {
            return false; // Not Base64
        }
    }

    public static byte[] decodeBase64(String input) {
        return Base64.getDecoder().decode(input);
    }

    /**
     * Returns the public key from a base64 encoded certificate (in DER format)
     */
    public static PublicKey getPublicKeyFromBase64Certificate(String base64EncodedCertificate) {
        LOGGER.debug("Going to parse and extract public key from certificate: {}", base64EncodedCertificate);
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
            Certificate certificate =
                    certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64EncodedCertificate)));
            PublicKey publicKey = certificate.getPublicKey();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PublicKey is: '{}'", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
            }
            return publicKey;
        } catch (CertificateException e) {
            throw new BusinessException("Could not create certificate from base64-string='" + base64EncodedCertificate + "'",
                    BusinessReason.ERROR_INPUT_VALIDATION_FAILED, e);
        }
    }

    /**
     * Generates an approval token and returns it base64 encoded.
     */
    public static String getApprovalToBeSignedBase64Encoded(String base64EncodedTimestamp,
                                                            String base64EncodedTimestampSignature,
                                                            String base64EncodedPayload,
                                                            String keyName,
                                                            HsmRequestType requestType,
                                                            String timestampSignatureAlgorithm
    ) {
        PrimusSignature
                timestampSignature =
                new PrimusSignature(Base64.getDecoder().decode(base64EncodedTimestampSignature), timestampSignatureAlgorithm);

        int operation;

        switch (requestType) {
            case SIGN:
            case CSRSIGN:
            case CRTSIGN:
            case SELFSIGN:
                operation = PrimusApprovalToken.OPERATION_SIGN;
                break;

            case BLOCK:
                operation = PrimusApprovalToken.OPERATION_BLOCK;
                break;

            case UNBLOCK:
                operation = PrimusApprovalToken.OPERATION_UNBLOCK;
                break;

            case MODIFY:
                operation = PrimusApprovalToken.OPERATION_MODIFY;
                break;

            default:
                operation = PrimusApprovalToken.OPERATION_OPERATION;
                break;
        }
        byte[] payload = base64EncodedPayload != null ? Base64.getDecoder().decode(base64EncodedPayload) : null;
        PrimusApprovalToken approvalToken = new PrimusApprovalToken(operation,
                payload,
                keyName,
                Base64.getDecoder().decode(base64EncodedTimestamp),
                timestampSignature);

        return Base64.getEncoder().encodeToString(approvalToken.getEncoding());
    }



    public static String getKeyTypeForCipherAlgorithm(CipherAlgorithm cipherAlgorithm) {
        switch (cipherAlgorithm) {
            case RSA_PADDING_OAEP_WITH_SHA512:
            case RSA:
            case RSA_PADDING_OAEP_WITH_SHA224:
            case RSA_PADDING_OAEP_WITH_SHA256:
            case RSA_PADDING_OAEP_WITH_SHA1:
            case RSA_PADDING_OAEP:
            case RSA_PADDING_OAEP_WITH_SHA384:
            case RSA_NO_PADDING:
                return "RSA";
            case AES_GCM:
            case AES_CTR:
            case AES_ECB:
            case AES_CBC_NO_PADDING:
            case AES:
                return "AES";
            case CHACHA20:
            case CHACHA20_AEAD:
                return "ChaCha20";
            case CAMELLIA:
            case CAMELLIA_CBC_NO_PADDING:
            case CAMELLIA_ECB:
                return "Camellia";
            case TDEA_CBC:
            case TDEA_CBC_NO_PADDING:
            case TDEA_ECB:
                return "TDEA";
            default:
                return "NOT_SUPPORTED";
        }
    }

    private static byte[] convertPublicKeyStringToBytes(String publicKey){
        String publicKeyPEM = publicKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", ""); // remove whitespace/newlines

        // Decode Base64
        return Base64.getDecoder().decode(publicKeyPEM);
    }


    private static String getSignatureAlgorithmFromDigestAlgorithm(String digestAlgorithm, PrivateKey privateKey) {
        String signatureAlgorithm;
        switch (privateKey.getAlgorithm()) {
            case "RSA":
                signatureAlgorithm = "RSA";
                break;
            case "DSA":
                signatureAlgorithm = "DSA";
                break;
            case "EC":
                signatureAlgorithm = "ECDSA";
                break;
            default:
                throw new BusinessException("Cannot determine signature algorithm based on the algorithm defined "
                        + "for the provided public key'" + privateKey.getAlgorithm() + "'",
                        BusinessReason.ERROR_IMPLEMENTATION);
        }
        return digestAlgorithm.replace("SHA-", "SHA") + "with" + signatureAlgorithm;
    }

    private static String getSignatureAlgorithmFromDigestAlgorithm(String digestAlgorithm, PublicKey publicKey) {
        String signatureAlgorithm;
        switch (publicKey.getAlgorithm()) {
            case "RSA":
                signatureAlgorithm = "RSA";
                break;
            case "DSA":
                signatureAlgorithm = "DSA";
                break;
            case "EC":
                signatureAlgorithm = "ECDSA";
                break;
            default:
                throw new BusinessException("Cannot determine signature algorithm based on the algorithm defined "
                        + "for the provided public key'" + publicKey.getAlgorithm() + "'",
                        BusinessReason.ERROR_IMPLEMENTATION);
        }
        return digestAlgorithm.replace("SHA-", "SHA") + "with" + signatureAlgorithm;
    }

    public static Certificate getCertificateFromBase64(String base64EncodedCertificate) {
        CertificateFactory fact;
        try {
            fact = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
            byte[] decodedCertificate = Base64.getDecoder().decode(base64EncodedCertificate);
            //String sanitizedCertificateString = new String(decodedCertificate).replace("\n", "");
            return fact.generateCertificate(new ByteArrayInputStream(decodedCertificate));
        } catch (CertificateException e) {
            LOGGER.debug("Problem converting base64 certificate:", e);
            throw new BusinessException("Could not read certificate.", BusinessReason.ERROR_INVALID_CERTIFICATE);
        }
    }

    public static Certificate getCertificateFromString(String certificateString) {
        CertificateFactory fact;
        try {
            fact = CertificateFactory.getInstance(X509_CERTIFICATE_TYPE);
            return fact.generateCertificate(new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8)));
        } catch (CertificateException e) {
            LOGGER.debug("Problem converting base64 certificate:", e);
            throw new BusinessException("Could not read certificate.", BusinessReason.ERROR_INVALID_CERTIFICATE);
        }
    }




    public static String getAlgorithmForOid(String algOid) {
        String alg = null;
        if (algOid == null) {
            return null;
        } else if (algOid.startsWith("1.2.840.113549.1.1")) {
            // this is RSA, but the OID is not used as a key factory id, so we have to map
            alg = "RSA";
        } else if (algOid.startsWith("1.2.840.10045.2.1")) {
            // this is EC
            alg = "EC";
        } else if (algOid.startsWith("1.2.840.10040.4.1")) {
            // DSA
            alg = "DSA";
        } else if (algOid.equals("1.0.18033.3.2.1")) {
            alg = "AES";
        } else if (algOid.equals("1.0.18033.3.2.2")) {
            alg = "Camellia";
        } else if (algOid.equals("1.2.840.113549.1.9.16.3.18")) {
            alg = "ChaCha20";
        } else if (algOid.equals("1.0.18033.3.1.1")) {
            alg = "TDEA";
        } else if (algOid.equals("1.3.6.1.4.1.44668.5.3.1.1")) {
            alg = "BLS";
        }
        return alg;
    }

    public static String hashPublicKey(String publicKey) {
        return DigestUtils.sha256Hex(publicKey);
    }


     public static String getTimestampSignatureWithAlgorithm(String timestampBase64, String timestampSignatureAlgorithm) {
        return Base64.getEncoder().encodeToString(
                new PrimusSignature(
                        Base64.getDecoder().decode(timestampBase64),
                        timestampSignatureAlgorithm
                ).getEncodingWithSignAlgorithm()
        );
    }

    /**
     * Generate a cryptographically secure random number
     * @param length The length of the number
     * @return The random number
     */
    public static byte[] generateRandomNumber(int length) {
        try {
            SecureRandom rand = SecureRandom.getInstance(RNG_ALGORITHM);
            byte[] randomNumber = new byte[length];
            rand.nextBytes(randomNumber);
            return randomNumber;
        } catch (NoSuchAlgorithmException e) {
            throw new TechnicalException("Could not generate random number", TechnicalReason.ERROR_TECHNICAL, e);
        }
    }


    /**
     * Loads the RSA public key from a X509 certificate
     * @param certificate the X509 certificate to load the public key from
     * @return the RSA public key
     */
    public static RSAPublicKey loadRsaPublicKeyFromX509Certificate(X509Certificate certificate) {
        if (certificate.getPublicKey() instanceof RSAPublicKey) {
            return (RSAPublicKey) certificate.getPublicKey();
        }
        throw new BusinessException("Could not load public key from x509 certificate", BusinessReason.ERROR_PARSING_KEY);
    }



    /**
     * Loads the PEM content from a certificate file. The PEM content is a single line string without the BEGIN CERTIFICATE and
     * END CERTIFICATE.
     * @param certificate
     * @return
     */
    public static String retrievePemContentFromCertificateFile(File certificate) {
        try {
            String certificateContent = Files.readString(certificate.toPath(), StandardCharsets.UTF_8);
            return certificateContent.replaceAll("\n", "")
                    .replaceFirst("-----BEGIN CERTIFICATE-----", "")
                    .replaceFirst("-----END CERTIFICATE-----", "");
        } catch (IOException e) {
            String msg = String.format("Could not load certificate '%s'", certificate.getName());
            throw new BusinessException(msg, BusinessReason.ERROR_INVALID_CONFIG_INPUT, e);
        }
    }

    /**
     * Creates a secret key from an byte representation of a key.
     * @param secretKeyBytes The byte representation of a secret key
     * @param algorithm The algorithm of the key
     * @return A SecretKey object created from the byte representation
     */
    public static SecretKey parseSecretKey(byte[] secretKeyBytes, String algorithm) {
        return new SecretKeySpec(secretKeyBytes, algorithm);
    }

    public static String computeFingerprint(Certificate cert) {
        try {
            return DigestUtils.sha1Hex(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new BusinessException("Could not compute fingerprint for certificate",
                    BusinessReason.ERROR_PARSING_CERTIFICATE, e);
        }
    }
    public static PublicKey loadPublicKey(String publicKeyPEM) throws Exception {
        // Remove the first and last lines (PEM header/footer)
        publicKeyPEM = publicKeyPEM.replaceAll("-----BEGIN PUBLIC KEY-----", "").replaceAll("-----END PUBLIC KEY-----", "").replaceAll("\n", "").replaceAll("\r", "");

        // Decode the Base64-encoded string
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

        // Create a KeyFactory and generate a PublicKey
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        String[] algorithms = { "RSA", "EC", "Ed25519", "Ed448" };

        for (String alg : algorithms) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(alg);
                return keyFactory.generatePublic(keySpec);
            } catch (Exception e) {
                // Try next algorithm
            }
        }

        throw new IllegalArgumentException("Unsupported key type or format");
    }
    public static X509Certificate loadCertificate(String certPathOrContent) throws Exception {
        byte[] certBytes;

        File f = new File(certPathOrContent);
        if (f.exists()) {
            // Read file bytes
            certBytes = Files.readAllBytes(f.toPath());
        } else {
            // Treat input as direct string
            certBytes = certPathOrContent.getBytes();
        }

        String certStr = new String(certBytes).trim();
        if (certStr.contains("-----BEGIN CERTIFICATE-----")) {
            // PEM format, remove headers and decode base64
            certStr = certStr
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s+", "");
            certBytes = Base64.getDecoder().decode(certStr);
        }

        try (ByteArrayInputStream bis = new ByteArrayInputStream(certBytes)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(bis);
        }
    }

    public static PublicKey loadPublicKeyFromCertificate(String certPem) throws Exception {
        // Clean up PEM string
        certPem = certPem.replaceAll("-----BEGIN CERTIFICATE-----", "")
                .replaceAll("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", ""); // Remove all whitespace

        // Decode Base64 to DER
        byte[] certBytes = Base64.getDecoder().decode(certPem);

        // Create certificate
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate)
                certFactory.generateCertificate(new ByteArrayInputStream(certBytes));

        // Extract public key
        return certificate.getPublicKey();
    }
    public static PrivateKey loadPrivateKey(String privateKeyPEM) throws Exception {
        // Clean up PEM headers/footers
        String cleanedPem = privateKeyPEM
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(cleanedPem);

        // Parse key spec
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);

        // Try common algorithms
        for (String algorithm : new String[]{"RSA", "EC", "Ed25519", "Ed448"}) {
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                return keyFactory.generatePrivate(keySpec);
            } catch (Exception e) {
                // Try next
            }
        }

        throw new IllegalArgumentException("Unsupported key algorithm or invalid key format.");
    }

}
