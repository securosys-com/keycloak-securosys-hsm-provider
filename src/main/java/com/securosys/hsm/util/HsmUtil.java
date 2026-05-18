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

import com.securosys.hsm.dto.*;
import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;
import com.securosys.primus.jce.*;
import com.securosys.primus.jce.spec.EdPrivateKeyImpl;
import com.securosys.primus.jce.spec.EdPublicKeyImpl;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This class offers helper methods for HSM specific operations. This includes all methods that depend on features offered by
 * the JCE. Additionally, this also includes methods that only make sense in conjunction with the JCE like crafting a specific
 * input for a JCE method.
 */
public class HsmUtil {

    private static final String BIP32_PATH_SEPARATOR = "/";

    private static final Logger LOGGER = LoggerFactory.getLogger(HsmUtil.class);

    private HsmUtil() {
    }

    public static OffsetDateTime getDateFromTimestamp(byte[] timestamp) {
        final PrimusTimestamp primusTimestamp = new PrimusTimestamp(timestamp);
        return OffsetDateTime.ofInstant(Instant.ofEpochSecond(primusTimestamp.getSecondsSinceEpoch()), ZoneId.systemDefault());
    }

    public static boolean isSkaKey(String keyName) {
        String[][] keyType = PrimusKeyTypes.getKeyTypes(keyName);
        for (int i = 0; i < keyType.length; i++) {
            for (int j = 0; j < keyType[i].length; j++) {
                if (keyType[i][j].startsWith("Eka")) {
                    return true;
                }
            }
        }

        return false;
    }


    /**
     * Get key types for an alias.
     *      *
     *      * Returns an array of which each entry corresponds to a HSM object.
     *      * Such entries represent pairs of object type (e.g. "PrivateKey", "PublicKey", "Certificate") and algorithm type (e.g. "DSA").
     *      * If there is no such alias, an empty list will be returned.
     *      *
     *      * Known key types:
     *      * PrivateKey, PublicKey, SecretKey, Certificate, DataObject, EkaPrivateKey, RksPrivateKey.
     *      *
     *      * Known algorithm types:
     *      * RSA, DSA, DH, DHX942, EC, ED25519, ECCKD, ISS, BLS,
     *      * RSAEKA, DSAEKA, ECEKA, ED25519EKA, ECCKDEKA, ISSEKA, BLSEKA,
     *      * RSARKS, ECRKS,
     *      * AES, CAMELLIA, TDEA, CHACHA20, POLY1305,
     *      * HMACSHA1, HMACSHA224, HMACSHA256, HMACSHA384, HMACSHA512, HMACSHA3224, HMACSHA3256, HMACSHA3384, HMACSHA3512,
     *      * UNSPECIFIED
     */
    public static String getKeyTypeAlgorithm(String keyName) {
        String[][] keyType = PrimusKeyTypes.getKeyTypes(keyName);
        for (int i = 0; i < keyType.length; i++) {
            if (keyType[i][0].equals("SecretKey") || keyType[i][0].equals("PrivateKey") || keyType[i][0].equals("EkaPrivateKey") || keyType[i][0].equals("RksPrivateKey"))
                return keyType[i][1];
        }

        return null;
    }

    public static int mapCryptoCurrency(String cryptoCurrencyFormat) {
        switch (cryptoCurrencyFormat) {
            case "BTC":
                return PrimusCryptoCurrencies.BITCOIN;
            case "ETH":
                return PrimusCryptoCurrencies.ETHEREUM;
            case "XLM":
                return PrimusCryptoCurrencies.STELLAR;
            case "XRP":
                return PrimusCryptoCurrencies.RIPPLE;
            case "IOTA":
                return PrimusCryptoCurrencies.IOTA;
            default:
                throw new BusinessException("Cryptocurrency '" + cryptoCurrencyFormat + "' is not supported",
                        BusinessReason.ERROR_UNSUPPORTED_CRYPTOCURRENCY);
        }
    }

    public static boolean containsBIP32Path(String keyName) {
        return keyName.contains(BIP32_PATH_SEPARATOR);
    }

    /**
     * Returns the master key name part of a BIP32 keyname incl. derivation path. Throws exception if the master key name
     * portion is empty.
     * @param keyNameWithPath a BIP32 keyname concatenated with derivation path (e.g. mykey/0'/1)
     * @return the master key name (e.g. mykey)
     */
    public static String getBIP32MasterKeyName(String keyNameWithPath) {
        String masterKeyName = StringUtils.substringBefore(keyNameWithPath, BIP32_PATH_SEPARATOR);
        if (masterKeyName == null || masterKeyName.isBlank() || !keyNameWithPath.contains(BIP32_PATH_SEPARATOR)) {
            throw new BusinessException("BIP32 key name '" + keyNameWithPath + "' does not contain master key name and path",
                    BusinessReason.ERROR_INVALID_KEY_NAME);
        } else {
            return masterKeyName;
        }
    }

    /**
     * Returns the derivation path part of a BIP32 keyname incl. derivation path. Throws exception if the derivation path
     * portion is empty.
     * @param keyNameWithPath a BIP32 keyname concatenated with derivation path (e.g. mykey/0'/1)
     * @return the master key name (e.g. 0'/1)
     */
    public static String getBIP32DerivationPath(String keyNameWithPath) {
        String derivationPath = StringUtils.substringAfter(keyNameWithPath, BIP32_PATH_SEPARATOR);
        if (derivationPath == null || derivationPath.isBlank()) {
            throw new BusinessException("BIP32 key name '" + keyNameWithPath + "' does not contain master key name and path",
                    BusinessReason.ERROR_INVALID_KEY_NAME);
        } else {
            return derivationPath;
        }
    }


    public static boolean isSkaKey(KeyAttributesDto keyAttributes) {
        return isPolicySet(keyAttributes.getPolicy());
    }

    public static boolean isSkaKey(CreateKeyDto createKeyRequest) {
        return isPolicySet(createKeyRequest.getPolicy());
    }


    private static boolean isPolicySet(PolicyDto policy) {
        return policy != null;
    }

    public static boolean isAsymmetricAlgorithm(String algorithm) {
        // search for the KeyPairGenerator services to figure out what types of keys can be generated.
        Provider primusProvider = new PrimusProvider();
        List<Provider.Service> keyPairGeneratorServices = getProviderServices(primusProvider, "KeyPairGenerator");

        // now collect all asymmetric key algorithms in a list
        Set<String> primusKeyPairGeneratorAlgorithms =
                keyPairGeneratorServices.stream()
                        .map(Provider.Service::getAlgorithm)
                        .filter(algo -> !algo.equals("DH")) //DH is not supported for SKA keys
                        .collect(Collectors.toCollection(HashSet::new));

        //ED is not explicitly listed in the Provider Services. The reason for that probably is that it is created with setting
        // the algorithm to EC. This is why we have to explicitly allow ED here.
        primusKeyPairGeneratorAlgorithms.add("ED");

        // PQC Algorithm's do not have defined algOID's that's why we map all to the primus-kpg.
        getDelithiumParameterSpec().keySet().forEach(x -> primusKeyPairGeneratorAlgorithms.add(x));
        getSphincsPlusParameterSpec().keySet().forEach(x -> primusKeyPairGeneratorAlgorithms.add(x));
        getKyberParameterSpec().keySet().forEach(x -> primusKeyPairGeneratorAlgorithms.add(x));

        LOGGER.debug("Supported Algorithms: {}", primusKeyPairGeneratorAlgorithms);

        return primusKeyPairGeneratorAlgorithms.contains(algorithm);
    }

    public static boolean isSymmetricAlgorithm(String algorithm) {
        // search for the KeyGenerator services to figure out what types of keys can be generated.
        Provider primusProvider = new PrimusProvider();
        List<Provider.Service> keyGeneratorServices = getProviderServices(primusProvider, "KeyGenerator");

        // now collect all symmetric key algorithms in a list
        Set<String> primusKeyGeneratorAlgorithms =
                keyGeneratorServices.stream()
                        .map(Provider.Service::getAlgorithm)
                        //MAC algorithms are not supported for now
                        .filter(algo -> !algo.equals("Poly1305") && !algo.startsWith("HMAC"))
                        .collect(Collectors.toCollection(HashSet::new));
        LOGGER.debug("Supported Algorithms: {}", primusKeyGeneratorAlgorithms);

        return primusKeyGeneratorAlgorithms.contains(algorithm);
    }

    public static void checkPolicyAttachedToSymmetricKey(String algorithm) {
        if (HsmUtil.isSymmetricAlgorithm(algorithm)) {
            LOGGER.warn("Create symmetric key request received with key policy, this is not allowed. " +
                    "The policy is ignored and the request is processed.");
        }
    }

    private static List<Provider.Service> getProviderServices(Provider provider, String serviceName) {
        List<Provider.Service> services =
                provider.getServices().stream()
                        .filter(x -> x.getType().equals(serviceName)).collect(Collectors.toList());
        services.forEach(x -> LOGGER.debug("KeyGeneratorService: {}", x));
        return services;
    }

    public static String getEcCurveNameForOID(String oid) {
        Map<String, String> curves = getSupportedEcCurves();
        curves.putAll(getSupportedEdCurves());
        LOGGER.debug("looking for curve name for oid: '{}'", oid);
        String curve = curves.get(oid);
        LOGGER.debug("curve for '{}' is '{}'", oid, curve);
        return curve;
    }

    public static Map<String, String> getDelithiumParameterSpec() {
        Map<String, String> map = new HashMap<>();
        map.put("DILITHIUM_L2", "dilithiumMode4x4r3");
        map.put("DILITHIUM_L3", "dilithiumMode6x5r3");
        map.put("DILITHIUM_L5", "dilithiumMode8x7r3");
        return map;
    }

    public static Map<String, String> getSphincsPlusParameterSpec() {
        Map<String, String> map = new HashMap<>();
        map.put("SPHINCS_PLUS_SHAKE_L1", "sphincsPlusMode128ShakeFastr3");
        map.put("SPHINCS_PLUS_SHAKE_L3", "sphincsPlusMode192ShakeFastr3");
        map.put("SPHINCS_PLUS_SHAKE_L5", "sphincsPlusMode256ShakeFastr3");
        return map;
    }

    public static Map<String, String> getKyberParameterSpec() {
        Map<String, String> map = new HashMap<>();
        map.put("KYBER512_WITH_SHAKE", "KyberMode512r3");
        map.put("KYBER768_WITH_SHAKE", "KyberMode768r3");
        map.put("KYBER1024_WITH_SHAKE", "KyberMode1024r3");
        map.put("KYBER512_WITH_SHA2_AES", "KyberMode90s512r3");
        map.put("KYBER768_WITH_SHA2_AES", "KyberMode90s768r3");
        map.put("KYBER1024_WITH_SHA2_AES", "KyberMode90s1024r3");
        return map;
    }

    public static String getPqcSignAlgorithm(String keyAlgorithm) {
        Map<String, String> map = new HashMap<>();
        map.put("Kyber-512-r3", "Kyber");
        map.put("Kyber-768-r3", "Kyber");
        map.put("Kyber-1024-r3", "Kyber");
        map.put("Kyber-512-90s-r3", "Kyber");
        map.put("Kyber-768-90s-r3", "Kyber");
        map.put("Kyber-1024-90s-r3", "Kyber");
        map.put("SphincsPlus-shake-128f-r3.1", "SphincsPlus");
        map.put("SphincsPlus-shake-192f-r3.1", "SphincsPlus");
        map.put("SphincsPlus-shake-256f-r3.1", "SphincsPlus");
        map.put("Dilithium-4x4-r3", "Dilithium");
        map.put("Dilithium-6x5-r3", "Dilithium");
        map.put("Dilithium-8x7-r3", "Dilithium");
        return map.get(keyAlgorithm);
    }

    public static List<String> getFips204MLDSA_SLHDSAPreHashSignatureAlgorithms(){
        List<String> map = new ArrayList<>();
        map.add("SHA2-224");
        map.add("SHA2-256");
        map.add("SHA2-384");
        map.add("SHA2-512");
        map.add("SHA3-224");
        map.add("SHA3-256");
        map.add("SHA3-384");
        map.add("SHA3-512");
        map.add("SHAKE-128");
        map.add("SHAKE-256");
        return map;
    }


    public static String getPqcKeyAlgorithm(String keyAlgorithm) {
        Map<String, String> map = new HashMap<>();
        map.put("KYBER512_WITH_SHAKE", "Kyber");
        map.put("KYBER768_WITH_SHAKE", "Kyber");
        map.put("KYBER1024_WITH_SHAKE", "Kyber");
        map.put("KYBER512_WITH_SHA2_AES", "Kyber");
        map.put("KYBER768_WITH_SHA2_AES", "Kyber");
        map.put("KYBER1024_WITH_SHA2_AES", "Kyber");
        map.put("SPHINCS_PLUS_SHAKE_L1", "SphincsPlus");
        map.put("SPHINCS_PLUS_SHAKE_L3", "SphincsPlus");
        map.put("SPHINCS_PLUS_SHAKE_L5", "SphincsPlus");
        map.put("DILITHIUM_L2", "Dilithium");
        map.put("DILITHIUM_L3", "Dilithium");
        map.put("DILITHIUM_L5", "Dilithium");
        return map.get(keyAlgorithm);
    }

    private static Map<String, String> getSupportedEcCurves() {
        Provider[] providers = Security.getProviders("AlgorithmParameters.EC");
        Provider provider = providers[0];
        String curves = provider.getService("AlgorithmParameters", "EC").getAttribute("SupportedCurves");
        Map<String, String> map = Arrays.stream(curves.split("\\|"))
                .map(s -> s.replace("[", "").replace("]", ""))
                .map(s -> s.split(","))
                .collect(Collectors.toMap(a -> a[a.length - 1], a -> a[0]));

        map.put("1.3.132.0.32", "secp224k1");
        map.put("1.3.132.0.33", "secp224r1");
        map.put("1.3.132.0.10", "secp256k1");
        map.put("1.2.840.10045.3.1.7", "secp256r1");
        map.put("1.3.132.0.34", "secp384r1");
        map.put("1.3.132.0.35", "secp521r1");

        map.put("1.2.840.10045.3.1.1", "x962p239v1");
        map.put("1.2.840.10045.3.1.2", "x962p239v2");
        map.put("1.2.840.10045.3.1.3", "x962p239v3");

        map.put("1.3.36.3.3.2.8.1.1.1", "brainpool224r1");
        map.put("1.3.36.3.3.2.8.1.1.7", "brainpool256r1");
        map.put("1.3.36.3.3.2.8.1.1.9", "brainpool320r1");
        map.put("1.3.36.3.3.2.8.1.1.11", "brainpool384r1");
        map.put("1.3.36.3.3.2.8.1.1.13", "brainpool512r1");

        map.put("1.2.250.1.223.101.256.1", "frp256v1");

        LOGGER.debug("supported curves: {}", map);
        return map;
    }

    public static String getEdCurveNameForOID(String oid) {
        Map<String, String> curves = getSupportedEdCurves();
        LOGGER.debug("looking for curve name for oid: '{}'", oid);
        String curve = curves.get(oid);
        LOGGER.debug("curve for '{}' is '{}'", oid, curve);
        return curve;
    }

    /*
    This method manually defines a mapping between the ED curves and the curve OID. It can't be loaded the same as the EC curves
    as the available providers do not contain these curve OIDs.
     */
    private static Map<String, String> getSupportedEdCurves() {
        Map<String, String> map = new HashMap<>();
        map.put("1.3.101.112", "ed25519");
        return map;
    }


    public static PrimusAuthorization createPrimusAuthorizationFromSignedApprovals(List<String> signedApprovals) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Number of signed approvals: {}", signedApprovals.size());
        }

        PrimusAuthorization primusAuthorization = new PrimusAuthorization();

        List<PrimusAuthorizationToken> primusAuthorizationTokens = signedApprovals.stream()
                .map(Base64.getDecoder()::decode)
                .map(PrimusAuthorizationToken::new)
                .collect(Collectors.toList());

        primusAuthorizationTokens.forEach(primusAuthorization::add);

        return primusAuthorization;
    }

    /**
     * Creates a public key from a byte representation of a key.
     * @param publicKeyBytes The byte representation of a public key
     * @param algorithm The algorithm of the key
     * @return A PublicKey object created from the byte representation
     */
    public static PublicKey parsePublicKey(byte[] publicKeyBytes, String algorithm) {
        try {
            if ("ED".equals(algorithm)) {
                return EdPublicKeyImpl.fromBytes(publicKeyBytes);
            } else {
                KeyFactory kf = KeyFactory.getInstance(algorithm);
                return kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
            }
        } catch (InvalidKeySpecException e) {
            String msg = "Could not parse public key";
            if (e.getCause() instanceof InvalidKeyException) {
                msg = String.format("The provided public key is not compatible with algorithm '%s'", algorithm);
            }
            throw new BusinessException(msg, BusinessReason.ERROR_PARSING_KEY, e);
        } catch (NoSuchAlgorithmException e) {
            throw new BusinessException("Could not parse public key", BusinessReason.ERROR_PARSING_KEY, e);
        }
    }


    public static Set<String> gatherApprovalPublicKeys(List<ModifyPolicyDto.Token> tokens) {
        return tokens.stream()
                .flatMap(token -> Stream.ofNullable(token.getGroups()))
                .flatMap(Collection::stream)
                .flatMap(group -> group.getApprovals().stream())
                .map(approval -> ModifyPolicyDto.ApprovalType.certificate.equals(approval.getType()) ?
                        Base64.getEncoder().encodeToString(CryptoUtil.getPublicKeyFromBase64Certificate(approval.getValue()).getEncoded()) :
                        approval.getValue())
                .collect(Collectors.toSet());
    }
}