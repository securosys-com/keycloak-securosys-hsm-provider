/**
 * Copyright (c) 2025 Securosys SA, authors: Tomasz Madej
 * <p>
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
 */

package com.securosys.hsm.client.jce;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmKeyAttributes;
import com.securosys.hsm.client.config.JceConfig;
import com.securosys.hsm.dto.*;
import com.securosys.hsm.enums.PayloadType;
import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;
import com.securosys.hsm.util.*;
import com.securosys.primus.jce.*;
import com.securosys.primus.jce.encoding.DEREncodingException;
import com.securosys.primus.jce.encoding.StringEncoding;
import com.securosys.primus.jce.spi0.*;
import org.keycloak.crypto.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core HSM service providing integration with Securosys Primus HSM for key management,
 * certificate operations, and digital signature generation.
 *
 * This service handles:
 * - HSM connection lifecycle and authentication
 * - Key creation, import, and attribute management
 * - Certificate generation and import
 * - Signature generation and verification
 * - Timestamp operations
 *
 * Thread Safety: Certain methods may require synchronized access to HSM connection state.
 * See individual method documentation for details.
 */
public class JceClient implements HsmClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(JceClient.class);

    private static final String JCE_PROVIDER = PrimusProvider.getProviderName();

    private static final String KEYSTORE_TYPE = PrimusProvider.getKeyStoreTypeName();

    /** Default RSA key size in bits for key generation */
    private static final int RSA_KEY_SIZE = 2048;
    private String secretFile;
    private JceConfig config;

    public JceClient(JceConfig config) {
        this.config = config;
    }

    /**
     * Formats the timestamp signature algorithm name for HSM compatibility.
     * Converts underscore-separated format (e.g., "SHA256_WITH_RSA") to
     * lowercase concatenated format (e.g., "sha256withrsa").
     *
     * @return formatted algorithm name suitable for HSM operations
     */
    public String getTimestampSignatureAlgorithm() {
        String timestampSignatureAlgorithm = this.config.getTimestampSignatureAlgorithm();
        if (timestampSignatureAlgorithm.contains("_")) {
            String[] splited = timestampSignatureAlgorithm.split("_");
            return splited[0] + splited[1].toLowerCase() + splited[2];
        }
        return timestampSignatureAlgorithm;
    }

    public void setSecretFile(){
        this.secretFile=config.getSecretPath();
    }
    public void setHsmHost() {

        long startTime = System.currentTimeMillis();

        PrimusConfiguration.setHsmHost(config.getHost(), config.getPort(), config.getUser());
        LOGGER.info("Setup configuration latency for each SETTINGS: {} {} {} ms", config.getHost(),config.getPort(),config.getUser());
        long endTime = System.currentTimeMillis();
        long latency = endTime - startTime;
        LOGGER.info("Setup configuration latency for each request: {} ms", latency);
    }

    public void login() {
        if (PrimusLogin.isLoggedIn()) {
            return;
        }
        if(config!=null)
            connectToPrimus();
    }

    public void setProxyCredentials() {
        if (config.getProxyPassword() != null) {
            PrimusConfiguration.setProxyCredentials(config.getProxyUser(), config.getProxyPassword().toCharArray());
        } else {
            PrimusConfiguration.setProxyCredentials(config.getProxyUser(), "".toCharArray());
        }
    }

    /**
     * Establishes connection to HSM and initializes JCE provider.
     *
     * Steps performed:
     * 1. Adds Primus JCE provider to Java security
     * 2. Sets up HSM host/port configuration
     * 3. Configures proxy credentials if needed
     * 4. Sets connection timeout system property
     * 5. Performs authentication if credentials provided
     * 6. Logs license information on successful connection
     */
    public void connectToPrimus() {
        Security.addProvider(new PrimusProvider());
        setSecretFile();
        setHsmHost();
        setProxyCredentials();
        setConnectionTimeout();
        authenticateToPrimus();
    }

    private void setConnectionTimeout() {
        System.setProperty(
                "com.securosys.primus.jce.Transport.overallConnectAndHelloGraceTimeMilliSeconds",
                config.getConnectionTimeout());
    }

    private void authenticateToPrimus() {
        LOGGER.info("Authenticating to Primus HSM...");
        if (!hasSecretFile()) {
            LOGGER.info("No secret file found. Performing initial authentication with password.");
            createSecretFile();
            return;
        }
        loginWithSecretFile();
    }

    private boolean hasSecretFile() {
        return Files.exists(Path.of(secretFile));
    }

    private void loginWithSecretFile() {
        PrimusLogin.login(config.getUser(), ("file:" + secretFile).toCharArray());
        if (PrimusLogin.isLoggedIn()) {
            logSuccessfulPrimusLogin();
        } else {
            logFailedPrimusLogin();
        }
    }

    private void logSuccessfulPrimusLogin() {
        LOGGER.info("Successfully login to primus hsm");
        LOGGER.info("Primus HSM JCE provider information: {} ", Security.getProvider(PrimusProvider.getProviderName()));
        LOGGER.info("Primus HSM JCE provider version: {}", Security.getProvider(PrimusProvider.getProviderName()).getVersion());
        LicenseDto licenseDtoInformation = new LicenseDto();
        Set<String> clientFlags = loadUserFlags();
        licenseDtoInformation.setClientFlags(clientFlags);
        LOGGER.info("License info: {} ", licenseDtoInformation.getClientFlags());
    }

    private void logFailedPrimusLogin() {
        LOGGER.error("Cannot login to primus hsm");
    }

    /**
     * Retrieves the password in the correct format from the configuration.
     * @return password as character array
     */
    public char[] readPassword() {
        return config.getSetupPassword().toCharArray();
    }

    /**
     * Creates a secret file for HSM authentication by retrieving user secret,
     * blinding it, and saving encrypted version to file for future logins.
     */
    public void createSecretFile() {
        loginWithPassword();
        final char[] blindedUserSecret = blindUserSecret();
        logoutFromPrimus();
        Path path = createSecretFilePath();
        writeBlindedSecretToFile(path, blindedUserSecret);
        loginWithSecretFile();
    }

    private void loginWithPassword() {
        PrimusLogin.login(config.getUser(), readPassword());
    }

    private char[] blindUserSecret() {
        final char[] userSecret = PrimusLogin.getUserSecretChars();
        final char[] blindedUserSecret = PrimusBlinding.blindChars(userSecret, PrimusBlinding.BlindingAlgorithm.AES);
        Arrays.fill(userSecret, '*');
        return blindedUserSecret;
    }

    private void logoutFromPrimus() {
        LOGGER.info("logging out");
        PrimusLogin.logout();
    }

    private Path createSecretFilePath() {
        final Path path = Paths.get(secretFile);
        try {
            Files.deleteIfExists(path);
            createSecretFileWithOwnerPermissions(path);
        } catch (IOException | UnsupportedOperationException e) {
            createSecretFileWithoutPermissions(path);
        }
        return path;
    }

    private void createSecretFileWithOwnerPermissions(Path path) throws IOException {
        final Set<PosixFilePermission> permissions = new HashSet<>();
        permissions.add(PosixFilePermission.OWNER_READ);
        permissions.add(PosixFilePermission.OWNER_WRITE);
        final FileAttribute<?> ownerOnlyPermissions = PosixFilePermissions.asFileAttribute(permissions);
        Files.createFile(path, ownerOnlyPermissions);
    }

    private void createSecretFileWithoutPermissions(Path path) {
        try {
            Files.createFile(path);
        } catch (IOException ex) {
            throw new BusinessException("Cannot create secret file", BusinessReason.ERROR_IO, ex);
        }
    }

    private void writeBlindedSecretToFile(Path path, char[] blindedUserSecret) {
        LOGGER.info("writing blinded permanent secret to file");
        final ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(blindedUserSecret));
        Arrays.fill(blindedUserSecret, '*');
        final byte[] b = new byte[bb.remaining()];
        bb.get(b);
        Arrays.fill(bb.array(), (byte) 0);
        try {
            Files.write(path, b);
        } catch (IOException e) {
            throw new BusinessException("Cannot write into secret file", BusinessReason.ERROR_IO, e.getCause());
        }
        Arrays.fill(b, (byte) 0);
    }
    private static byte[] generateRandomOnHsm(int length) {
        try {
            final SecureRandom secureRandom =
                    SecureRandom.getInstance(PrimusProvider.getSecureRandomTypeName(), PrimusProvider.getProviderName());
            final byte[] random = new byte[length];
            secureRandom.nextBytes(random);

            return random;
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            String msg = "Could not generate random number on the HSM";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        }
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

        return primusKeyGeneratorAlgorithms.contains(algorithm);
    }

    private static List<Provider.Service> getProviderServices(Provider provider, String serviceName) {
        List<Provider.Service> services =
                provider.getServices().stream()
                        .filter(x -> x.getType().equals(serviceName)).collect(Collectors.toList());
        services.forEach(x -> LOGGER.debug("KeyGeneratorService: {}", x));
        return services;
    }
    private static KeyAttributesDto createJsonKeyAttributes(String xml) {
        try {
            XmlMapper xmlMapper = new XmlMapper();
            xmlMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
            return xmlMapper.readValue(xml, KeyAttributesDto.class);
        } catch (IOException e) {
            throw new BusinessException("Could not create json object from xml.",
                    BusinessReason.ERROR_DATA_INVALID_CONSTELLATION, e);
        }
    }
    /**
     * The key loaded is either a PrivateKey if the key is asymmetric or a SecretKey if the key is symmetric.
     */
    private static Key loadKeyFromKeyname(String keyName, char[] keyPassword) {
        try {
            Key key;
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, JCE_PROVIDER);
            keyStore.load(null);
            key = keyStore.getKey(keyName, keyPassword);

            if (key == null) {
                String msg = String.format("A key with the name '%s' does not exist.", keyName);
                throw new BusinessException(msg, BusinessReason.ERROR_KEY_NOT_EXISTENT);
            } else {
                return key;
            }
        } catch (UnrecoverableKeyException e) {
            if (e.getCause() instanceof WrongKeyPasswordException) {
                String msg = String.format("Key password mismatch for key '%s'.", keyName);
                throw new BusinessException(msg, BusinessReason.ERROR_KEY_PASSWORD_MISMATCH, e);
            }
            throw createKeystoreAccessFailingException(e);
        } catch (IOException | KeyStoreException | NoSuchProviderException | CertificateException |
                 NoSuchAlgorithmException e) {
            throw createKeystoreAccessFailingException(e);
        }
    }
    private static RuntimeException createKeystoreAccessFailingException(Exception e) {
        String msg = "Could not load key. Access to HSM keystore is not working properly.";
        return new BusinessException(msg, BusinessReason.ERROR_GENERAL, e.getCause());
    }

    public SignedKeyAttributesDto getKeyAttributes(String keyName, char[] keyPassword) {
        this.login();


        String attestationKeyName = config.getAttestationKeyName();

        byte[][] signature = new byte[1][];
        String xml;

        try {
            if (HsmUtil.containsBIP32Path(keyName) && !doesKeyExist(keyName)) {
                xml = getAttributesForTemporaryBIP32Key(keyName, attestationKeyName, signature, keyPassword);
            } else {
                Key key = loadKeyFromKeyname(keyName, keyPassword);
                xml = PrimusAttestation.getSignedAttributes(attestationKeyName, key, signature);
            }

            SignedKeyAttributesDto keyAttributes = new SignedKeyAttributesDto();
            keyAttributes.setXml(xml);
            keyAttributes.setJson(createJsonKeyAttributes(xml));
            keyAttributes.setXmlSignature(Base64.getEncoder().encodeToString(signature[0]));
            keyAttributes.setAttestationKeyName(attestationKeyName);
            return keyAttributes;
        } catch (NotFoundException e) {
            String msg = String.format("An attestation key with the name '%s' does not exist.", attestationKeyName);
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        }
    }

    /**
     * @return the flags that are set for the client in their subscription
     */
    private static Set<String> loadUserFlags() {
        return PrimusDevice.getUserFlags();
    }
    private static boolean doesKeyExist(String keyName) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE, JCE_PROVIDER);
            keyStore.load(null);
            return keyStore.isKeyEntry(keyName);
        } catch (KeyStoreException | NoSuchProviderException | IOException | NoSuchAlgorithmException |
                 CertificateException e) {
            String msg = String.format("Could not check if key '%s' exists. Access to HSM keystore is not working properly.",
                    keyName);
            throw new BusinessException(msg, BusinessReason.ERROR_GENERAL, e.getCause());
        }
    }
    private static PrivateKey loadPrivateKeyFromKeyname(String keyName, char[] keyPassword) {
        Key key = loadKeyFromKeyname(keyName, keyPassword);
        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        } else {
            String msg = "Private key can not be loaded as the referenced key is not an asymmetric key.";
            throw new BusinessException(msg, BusinessReason.ERROR_INVALID_KEY_TYPE);
        }
    }
    private static void setKeyCapabilityFlags(PrimusKeyAttributes.CapabilityAttribute[] capabilityAttributes) {
        for (PrimusKeyAttributes.CapabilityAttribute attribute : capabilityAttributes) {
            PrimusKeyAttributes.setKeyCapabilityFlag(attribute.attribute, attribute.value);
        }
    }
    private static PrimusKeyAttributes.CapabilityAttribute[] getCapabilityAttributes(AttributesDto attributes) {
        LOGGER.debug("processing key attributes for capability flags: {}", attributes);
        List<PrimusKeyAttributes.CapabilityAttribute> primusCapabilityAttributes = new ArrayList<>();

        primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_DECRYPT,
                attributes.getDecrypt()));

        primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_DERIVE,
                attributes.isDerive()));

        primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_SIGN,
                attributes.getSign()));

        primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_UNWRAP,
                attributes.getUnwrap()));

        if (attributes.getEncrypt() != null) {
            primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_ENCRYPT,
                    attributes.getEncrypt()));
        }

        if (attributes.getVerify() != null) {
            primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_VERIFY,
                    attributes.getVerify()));
        }

        if (attributes.getWrap() != null) {
            primusCapabilityAttributes.add(new PrimusKeyAttributes.CapabilityAttribute(PrimusKeyAttributes.CAPABILITY_WRAP,
                    attributes.getWrap()));
        }

        return primusCapabilityAttributes.toArray(PrimusKeyAttributes.CapabilityAttribute[]::new);
    }


    private static void setFlagsAndAccess(AttributesDto attributes, PolicyDto.KeyStatus keyStatus, AddressFormatDto addressFormat, PrimusAccess primusAccess) {
        if(keyStatus!=null) {
            setKeyAccessFlags(getAccessAttributes(attributes, keyStatus.getBlocked()));
        }else{
            setKeyAccessFlags(getAccessAttributes(attributes, false));
        }
        setKeyCapabilityFlags(getCapabilityAttributes(attributes));
        PrimusAccess.setAccess(primusAccess);

        if (addressFormat != null
                && addressFormat.getFormat() != null
                && !addressFormat.getFormat().isBlank()) {
            PrimusCryptoCurrencies.setCryptoCurrency(HsmUtil.mapCryptoCurrency(addressFormat.getFormat()));
        }
    }
    /**
     The attributes copyable, sensitive and neverExtractable are not set on purpose.
     */
    private static PrimusKeyAttributes.AccessAttribute[] getAccessAttributes(AttributesDto attributes,
                                                                             boolean keyStatus) {
        LOGGER.debug("processing key attributes for access flags: {}", attributes);
        List<PrimusKeyAttributes.AccessAttribute> primusAccessAttributes = new ArrayList<>();
        primusAccessAttributes.add(new PrimusKeyAttributes.AccessAttribute(PrimusKeyAttributes.ACCESS_BLOCKED,
                keyStatus));

        // take care, logic inverted
        primusAccessAttributes.add(new PrimusKeyAttributes.AccessAttribute(PrimusKeyAttributes.ACCESS_INDESTRUCTIBLE,
                !attributes.isDestroyable()));


        primusAccessAttributes.add(new PrimusKeyAttributes.AccessAttribute(PrimusKeyAttributes.ACCESS_MODIFIABLE,
                attributes.isModifiable()));


        primusAccessAttributes.add(new PrimusKeyAttributes.AccessAttribute(PrimusKeyAttributes.ACCESS_EXTRACTABLE,
                attributes.isExtractable()));


        if (attributes.getSensitive() != null) {
            primusAccessAttributes.add(new PrimusKeyAttributes.AccessAttribute(PrimusKeyAttributes.ACCESS_SENSITIVE,
                    attributes.getSensitive()));
        }

        return primusAccessAttributes.toArray(PrimusKeyAttributes.AccessAttribute[]::new);
    }
    private static void setKeyAccessFlags(PrimusKeyAttributes.AccessAttribute[] accessAttributes) {
        for (PrimusKeyAttributes.AccessAttribute attribute : accessAttributes) {
            PrimusKeyAttributes.setKeyAccessFlag(attribute.attribute, attribute.value);
        }
    }
    /**
     * Not all attributes are necessary for derivation:
     * - encrypt, verify and wrap can only be set for symmetric keys and derivation only supports asymmetric keys.
     * - bip32 is not relevant for the key generation process
     */
    protected static AttributesDto mapAttributesForDerivation(KeyAttributesDto.Attributes attestationAttributes) {
        AttributesDto attributesDto = new AttributesDto();
        attributesDto.setDecrypt(attestationAttributes.getDecrypt());
        attributesDto.setSign(attestationAttributes.getSign());
        attributesDto.setUnwrap(attestationAttributes.getUnwrap());
        attributesDto.setDerive(attestationAttributes.getDerive());
        attributesDto.setSensitive(attestationAttributes.getSensitive());
        attributesDto.setExtractable(attestationAttributes.getExtractable());
        attributesDto.setModifiable(attestationAttributes.getModifiable());
        attributesDto.setDestroyable(attestationAttributes.getDestroyable());
        return attributesDto;
    }
    public SignedKeyAttributesDto getKeyAttributes(String keyLabel, String keyPassword){
        this.login();
        char[] password = null;
        if (keyPassword != null) {
            password = keyPassword.toCharArray();
        }
        return this.getKeyAttributes(keyLabel, password);
    }
    public static PublicKey parsePublicKey(String publicKey) {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        // Try the common key types; the one that matches ASN.1 will succeed
        for (String alg : new String[]{"RSA", "EC"}) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(spec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ignored) { }
        }
        throw new IllegalArgumentException("Unknown public key algorithm / not X.509");

    }


    public PublicKey getPublicKey(SignedKeyAttributesDto keyAttributesDto) {
        this.login();
        String publicKey = keyAttributesDto.getJson().getPublicKey();
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        // Try the common key types; the one that matches ASN.1 will succeed
        for (String alg : new String[]{"RSA", "EC"}) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(spec);
            } catch (InvalidKeySpecException | NoSuchAlgorithmException ignored) { }
        }
        throw new IllegalArgumentException("Unknown public key algorithm / not X.509");

    }

    @Override
    public HsmKeyAttributes fetchKeyAttributes(String keyLabel, String keyPassword) {
        SignedKeyAttributesDto attributes = getKeyAttributes(keyLabel, keyPassword);
        KeyAttributesDto json = attributes.getJson();
        return new HsmKeyAttributes(
                json.getLabel(),
                json.getAlgorithm(),
                json.getPublicKey(),
                attributes.getXml(),
                attributes.getXmlSignature(),
                attributes.getAttestationKeyName());
    }

    @Override
    public PublicKey getPublicKey(HsmKeyAttributes keyAttributes) {
        this.login();
        return parsePublicKey(keyAttributes.getPublicKey());
    }
    private String getAttributesForTemporaryBIP32Key(String keyName, String attestationKeyName, byte[][] signature, char[] masterKeyPassword) {
        String masterKeyName = HsmUtil.getBIP32MasterKeyName(keyName);
        String derivationPath = HsmUtil.getBIP32DerivationPath(keyName);
        PrivateKey masterKey = loadPrivateKeyFromKeyname(masterKeyName, masterKeyPassword);
        PrivateKey temporaryDerviedKey = new PrimusSpecs.CkdDerivedPrivateKey(masterKey, derivationPath);
        KeyAttributesDto.Attributes masterKeyAttributes = getKeyAttributes(masterKeyName, masterKeyPassword).getJson().getAttributes();
        setFlagsAndAccess(mapAttributesForDerivation(masterKeyAttributes), null, null, null);
        return PrimusAttestation.getSignedAttributes(attestationKeyName, temporaryDerviedKey, signature);
    }
    private static Signature initAlgorithmSpecificSignature(PrivateKey signKey, String signatureAlgorithm) {
        try {
            Signature signature;
            signature = Signature.getInstance(signatureAlgorithm, JCE_PROVIDER);

            return signature;
        } catch (Exception e) {
            throw createSignErrorException(e);
        }
    }
    private static SignResult setSchnorrAlgorithmInfoPost(String signatureAlgorithm, Signature signature, byte[] derSignature) {
        try {
            if (signatureAlgorithm.equals("SchnorrBip0340") &&
                    signature.getParameters().getParameterSpec(PrimusSpecs.AuxiliaryRandomDataParameterSpec.class) != null){
                return new SignResult(derSignature,
                        signature.getParameters().getParameterSpec(PrimusSpecs.AuxiliaryRandomDataParameterSpec.class).getAuxiliaryRandomData()
                );
            }
            return new SignResult(derSignature, null);
        } catch (Exception e) {
            throw createSignErrorException(e);
        }
    }

    private static SignResult createSignature(PrivateKey signKey, byte[] payload, String signatureAlgorithm, String signatureType, String signKeyName) throws Throwable {
        try {
            LOGGER.debug("setting signature algorithm '{}'", signatureAlgorithm);

            byte[] decPayload = payload;

            // get signature
            Signature signature = initAlgorithmSpecificSignature(signKey, signatureAlgorithm);

            // init sign
            signature.initSign(signKey);


            // set message
            signature.update(decPayload);

            // sign
            byte[] derSignature = signature.sign();

            // SchnorrBip0340 Support with AuxiliaryRandomData
            if(signatureType == null || signatureType.equals("DER") || signatureType.equals("RAW")) {
                if(signatureType != null && signatureType.equals("RAW")) {
                    try{
                        byte[] rs = SignatureUtil.extractRSfromDERSignature(derSignature);
                        byte[] r = Arrays.copyOfRange(rs, 0, rs.length / 2);
                        byte[] s = Arrays.copyOfRange(rs, rs.length / 2, rs.length);
                        return new SignResult(SignatureUtil.cat(r, s), null);
                    } catch (DEREncodingException e) {
                        throw new BusinessException(e.getMessage(), BusinessReason.ERROR_ENCODING_EXCEPTION, e);
                    }
                }
                return setSchnorrAlgorithmInfoPost(signatureAlgorithm, signature, derSignature);
            }

            // ETH compatible signature-format: r,s,v
            return null;
        }
        catch(PrimusAuthorizationInsufficientException e) {
            String msg = "Error creating signature. The provided approvals are insufficient.";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        }
        catch (SpiException e) {
            if(e instanceof NotFoundException){
                throw new Throwable(BusinessReason.ERROR_KEY_NOT_EXISTENT.getReason());
            }
            throw createSignErrorException(e);
        }
        catch (Exception e) {
            throw createSignErrorException(e);
        }
    }
    private static BusinessException createSignErrorException(Exception e) {
        return new BusinessException("Error creating signature", BusinessReason.ERROR_IN_HSM, e);
    }

    private SignResult createSignature(SignPayload signPayload) throws Throwable {
        this.login();


        PrivateKey signKey;
        String keyName = signPayload.getSignKeyName();
        char[] keyPassword = signPayload.getKeyPassword();
        signKey = loadPrivateKeyFromKeyname(keyName, keyPassword);
        return createSignature(signKey, Base64.getDecoder().decode(signPayload.getPayload()),
                signPayload.getSignatureAlgorithm(), signPayload.getSignatureType(), keyName);
    }
    private String mapKeycloakAlgorithm(String algorithm){
        switch (algorithm){
            case Algorithm.RS256 -> {
                return "SHA256withRSA";
            }
            case Algorithm.RS384 -> {
                return "SHA384withRSA";
            }
            case Algorithm.RS512 -> {
                return "SHA512withRSA";
            }
            case Algorithm.ES256 -> {
                return "SHA256withECDSA";
            }
            case Algorithm.ES384 -> {
                return "SHA384withECDSA";
            }
            case Algorithm.ES512 -> {
                return "SHA512withECDSA";
            }
        }
        return algorithm;

    }
    private static SignResult createSignature(PrivateKey signKey,
                                              char[] keyPassword,
                                              String payload,
                                              String attestationKeyName,
                                              String signatureAlgorithm,
                                              String signatureType,
                                              String signKeyName,
                                              String auxiliaryRandomData,
                                              String mlslhContext,
                                              String taprootTweakData,
                                              String merkleRootData,
                                              PayloadType payloadType) {
        try {
            LOGGER.debug("setting signature algorithm '{}'", signatureAlgorithm);

            byte[] decPayload = EncodeDecodeUtil.decodeByType(payload, payloadType);


            // get signature
            Signature signature = initAlgorithmSpecificSignature(signKey, signatureAlgorithm);

            // init sign
            signature.initSign(signKey);

            // set message
            signature.update(decPayload);

            // sign
            byte[] derSignature = signature.sign();

            // SchnorrBip0340 Support with AuxiliaryRandomData
            if(signatureType == null || signatureType.equals("DER") || signatureType.equals("RAW")) {
                if(signatureType != null && signatureType.equals("RAW")) {
                    try{
                        byte[] rs = SignatureUtil.extractRSfromDERSignature(derSignature);
                        byte[] r = Arrays.copyOfRange(rs, 0, rs.length / 2);
                        byte[] s = Arrays.copyOfRange(rs, rs.length / 2, rs.length);
                        return new SignResult(SignatureUtil.cat(r, s), null);
                    } catch (DEREncodingException e) {
                        throw new BusinessException(e.getMessage(), BusinessReason.ERROR_ENCODING_EXCEPTION, e);
                    }
                }
                return setSchnorrAlgorithmInfoPost(signatureAlgorithm, signature, derSignature);
            }
        }
        catch(PrimusAuthorizationInsufficientException e) {
            String msg = "Error creating signature. The provided approvals are insufficient.";
            throw new BusinessException(msg, BusinessReason.ERROR_IN_HSM, e);
        }
        catch (Exception e) {
            throw createSignErrorException(e);
        }
        return null;
    }
    public SignResult createSignature(byte[] payload, String keyName, String password, String algorithm,String signatureType) throws Throwable {
        this.login();
        SignPayload signPayload = new SignPayload();
        signPayload.setPayload(CryptoUtil.encodeBase64(payload));
        signPayload.setSignKeyName(keyName);
        signPayload.setSignatureType(signatureType);
        if (password != null)
            signPayload.setKeyPassword(password.toCharArray());
       signPayload.setSignatureAlgorithm(mapKeycloakAlgorithm(algorithm));
        return createSignature(signPayload);
    }
    private SecretKey createSymmetricKey(CreateKeyDto createKey) {
        // create signing key
        final String keyName = createKey.getLabel();

        try {
            LOGGER.debug("creating key with name '{}'", keyName);
            setFlagsAndAccess(createKey.getAttributes(), null, createKey.getAddressFormat(), null);

            KeyGenerator primusKeyGenerator = PrimusKeyGeneratorFactory.getKeyGenerator(createKey);

            SecretKey secretKey;
            LOGGER.debug("generating key with name: '{}'", keyName);
            secretKey = PrimusName.generateKey(primusKeyGenerator, createKey.getLabel(), createKey.getPassword());

            return secretKey;
        } catch (DuplicateEntryException e) {
            throw new BusinessException("Could not create key. The key name is already in use.",
                    BusinessReason.ERROR_KEY_ALREADY_EXISTING, e);
        } finally {
            clearFlagsAndAccess();
        }
    }
    public HsmTimestamp getTimestamp(byte[] payload) {
        login();
        String integrityKeyName = this.config.getTimestampKeyName();
        PrimusSignature.setWantSignatures(true);
        PrimusSignature.setSignatureKey(integrityKeyName);

        final byte[] timestamp = PrimusDevice.getHsmTimestamp(payload, integrityKeyName);
        return getHsmTimestamp(payload, integrityKeyName, timestamp);
    }
    private static HsmTimestamp getHsmTimestamp(byte[] payload, String integrityKeyName, byte[] timestamp) {
        final PrimusSignature timestampSignature = PrimusSignature.getSignature();
        final byte[] timestampSignatureBinary = timestampSignature.getEncoding();
        return new HsmTimestamp(payload, timestamp, timestampSignatureBinary, integrityKeyName);
    }


    private KeyPair createAsymmetricKey(CreateKeyDto createKey) {
        // fill in the policy based on the input
        PolicyDto policy = createKey.getPolicy();
        PrimusAccess primusAccess = null;
        if(HsmUtil.isSkaKey(createKey)){
            primusAccess = CryptoUtil.getPrimusAccessFromPolicyDto(policy);
        }

        // create signing key
        final String keyName = createKey.getLabel();

        final KeyPair keyPair;
        try {
            PolicyDto.KeyStatus keyStatus = HsmUtil.isSkaKey(createKey) ? policy.getKeyStatus() : null;
            setFlagsAndAccess(createKey.getAttributes(), keyStatus, createKey.getAddressFormat(), primusAccess);
            KeyPairGenerator primusKeyPairGenerator = PrimusKeyPairGeneratorFactory.getKeyPairGenerator(createKey);

            LOGGER.debug("generating key with name: '{}'", keyName);
            keyPair = PrimusName.generateKeyPair(primusKeyPairGenerator, keyName, createKey.getPassword());
            final PrivateKey privateKey = keyPair.getPrivate();
            LOGGER.debug("generated private key: '{}'", privateKey);
            final PublicKey signKeyPublic = keyPair.getPublic();
            LOGGER.debug("generated public key: '{}'", signKeyPublic);
            LOGGER.debug("persisting key: '{}'", keyName);

            PrimusKeyAttributes.setKeyAccessFlag(PrimusKeyAttributes.ACCESS_INDESTRUCTIBLE, false);
            PrimusName.persistPublicKey(keyPair.getPublic(), keyName);

            return keyPair;
        }
        catch (KeyStoreException e) {
            throw new BusinessException("Could not persist public key.", BusinessReason.ERROR_IN_HSM, e);
        }
        catch (DuplicateEntryException e) {
            throw new BusinessException("Could not create key. The key name is already in use.",
                    BusinessReason.ERROR_KEY_ALREADY_EXISTING, e);
        }
        finally {
            clearFlagsAndAccess();
        }
    }

    private static void clearFlagsAndAccess() {

        PrimusKeyAttributes.clearKeyCapabilityFlags();

    }

    private void createKey(CreateKeyDto createKey) {
            login();

            String keyAlgorithm = createKey.getAlgorithm();
            Key key;
            if (HsmUtil.isAsymmetricAlgorithm(keyAlgorithm)) {
                KeyPair keyPair = createAsymmetricKey(createKey);
                key = keyPair.getPrivate();
            } else if (HsmUtil.isSymmetricAlgorithm(keyAlgorithm)) {
                key = createSymmetricKey(createKey);
            } else {
                throw new BusinessException("Unsupported algorithm: '" + keyAlgorithm + "'",
                        BusinessReason.ERROR_INPUT_VALIDATION_FAILED);
            }

            String keyId = createKey.getId();
            if (keyId != null) {
                setKeyId(keyId, key); // TODO: sfe, 2022-11-04, TSB-5120
            }
        }
    private static void setKeyId(String id, Key key) {
        PrimusKeyFields.setSharedKeyValue(key, StringEncoding.encode(id), PrimusKeyFields.ID);
    }
}
