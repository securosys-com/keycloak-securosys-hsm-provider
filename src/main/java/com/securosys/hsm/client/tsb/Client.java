// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Shared TSB client plumbing for authorization and HTTP requests.
 */
public abstract class Client {
    private static final Logger LOGGER = LoggerFactory.getLogger(Client.class);

    protected final String hostURL;
    protected final HttpClient httpClient;
    protected final AuthStruct auth;
    protected final ObjectMapper objectMapper = new ObjectMapper();

    public static final String KeyManagementTokenName = "KeyManagementToken";
    public static final String KeyOperationTokenName = "KeyOperationToken";
    public static final String ApproverTokenName = "ApproverToken";
    public static final String ServiceTokenName = "ServiceToken";
    public static final String ApproverKeyManagementTokenName = "ApproverKeyManagementToken";

    protected Client(String hostURL, HttpClient httpClient, AuthStruct auth) {
        this.hostURL = hostURL == null ? "" : hostURL.replaceAll("/$", "");
        this.httpClient = httpClient;
        this.auth = auth;
    }

    protected static AuthStruct buildAuth(SecurosysConfig config) throws Exception {
        if (config == null) {
            throw new IllegalArgumentException("client configuration was null");
        }

        ObjectMapper mapper = new ObjectMapper();
        KeyPair keyPair = readOptionalJson(mapper, config.getApplicationKeyPair(), KeyPair.class, new KeyPair());
        ApiKeyTypes apiKeys = readOptionalJson(mapper, config.getApiKeys(), ApiKeyTypes.class, new ApiKeyTypes());
        String appName = config.getAppName() == null ? "OpenBao - Securosys HSM KMS" : config.getAppName();

        return new AuthStruct(
            config.getAuth(),
            config.getCertPath(),
            config.getKeyPath(),
            config.getBearerToken(),
            config.getBasicToken(),
            config.getUsername(),
            config.getPassword(),
            keyPair,
            apiKeys,
            appName
        );
    }

    private static <T> T readOptionalJson(ObjectMapper mapper, String json, Class<T> type, T fallback) throws Exception {
        if (json == null || json.trim().isEmpty()) {
            return fallback;
        }
        return mapper.readValue(json, type);
    }

    protected static HttpClient buildHttpClient(AuthStruct settings) throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder()
            .connectTimeout(java.time.Duration.ofSeconds(9999999));

        if ("CERT".equals(settings.getAuthType())) {
            configureCertAuth(builder, settings);
        }

        return builder.build();
    }

    private static void configureCertAuth(HttpClient.Builder builder, AuthStruct settings) throws Exception {
        if (settings.getCertPath() == null || settings.getCertPath().isEmpty()) {
            throw new IllegalArgumentException("P12 certificate path is required for CERT authentication");
        }
        if (settings.getKeyPath() == null || settings.getKeyPath().isEmpty()) {
            throw new IllegalArgumentException("P12 password is required for CERT authentication");
        }

        // Load the P12 keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(settings.getCertPath())) {
            keyStore.load(fis, settings.getKeyPath().toCharArray());
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init((KeyStore) null);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, settings.getKeyPath().toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), new SecureRandom());

        builder.sslContext(sslContext);
    }

    public void rollOverApiKey(String name) throws Exception {
        switch (name) {
            case KeyManagementTokenName:
                auth.getCurrentApiKeyTypeIndex().setKeyManagementTokenIndex(
                    auth.getCurrentApiKeyTypeIndex().getKeyManagementTokenIndex() + 1);
                break;
            case KeyOperationTokenName:
                if (auth.getApiKeys().getKeyOperationToken() == null || auth.getApiKeys().getKeyOperationToken().isEmpty()) {
                    throw new Exception("no KeyOperationToken provided");
                }
                auth.getCurrentApiKeyTypeIndex().setKeyOperationTokenIndex(
                    auth.getCurrentApiKeyTypeIndex().getKeyOperationTokenIndex() + 1);
                break;
            case ApproverTokenName:
                if (auth.getApiKeys().getApproverToken() == null || auth.getApiKeys().getApproverToken().isEmpty()) {
                    throw new Exception("no ApproverToken provided");
                }
                auth.getCurrentApiKeyTypeIndex().setApproverTokenIndex(
                    auth.getCurrentApiKeyTypeIndex().getApproverTokenIndex() + 1);
                break;
            case ServiceTokenName:
                if (auth.getApiKeys().getServiceToken() == null || auth.getApiKeys().getServiceToken().isEmpty()) {
                    throw new Exception("no ServiceToken provided");
                }
                auth.getCurrentApiKeyTypeIndex().setServiceTokenIndex(
                    auth.getCurrentApiKeyTypeIndex().getServiceTokenIndex() + 1);
                break;
            case ApproverKeyManagementTokenName:
                if (auth.getApiKeys().getApproverKeyManagementToken() == null || auth.getApiKeys().getApproverKeyManagementToken().isEmpty()) {
                    throw new Exception("no ApproverKeyManagementToken provided");
                }
                auth.getCurrentApiKeyTypeIndex().setApproverKeyManagementTokenIndex(
                    auth.getCurrentApiKeyTypeIndex().getApproverKeyManagementTokenIndex() + 1);
                break;
            default:
                throw new Exception("apikey using name " + name + " does not exist");
        }
    }

    public boolean canGetNewApiKeyByName(String name) throws Exception {
        if (auth.getApiKeys() == null) {
            return false;
        }

        switch (name) {
            case KeyManagementTokenName:
                return auth.getApiKeys().getKeyManagementToken() != null
                    && auth.getApiKeys().getKeyManagementToken().size() > auth.getCurrentApiKeyTypeIndex().getKeyManagementTokenIndex();
            case KeyOperationTokenName:
                return auth.getApiKeys().getKeyOperationToken() != null
                    && auth.getApiKeys().getKeyOperationToken().size() > auth.getCurrentApiKeyTypeIndex().getKeyOperationTokenIndex();
            case ApproverTokenName:
                return auth.getApiKeys().getApproverToken() != null
                    && auth.getApiKeys().getApproverToken().size() > auth.getCurrentApiKeyTypeIndex().getApproverTokenIndex();
            case ServiceTokenName:
                return auth.getApiKeys().getServiceToken() != null
                    && auth.getApiKeys().getServiceToken().size() > auth.getCurrentApiKeyTypeIndex().getServiceTokenIndex();
            case ApproverKeyManagementTokenName:
                return auth.getApiKeys().getApproverKeyManagementToken() != null
                    && auth.getApiKeys().getApproverKeyManagementToken().size() > auth.getCurrentApiKeyTypeIndex().getApproverKeyManagementTokenIndex();
            default:
                throw new Exception("no apikey exists using name " + name);
        }
    }

    public String getApiKeyByName(String name) {
        switch (name) {
            case KeyManagementTokenName:
                return auth.getApiKeys().getKeyManagementToken().get(auth.getCurrentApiKeyTypeIndex().getKeyManagementTokenIndex());
            case KeyOperationTokenName:
                return auth.getApiKeys().getKeyOperationToken().get(auth.getCurrentApiKeyTypeIndex().getKeyOperationTokenIndex());
            case ApproverTokenName:
                return auth.getApiKeys().getApproverToken().get(auth.getCurrentApiKeyTypeIndex().getApproverTokenIndex());
            case ServiceTokenName:
                return auth.getApiKeys().getServiceToken().get(auth.getCurrentApiKeyTypeIndex().getServiceTokenIndex());
            case ApproverKeyManagementTokenName:
                return auth.getApiKeys().getApproverKeyManagementToken().get(auth.getCurrentApiKeyTypeIndex().getApproverKeyManagementTokenIndex());
            default:
                return null;
        }
    }

    private static String debugHeaders(HttpHeaders headers) {
        return headers.map().entrySet().stream()
            .map(entry -> entry.getKey() + "=" + entry.getValue().stream()
                .map(value -> isSensitiveHeader(entry.getKey()) ? "*****" : value)
                .collect(Collectors.joining(",")))
            .collect(Collectors.joining("; "));
    }

    private static boolean isSensitiveHeader(String headerName) {
        String lower = headerName.toLowerCase();
        return "authorization".equals(lower) || "x-api-key".equals(lower) || "proxy-authorization".equals(lower);
    }

    private static String debugRequestBody(HttpRequest request) {
        return request.bodyPublisher()
            .map(Client::bodyPublisherToString)
            .orElse("<empty>");
    }

    private static String bodyPublisherToString(HttpRequest.BodyPublisher publisher) {
        try {
            for (Field field : publisher.getClass().getDeclaredFields()) {
                if (field.getType() == String.class) {
                    field.setAccessible(true);
                    Object value = field.get(publisher);
                    if (value != null) {
                        return String.valueOf(value);
                    }
                }
            }
        } catch (Throwable ignored) {
            // best effort only
        }
        return "<body-publisher=" + publisher.getClass().getName() + "; length=" + publisher.contentLength() + ">";
    }

    /**
     * Function that makes all requests. Using config for Authorization to TSB.
     */
    public ResponseData doRequest(HttpRequest request, String apiKeyName) throws Exception {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(request.uri());

        request.headers().map().forEach((key, values) ->
            values.forEach(value -> requestBuilder.header(key, value)));

        if ("TOKEN".equals(auth.getAuthType())) {
            requestBuilder.header("Authorization", "Bearer " + auth.getBearerToken());
        } else if ("BASIC".equals(auth.getAuthType())) {
            if (auth.getBasicToken() == null || auth.getBasicToken().isEmpty()) {
                String credentials = auth.getUsername() + ":" + auth.getPassword();
                String encoded = Base64.toBase64String(credentials.getBytes());
                requestBuilder.header("Authorization", "Basic " + encoded);
            } else {
                requestBuilder.header("Authorization", "Basic " + auth.getBasicToken());
            }
        }

        if (canGetNewApiKeyByName(apiKeyName)) {
            requestBuilder.header("X-API-KEY", getApiKeyByName(apiKeyName));
        }

        requestBuilder.header("Content-Type", "application/json");

        if (request.method().equals("POST") || request.method().equals("PUT")) {
            requestBuilder.method(request.method(), request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
        } else {
            requestBuilder.method(request.method(), HttpRequest.BodyPublishers.noBody());
        }

        HttpRequest finalRequest = requestBuilder.build();

        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("TSB request: method={}, uri={}, authType={}, apiKeyName={}, headers={}, body={}",
                finalRequest.method(),
                finalRequest.uri(),
                auth.getAuthType(),
                apiKeyName,
                debugHeaders(finalRequest.headers()),
                debugRequestBody(request));
        }
        
        try {
            HttpResponse<String> response = httpClient.send(finalRequest, HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            int statusCode = response.statusCode();

            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("TSB response: status={}, body={}", statusCode, body);
            }
            if (canGetNewApiKeyByName(apiKeyName) && statusCode == 401) {
                Map<String, Object> result = objectMapper.readValue(body, Map.class);
                Object rawErrorCode = result.get("errorCode");
                int errorCode = rawErrorCode instanceof Number ? ((Number) rawErrorCode).intValue() : -1;
                if (errorCode == 631) {
                    rollOverApiKey(apiKeyName);
                    return doRequest(request, apiKeyName);
                }
            }

            if (statusCode != 200 && statusCode != 201) {
                throw new IOException("status: " + statusCode + ", body: " + body);
            }

            return new ResponseData(body, statusCode);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Request interrupted", e);
        }
    }

    public RSAPrivateKey getApplicationPrivateKey() {
        return null;
    }

    public byte[] wrapPrivateKeyWithHeaders(boolean pkcs8) {
        if (auth.getApplicationKeyPair() == null || auth.getApplicationKeyPair().getPrivateKey() == null) {
            return null;
        }
        if (!pkcs8) {
            return ("-----BEGIN RSA PRIVATE KEY-----\n" + auth.getApplicationKeyPair().getPrivateKey() + "\n-----END RSA PRIVATE KEY-----").getBytes();
        }
        return ("-----BEGIN PRIVATE KEY-----\n" + auth.getApplicationKeyPair().getPrivateKey() + "\n-----END PRIVATE KEY-----").getBytes();
    }

    public String generateRequestSignature(String requestData) throws Exception {
        if (auth.getApplicationKeyPair() == null
            || auth.getApplicationKeyPair().getPrivateKey() == null
            || auth.getApplicationKeyPair().getPublicKey() == null) {
            return "null";
        }

        String compact = objectMapper.writeValueAsString(objectMapper.readTree(requestData));
        String signature = signData(compact.getBytes());
        return String.format("{\n\t\t\"signature\": \"%s\",\n\t\t\"digestAlgorithm\": \"SHA-256\",\n\t\t\"publicKey\": \"%s\"\n\t\t}",
            signature, auth.getApplicationKeyPair().getPublicKey());
    }

    public String signData(byte[] dataToSign) throws Exception {
        if (auth.getApplicationKeyPair() == null
            || auth.getApplicationKeyPair().getPrivateKey() == null
            || auth.getApplicationKeyPair().getPublicKey() == null) {
            throw new Exception("No Application Private Key or Public Key provided!");
        }

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(dataToSign);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(getApplicationPrivateKey());
        sig.update(hash);
        byte[] signature = sig.sign();

        return Base64.toBase64String(signature);
    }

    public String prepareMetaData(String requestType, Map<String, String> additionalMetaData, Map<String, String> customMetaData) {
        return "";
    }

    public String getHostURL() {
        return hostURL;
    }

    public AuthStruct getAuth() {
        return auth;
    }
}
