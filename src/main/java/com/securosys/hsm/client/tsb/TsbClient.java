// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.PublicKey;
import java.util.Base64;

import org.keycloak.crypto.Algorithm;

import com.fasterxml.jackson.databind.JsonNode;
import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmKeyAttributes;
import com.securosys.hsm.client.tsb.dto.request.SynchronousSignEnvelope;
import com.securosys.hsm.client.tsb.dto.request.SynchronousSignRequest;
import com.securosys.hsm.client.tsb.dto.response.SynchronousSignResponse;
import com.securosys.hsm.client.tsb.key.KeyAttributes;
import com.securosys.hsm.client.tsb.key.KeyOperations;
import com.securosys.hsm.dto.SignResult;
import com.securosys.hsm.client.config.TsbConfig;
import com.securosys.hsm.util.HsmUtil;

/**
 * Single TSB client object. Operation methods live in parent classes split by area.
 */
public class TsbClient extends KeyOperations implements HsmClient {
    protected TsbClient(String hostURL, HttpClient httpClient, AuthStruct auth) {
        super(hostURL, httpClient, auth);
    }

    /**
     * Initialize a TSB client from TsbConfig.
     */
    public TsbClient(TsbConfig config) throws Exception {
        super(config.getTsbUrl(), buildHttpClient(buildAuthFromTsbConfig(config)), buildAuthFromTsbConfig(config));
    }

    /**
     * Build AuthStruct from TsbConfig.
     */
    private static AuthStruct buildAuthFromTsbConfig(TsbConfig config) throws Exception {
        if (config == null) {
            throw new IllegalArgumentException("TSB configuration was null");
        }

        // Create ApiKeyTypes from the API keys in TsbConfig
        ApiKeyTypes apiKeys = new ApiKeyTypes();
        if (config.getKeyOperationApiKey() != null && !config.getKeyOperationApiKey().trim().isEmpty()) {
            apiKeys.setKeyOperationToken(java.util.Arrays.asList(config.getKeyOperationApiKey().split(",")));
        }
        if (config.getKeyManagementApiKey() != null && !config.getKeyManagementApiKey().trim().isEmpty()) {
            apiKeys.setKeyManagementToken(java.util.Arrays.asList(config.getKeyManagementApiKey().split(",")));
        }

        return new AuthStruct(
            config.getAuth(),
            config.getMtlsP12Path(),      // p12Path
            config.getMtlsP12Password(),  // p12Password
            config.getBearerToken(),      // bearerToken
            null,                         // basicToken (not used in TsbConfig)
            null,                         // username (not used in TsbConfig)
            null,                         // password (not used in TsbConfig)
            new KeyPair(),                // keyPair (empty for now)
            apiKeys,
            "Keycloak Securosys TSB Provider" // appName
        );
    }

    @Override
    public HsmKeyAttributes fetchKeyAttributes(String keyLabel, String keyPassword) throws Exception {
        KeyAttributes attributes = getKeyAttributes(keyLabel, keyPassword);
        return new HsmKeyAttributes(
                attributes.getLabel(),
                attributes.getAlgorithm(),
                attributes.getPublicKey(),
                attributes.getXml(),
                attributes.getXmlSignature(),
                attributes.getAttestationKeyName());
    }

    @Override
    public PublicKey getPublicKey(HsmKeyAttributes keyAttributes) {
        byte[] publicKeyBytes = Base64.getDecoder().decode(keyAttributes.getPublicKey());
        return HsmUtil.parsePublicKey(publicKeyBytes, keyAttributes.getAlgorithm());
    }

    @Override
    public SignResult createSignature(byte[] payload, String keyName, String password, String algorithm,
            String signatureType) throws Exception {
        SynchronousSignRequest request = new SynchronousSignRequest();
        request.setSignKeyName(keyName);
        request.setKeyPassword(password);
        request.setPayload(Base64.getEncoder().encodeToString(payload));
        request.setSignatureAlgorithm(mapSignatureAlgorithm(algorithm));
        request.setSignatureType(signatureType);

        String jsonBody = objectMapper.writeValueAsString(new SynchronousSignEnvelope(request));
        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/synchronousSign"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyOperationTokenName);
        SynchronousSignResponse signResponse = readSynchronousSignResponse(response.getBody());
        return new SignResult(
                Base64.getDecoder().decode(signResponse.getSignature()),
                decodeOptionalBase64(signResponse.getPublicNonce()));
    }

    private SynchronousSignResponse readSynchronousSignResponse(String body) throws Exception {
        JsonNode root = objectMapper.readTree(body);
        JsonNode payload = root.has("signResponse") ? root.get("signResponse") : root;
        return objectMapper.treeToValue(payload, SynchronousSignResponse.class);
    }

    private byte[] decodeOptionalBase64(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Base64.getDecoder().decode(value);
    }

    private String mapSignatureAlgorithm(String algorithm) {
        if (algorithm == null) {
            return null;
        }
        return switch (algorithm) {
            case Algorithm.RS256, "SHA256withRSA" -> "SHA256_WITH_RSA";
            case Algorithm.RS384, "SHA384withRSA" -> "SHA384_WITH_RSA";
            case Algorithm.RS512, "SHA512withRSA" -> "SHA512_WITH_RSA";
            case Algorithm.ES256, "SHA256withECDSA" -> "SHA256_WITH_ECDSA";
            case Algorithm.ES384, "SHA384withECDSA" -> "SHA384_WITH_ECDSA";
            case Algorithm.ES512, "SHA512withECDSA" -> "SHA512_WITH_ECDSA";
            default -> algorithm;
        };
    }
}
