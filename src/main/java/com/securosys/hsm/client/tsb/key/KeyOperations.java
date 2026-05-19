// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.key;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;

import com.fasterxml.jackson.databind.JsonNode;
import com.securosys.hsm.client.tsb.AuthStruct;
import com.securosys.hsm.client.tsb.Client;
import com.securosys.hsm.client.tsb.ResponseData;

/**
 * Adds key-management methods to TSBClient through inheritance.
 */
public class KeyOperations extends Client {
    protected KeyOperations(String hostURL, HttpClient httpClient, AuthStruct auth) {
        super(hostURL, httpClient, auth);
    }

    /**
     * Get key attributes.
     */
    public KeyAttributes getKeyAttributes(String keyLabel, String keyPassword) throws Exception {
        java.util.Map<String, String> body = new java.util.HashMap<>();
        body.put("label", keyLabel);
        body.put("password", keyPassword);
        String jsonBody = objectMapper.writeValueAsString(body);

        HttpRequest httpRequest = HttpRequest.newBuilder()
            .uri(URI.create(getHostURL() + "/v1/key/attributes"))
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build();

        ResponseData response = doRequest(httpRequest, KeyManagementTokenName);
        JsonNode root = objectMapper.readTree(response.getBody());
        if (root.has("json") && root.get("json").isObject()) {
            KeyAttributes keyAttributes = objectMapper.treeToValue(root.get("json"), KeyAttributes.class);
            if (root.has("xml")) {
                keyAttributes.setXml(root.get("xml").asText(null));
            }
            if (root.has("xmlSignature")) {
                keyAttributes.setXmlSignature(root.get("xmlSignature").asText(null));
            }
            if (root.has("attestationKeyName")) {
                keyAttributes.setAttestationKeyName(root.get("attestationKeyName").asText(null));
            }
            return keyAttributes;
        }
        return objectMapper.readValue(response.getBody(), KeyAttributes.class);
    }
}
