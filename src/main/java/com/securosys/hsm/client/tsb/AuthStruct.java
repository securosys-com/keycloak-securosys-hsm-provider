// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

public class AuthStruct {
    private String appName;
    private String authType;
    private String certPath;
    private String keyPath;
    private String bearerToken;
    private String basicToken;
    private String username;
    private String password;
    private ApiKeyTypes apiKeys;
    private KeyPair applicationKeyPair;
    private ApiKeyTypesRetry currentApiKeyTypeIndex;

    public AuthStruct(String authType, String certPath, String keyPath, String bearerToken,
                      String basicToken, String username, String password, KeyPair applicationKeyPair,
                      ApiKeyTypes apiKeys, String appName) {
        this.authType = authType;
        this.certPath = certPath;
        this.keyPath = keyPath;
        this.bearerToken = bearerToken;
        this.basicToken = basicToken;
        this.username = username;
        this.password = password;
        this.applicationKeyPair = applicationKeyPair;
        this.apiKeys = apiKeys;
        this.appName = appName;
        this.currentApiKeyTypeIndex = new ApiKeyTypesRetry();
    }

    // Getters
    public String getAppName() { return appName; }
    public String getAuthType() { return authType; }
    public String getCertPath() { return certPath; }
    public String getKeyPath() { return keyPath; }
    public String getBearerToken() { return bearerToken; }
    public String getBasicToken() { return basicToken; }
    public String getUsername() { return username; }
    public String getPassword() { return password; }
    public ApiKeyTypes getApiKeys() { return apiKeys; }
    public KeyPair getApplicationKeyPair() { return applicationKeyPair; }
    public ApiKeyTypesRetry getCurrentApiKeyTypeIndex() { return currentApiKeyTypeIndex; }
}