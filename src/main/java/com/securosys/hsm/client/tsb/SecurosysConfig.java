// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

/**
 * SecurosysConfig includes the minimum configuration
 * required to instantiate a new Securosys client.
 */
public class SecurosysConfig {
    private String auth;
    private String bearerToken;
    private String username;
    private String password;
    private String basicToken;
    private String certPath;
    private String keyPath;
    private String restApi;
    private String appName;
    private String applicationKeyPair;
    private String apiKeys;

    // Getters and setters
    public String getAuth() { return auth; }
    public void setAuth(String auth) { this.auth = auth; }

    public String getBearerToken() { return bearerToken; }
    public void setBearerToken(String bearerToken) { this.bearerToken = bearerToken; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getBasicToken() { return basicToken; }
    public void setBasicToken(String basicToken) { this.basicToken = basicToken; }

    public String getCertPath() { return certPath; }
    public void setCertPath(String certPath) { this.certPath = certPath; }

    public String getKeyPath() { return keyPath; }
    public void setKeyPath(String keyPath) { this.keyPath = keyPath; }

    public String getRestApi() { return restApi; }
    public void setRestApi(String restApi) { this.restApi = restApi; }

    public String getAppName() { return appName; }
    public void setAppName(String appName) { this.appName = appName; }

    public String getApplicationKeyPair() { return applicationKeyPair; }
    public void setApplicationKeyPair(String applicationKeyPair) { this.applicationKeyPair = applicationKeyPair; }

    public String getApiKeys() { return apiKeys; }
    public void setApiKeys(String apiKeys) { this.apiKeys = apiKeys; }
}