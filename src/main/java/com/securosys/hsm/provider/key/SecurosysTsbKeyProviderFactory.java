/**
 * Copyright (c)2026 Securosys SA, authors: Tomasz Madej
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
/**
 * Factory for SecurosysKeyProviderFactory.
 */

package com.securosys.hsm.provider.key;

import static org.keycloak.provider.ProviderConfigProperty.*;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.SecretKeyProviderUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory for SecurosysTsbKeyProviderFactory.
 */
public class SecurosysTsbKeyProviderFactory implements org.keycloak.keys.KeyProviderFactory<SecurosysTsbKeyProvider> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurosysTsbKeyProviderFactory.class);

    public static final String ID = "securosys-hsm-tsb";
    private static final String HELP_TEXT = "Use keys from securosys hsm using TSB";


    public static String ALGORITHM_KEY = "algorithm";
    ProviderConfigProperty ALGORITHM_PROPERTY = new ProviderConfigProperty(ALGORITHM_KEY, "Algorithm", "Intended algorithm for the key", "List",
            Algorithm.RS256,
            new String[]{
                    Algorithm.RS256,
                    Algorithm.ES256,
            });

    public static String TSB_URL = "tsbUrl";
    ProviderConfigProperty TSB_URL_PROPERTY = new ProviderConfigProperty(TSB_URL, "TSB URL", "Base URL of the TSB service", STRING_TYPE, null);

    public static String AUTH_METHOD = "authMethod";
    ProviderConfigProperty AUTH_METHOD_PROPERTY = new ProviderConfigProperty(AUTH_METHOD, "Authentication Method", "Authentication method. TOKEN requires Bearer Token. CERT requires mTLS P12 Path and mTLS P12 Password.", LIST_TYPE, "NONE",
            new String[]{
                    "NONE",
                    "TOKEN",
                    "CERT",
            });

    public static String BEARER_TOKEN = "bearerToken";
    ProviderConfigProperty BEARER_TOKEN_PROPERTY = new ProviderConfigProperty(BEARER_TOKEN, "Bearer Token", "Required when Authentication Method is TOKEN", PASSWORD, null);

    public static String MTLS_P12_PATH = "mtlsP12Path";
    ProviderConfigProperty MTLS_P12_PATH_PROPERTY = new ProviderConfigProperty(MTLS_P12_PATH, "mTLS P12 Path", "Required when Authentication Method is CERT. Path to the mTLS P12 certificate file.", STRING_TYPE, null);

    public static String MTLS_P12_PASSWORD = "mtlsP12Password";
    ProviderConfigProperty MTLS_P12_PASSWORD_PROPERTY = new ProviderConfigProperty(MTLS_P12_PASSWORD, "mTLS P12 Password", "Required when Authentication Method is CERT. Password for the mTLS P12 certificate file.", PASSWORD, null);

    public static String KEY_OPERATION_API_KEY = "keyOperationApiKey";
    ProviderConfigProperty KEY_OPERATION_API_KEY_PROPERTY = new ProviderConfigProperty(KEY_OPERATION_API_KEY, "Key Operation API Key", "API key for key operation calls", PASSWORD, null);

    public static String KEY_MANAGEMENT_API_KEY = "keyManagementApiKey";
    ProviderConfigProperty KEY_MANAGEMENT_API_KEY_PROPERTY = new ProviderConfigProperty(KEY_MANAGEMENT_API_KEY, "Key Management API Key", "API key for key management calls", PASSWORD, null);

    public static String KEY_LABEL = "keyLabel";
    ProviderConfigProperty KEY_LABEL_PROPERTY = new ProviderConfigProperty(KEY_LABEL, "Key Label", "Key label of the external key", STRING_TYPE, null);

    public static String KEY_PASSWORD = "keyPassword";
    ProviderConfigProperty KEY_PASSWORD_PROPERTY = new ProviderConfigProperty(KEY_PASSWORD, "Key Password", "Key Password of the external key", PASSWORD, null);


    private List<ProviderConfigProperty> configProperties;


    @Override
    public SecurosysTsbKeyProvider create(KeycloakSession session, ComponentModel model) {
        if (!Boolean.parseBoolean(model.getConfig().getFirst("enabled"))) {
            return null;
        }
        try {
            return new SecurosysTsbKeyProvider(session, model);
        } catch (Exception e) {
            LOGGER.error("Failed to create TSB key provider", e);
            return null;
        }
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper validation = SecretKeyProviderUtils.validateConfiguration(model);
        validation.checkRequired(ALGORITHM_PROPERTY);
        validation.checkRequired(TSB_URL_PROPERTY);
        validation.checkRequired(AUTH_METHOD_PROPERTY);
        validation.checkRequired(KEY_LABEL_PROPERTY);
        
        String authMethod = model.getConfig().getFirst(AUTH_METHOD);
        if ("TOKEN".equals(authMethod)) {
            validation.checkRequired(BEARER_TOKEN_PROPERTY);
        } else if ("CERT".equals(authMethod)) {
            validation.checkRequired(MTLS_P12_PATH_PROPERTY);
            validation.checkRequired(MTLS_P12_PASSWORD_PROPERTY);
        }
        
        model.put(Attributes.KID_KEY, KeycloakModelUtils.generateId());
    }

    @Override
    public void init(Config.Scope config) {
        configProperties = ProviderConfigurationBuilder.create()
                .property(Attributes.PRIORITY_PROPERTY)
                .property(Attributes.ENABLED_PROPERTY)
                .property(Attributes.ACTIVE_PROPERTY)
                .property(TSB_URL_PROPERTY)
                .property(AUTH_METHOD_PROPERTY)
                .property(BEARER_TOKEN_PROPERTY)
                .property(MTLS_P12_PATH_PROPERTY)
                .property(MTLS_P12_PASSWORD_PROPERTY)
                .property(KEY_OPERATION_API_KEY_PROPERTY)
                .property(KEY_MANAGEMENT_API_KEY_PROPERTY)
                .property(KEY_LABEL_PROPERTY)
                .property(KEY_PASSWORD_PROPERTY)
                .property(ALGORITHM_PROPERTY)
                .build();
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getHelpText() {
        return HELP_TEXT;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }
    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // TSB provider initialization if needed
        LOGGER.debug("TSB Key Provider Factory initialized");
    }
}
