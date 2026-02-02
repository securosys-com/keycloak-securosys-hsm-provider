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
package com.securosys.hsm.provider.key;

import com.securosys.hsm.provider.signature.SecurosysProvider;
import com.securosys.primus.jce.PrimusLoginException;
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

import java.security.KeyException;
import java.security.Security;
import java.util.Collections;
import java.util.List;

import static org.keycloak.provider.ProviderConfigProperty.PASSWORD;
import static org.keycloak.provider.ProviderConfigProperty.STRING_TYPE;

public class SecurosysKeyProviderFactory implements org.keycloak.keys.KeyProviderFactory<SecurosysKeyProvider> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SecurosysKeyProviderFactory.class);

    public static final String ID = "securosys-hsm";
    private static final String HELP_TEXT = "Use keys from securosys hsm";


    public static String ALGORITHM_KEY = "algorithm";
    ProviderConfigProperty ALGORITHM_PROPERTY = new ProviderConfigProperty(ALGORITHM_KEY, "Algorithm", "Intended algorithm for the key", "List",
            Algorithm.RS256,
            new String[]{
                    Algorithm.RS256,
                    Algorithm.ES256,
            });
    public static String HSM_CONNECTION_TIMEOUT = "connectionTimeout";
    ProviderConfigProperty HSM_CONNECTION_TIMEOUT_PROPERTY = new ProviderConfigProperty(HSM_CONNECTION_TIMEOUT, "Connection timeout", "Timeout in ms, when disable provider to unfreeze UI", STRING_TYPE, 10000+"");

    public static String HSM_PORT = "hsmPort";
    ProviderConfigProperty HSM_PORT_PROPERTY = new ProviderConfigProperty(HSM_PORT, "HSM Port", "HSM port to connect to HSM. Can be added more using ',' as separator", STRING_TYPE, null);

    public static String HSM_HOST = "hsmHost";
    ProviderConfigProperty HSM_HOST_PROPERTY = new ProviderConfigProperty(HSM_HOST, "HSM Host", "HSM host to connect to HSM. Can be added more using ',' as separator", STRING_TYPE, null);

    public static String HSM_USER = "hsmUser";
    ProviderConfigProperty HSM_USER_PROPERTY = new ProviderConfigProperty(HSM_USER, "HSM User", "HSM user to connect to HSM", STRING_TYPE, null);
    public static String HSM_SETUP_PASSWORD = "hsmSetupPassword";
    ProviderConfigProperty HSM_SETUP_PASSWORD_PROPERTY = new ProviderConfigProperty(HSM_SETUP_PASSWORD, "HSM Setup Password", "HSM setup password to connect to HSM. This property will be use only once, after that Provider will use secret", PASSWORD, null);

    public static String HSM_PROXY_USER = "hsmProxyUser";
    ProviderConfigProperty HSM_PROXY_USER_PROPERTY = new ProviderConfigProperty(HSM_PROXY_USER, "HSM Proxy User", "HSM proxy user to connect to HSM", STRING_TYPE, null);
    public static String HSM_PROXY_PASSWORD = "hsmProxyPassword";
    ProviderConfigProperty HSM_PROXY_PASSWORD_PROPERTY = new ProviderConfigProperty(HSM_PROXY_PASSWORD, "HSM Proxy Password", "HSM proxy password to connect to HSM", PASSWORD, null);

    public static String HSM_ATTESTATION_KEY_NAME = "attestationKeyName";
    ProviderConfigProperty HSM_ATTESTATION_KEY_NAME_PROPERTY = new ProviderConfigProperty(HSM_ATTESTATION_KEY_NAME, "HSM attestation key name", "HSM attestation key name", STRING_TYPE, null);
    public static String HSM_SECRET_PATH = "hsmSecretPath";
    ProviderConfigProperty HSM_SECRET_PATH_PROPERTY = new ProviderConfigProperty(HSM_SECRET_PATH, "HSM Secret Path", "Path, where will be generated .secret", STRING_TYPE, null);

    public static String KEY_LABEL = "keyLabel";
    ProviderConfigProperty KEY_LABEL_PROPERTY = new ProviderConfigProperty(KEY_LABEL, "Key Label", "Key label of the external key", STRING_TYPE, null);
    public static String KEY_PASSWORD = "keyPassword";
    ProviderConfigProperty KEY_PASSWORD_PROPERTY = new ProviderConfigProperty(KEY_PASSWORD, "Key Password", "Key Password of the external key", PASSWORD, null);


    private List<ProviderConfigProperty> configProperties;


    @Override
    public SecurosysKeyProvider create(KeycloakSession session, ComponentModel model) {
        if (!Boolean.parseBoolean(model.getConfig().getFirst("enabled"))) {
            return null;
        }
        try {
            return new SecurosysKeyProvider(session,model);
        } catch (PrimusLoginException e) {
            if (e.getMessage().contains("java.net.ConnectException: Connection timed out")||e.getMessage().contains("java.nio.channels.ClosedByInterruptException")) {
                model.put("enabled", "false");
                model.put("active", "false");
                model.getConfig().put("enabled", Collections.singletonList("false"));
                model.getConfig().put("active", Collections.singletonList("false"));
                session.getContext().getRealm().updateComponent(model);

                LOGGER.error("HSM Timeout detected. Provider disabled to prevent UI freeze.");
            }
            return null;
        } catch (KeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
        ConfigurationValidationHelper validation = SecretKeyProviderUtils.validateConfiguration(model);
        validation.checkRequired(ALGORITHM_PROPERTY);
        validation.checkRequired(HSM_HOST_PROPERTY);
        validation.checkRequired(HSM_PORT_PROPERTY);
        validation.checkRequired(HSM_USER_PROPERTY);
        validation.checkRequired(HSM_SETUP_PASSWORD_PROPERTY);
        validation.checkRequired(HSM_ATTESTATION_KEY_NAME_PROPERTY);
        validation.checkRequired(HSM_SECRET_PATH_PROPERTY);
        validation.checkRequired(KEY_LABEL_PROPERTY);
        model.put(Attributes.KID_KEY, KeycloakModelUtils.generateId());
    }

    @Override
    public void init(Config.Scope config) {
        configProperties = ProviderConfigurationBuilder.create()
                .property(Attributes.PRIORITY_PROPERTY)
                .property(Attributes.ENABLED_PROPERTY)
                .property(Attributes.ACTIVE_PROPERTY)
                .property(HSM_HOST_PROPERTY)
                .property(HSM_PORT_PROPERTY)
                .property(HSM_USER_PROPERTY)
                .property(HSM_SETUP_PASSWORD_PROPERTY)
                .property(HSM_PROXY_USER_PROPERTY)
                .property(HSM_PROXY_PASSWORD_PROPERTY)
                .property(HSM_ATTESTATION_KEY_NAME_PROPERTY)
                .property(HSM_SECRET_PATH_PROPERTY)
                .property(HSM_CONNECTION_TIMEOUT_PROPERTY)
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
        SecurosysProvider jcaProvider = new SecurosysProvider(null);
        if (Security.getProvider(jcaProvider.getName()) == null) {
            Security.insertProviderAt(jcaProvider, 1);
        }
    }
}