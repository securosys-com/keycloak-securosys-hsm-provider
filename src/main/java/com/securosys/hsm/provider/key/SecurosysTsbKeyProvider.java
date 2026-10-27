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

import java.security.KeyException;
import java.util.Collections;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmClientFactory;
import com.securosys.hsm.client.HsmKeyAttributes;
import com.securosys.hsm.client.config.Config;
import com.securosys.hsm.client.config.TsbConfig;

/**
 * Key provider helper for SecurosysKeyProvider.
 */
public class SecurosysTsbKeyProvider implements KeyProvider {
    private static final String NOTE_KEY = SecurosysKeyWrapper.class.getName();

    private final Config config;
    private final HsmClient hsmClient;
    private final KeyStatus status;
    private final String kid;
    private final long providerPriority;
    private final String algorithm;
    private final SecurosysKeyWrapper key;
    private final String label;
    private final String password;

    public SecurosysTsbKeyProvider(KeycloakSession session, ComponentModel model) throws KeyException {
        TsbConfig tsbConfig = TsbConfig.builder()
                .tsbUrl(model.get(SecurosysTsbKeyProviderFactory.TSB_URL))
                .auth(model.get(SecurosysTsbKeyProviderFactory.AUTH_METHOD))
                .bearerToken(model.get(SecurosysTsbKeyProviderFactory.BEARER_TOKEN))
                .mtlsP12Path(model.get(SecurosysTsbKeyProviderFactory.MTLS_P12_PATH))
                .mtlsP12Password(model.get(SecurosysTsbKeyProviderFactory.MTLS_P12_PASSWORD))
                .keyOperationApiKey(model.get(SecurosysTsbKeyProviderFactory.KEY_OPERATION_API_KEY))
                .keyManagementApiKey(model.get(SecurosysTsbKeyProviderFactory.KEY_MANAGEMENT_API_KEY))
                .build();
        tsbConfig.setKeyLabel(model.get(SecurosysTsbKeyProviderFactory.KEY_LABEL));
        tsbConfig.setKeyPassword(model.get(SecurosysTsbKeyProviderFactory.KEY_PASSWORD));
        this.config = tsbConfig;
        this.hsmClient = createHsmClient(tsbConfig);
        this.kid = model.get(Attributes.KID_KEY);

        this.status = KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
        this.providerPriority = model.get(Attributes.PRIORITY_KEY, 0L);
        this.algorithm = model.get(SecurosysTsbKeyProviderFactory.ALGORITHM_KEY);
        this.label = model.get(SecurosysTsbKeyProviderFactory.KEY_LABEL);
        this.password = model.get(SecurosysTsbKeyProviderFactory.KEY_PASSWORD);
        if (model.hasNote(NOTE_KEY)) {
            key = model.getNote(NOTE_KEY);
        } else {
            key = createKeyWrapper(session, model);
            model.setNote(NOTE_KEY, key);
        }
    }

    private HsmClient createHsmClient(TsbConfig config) throws KeyException {
        try {
            return HsmClientFactory.create(config);
        } catch (Exception e) {
            throw new KeyException("Failed to initialize HSM client", e);
        }
    }

    private void disablePlugin(KeycloakSession session,ComponentModel model){
        model.put("enabled", "false");
        model.put("active", "false");
        model.getConfig().put("enabled", Collections.singletonList("false"));
        model.getConfig().put("active", Collections.singletonList("false"));
        session.getContext().getRealm().updateComponent(model);

    }


    private SecurosysKeyWrapper createKeyWrapper(KeycloakSession session, ComponentModel model) throws KeyException {
        HsmKeyAttributes keyAttributes;
        try {
            keyAttributes = hsmClient.fetchKeyAttributes(label, password);
        } catch (Exception e) {
            throw new KeyException("Failed to retrieve key attributes for '" + label + "'", e);
        }

        String keyAlgorithm = keyAttributes.getAlgorithm();
        if (!"RSA".equals(keyAlgorithm) && !"EC".equals(keyAlgorithm)) {
            this.disablePlugin(session, model);
            throw new KeyException("Unexpected key algorithm " + keyAlgorithm + " for '" + label + "'. Supported: RSA/EC");
        }

        SecurosysKeyWrapper securosysKeyWrapper = new SecurosysKeyWrapper();
        SecurosysProxyPrivateKey proxyPrivateKey = new SecurosysProxyPrivateKey(label, keyAlgorithm, config);
        securosysKeyWrapper.setPrivateKey(proxyPrivateKey);
        try {
            securosysKeyWrapper.setPublicKey(hsmClient.getPublicKey(keyAttributes));
        } catch (Exception e) {
            throw new KeyException("Failed to parse public key for '" + label + "'", e);
        }
        securosysKeyWrapper.setUse(KeyUse.SIG);
        securosysKeyWrapper.setAlgorithm(algorithm);
        securosysKeyWrapper.setStatus(status);
        securosysKeyWrapper.setLabel(label);
        securosysKeyWrapper.setPassword(password);
        securosysKeyWrapper.setKid(SecurosysTsbKeyProviderFactory.ID + "_" + kid);
        securosysKeyWrapper.setProviderPriority(this.providerPriority);
        securosysKeyWrapper.setProviderId(model.getId());
        securosysKeyWrapper.setHsmConfig(config);

        if ("EC".equals(keyAlgorithm)) {
            securosysKeyWrapper.setType(KeyType.EC);
            if (algorithm.contains("RS")) {
                this.disablePlugin(session, model);
                throw new KeyException("Unexpected signature algorithm '" + algorithm + "' for '" + label + "' EC key");
            }
        } else if ("RSA".equals(keyAlgorithm)) {
            securosysKeyWrapper.setType(KeyType.RSA);
            if (algorithm.contains("ES")) {
                this.disablePlugin(session, model);
                throw new KeyException("Unexpected signature algorithm '" + algorithm + "' for '" + label + "' RSA key");
            }
        }

        return securosysKeyWrapper;
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
        return Stream.of(key);
    }
}
