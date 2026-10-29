package com.securosys.hsm.provider.key;

import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurosysJceKeyProviderFactoryTest {

    @Test
    void marksProxyPasswordAsSecretSoKeycloakMasksItDuringExport() {
        SecurosysJceKeyProviderFactory factory = new SecurosysJceKeyProviderFactory();
        factory.init(null);

        ProviderConfigProperty proxyPassword = factory.getConfigProperties().stream()
                .filter(property -> SecurosysJceKeyProviderFactory.HSM_PROXY_PASSWORD.equals(property.getName()))
                .findFirst()
                .orElseThrow();

        assertTrue(proxyPassword.isSecret());
    }

    @Test
    void exposesAttestationKeyAsOptionalInAdminConsole() {
        SecurosysJceKeyProviderFactory factory = new SecurosysJceKeyProviderFactory();
        factory.init(null);

        ProviderConfigProperty attestationKey = factory.getConfigProperties().stream()
                .filter(property -> SecurosysJceKeyProviderFactory.HSM_ATTESTATION_KEY_NAME.equals(property.getName()))
                .findFirst()
                .orElseThrow();

        assertFalse(attestationKey.isRequired());
    }
}
