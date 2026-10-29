package com.securosys.hsm.provider.key;

import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmKeyAttributes;
import com.securosys.hsm.dto.SignResult;
import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurosysJceKeyProviderAutoGenerationTest {

    @Test
    void usesExistingKeyWithoutGeneratingAnotherOne() throws Exception {
        HsmKeyAttributes existing = attributes("RSA");
        FakeClient client = new FakeClient(existing, null);

        assertSame(existing, SecurosysJceKeyProvider.fetchOrCreateSigningKey(client, "key", "", "RS256"));
        assertEquals(0, client.creates.get());
    }

    @Test
    void generatesOnlyWhenKeyDoesNotExist() throws Exception {
        HsmKeyAttributes generated = attributes("RSA");
        FakeClient client = new FakeClient(null,
                new BusinessException("missing", BusinessReason.ERROR_KEY_NOT_EXISTENT));
        client.generated = generated;

        assertSame(generated, SecurosysJceKeyProvider.fetchOrCreateSigningKey(client, "key", "", "RS256"));
        assertEquals(1, client.creates.get());
    }

    @Test
    void doesNotGenerateForAuthenticationOrConnectionErrors() {
        FakeClient client = new FakeClient(null,
                new BusinessException("password", BusinessReason.ERROR_KEY_PASSWORD_MISMATCH));

        assertThrows(BusinessException.class,
                () -> SecurosysJceKeyProvider.fetchOrCreateSigningKey(client, "key", "", "RS256"));
        assertEquals(0, client.creates.get());
    }

    private static HsmKeyAttributes attributes(String algorithm) {
        return new HsmKeyAttributes("key", algorithm, "", null, null, null);
    }

    private static final class FakeClient implements HsmClient {
        private final HsmKeyAttributes existing;
        private final BusinessException fetchError;
        private final AtomicInteger creates = new AtomicInteger();
        private HsmKeyAttributes generated;

        private FakeClient(HsmKeyAttributes existing, BusinessException fetchError) {
            this.existing = existing;
            this.fetchError = fetchError;
        }

        @Override
        public HsmKeyAttributes fetchKeyAttributes(String keyLabel, String keyPassword) {
            if (fetchError != null) {
                throw fetchError;
            }
            return existing;
        }

        @Override
        public HsmKeyAttributes createSigningKey(String keyLabel, String keyPassword, String signatureAlgorithm) {
            creates.incrementAndGet();
            return generated;
        }

        @Override
        public PublicKey getPublicKey(HsmKeyAttributes keyAttributes) {
            throw new UnsupportedOperationException();
        }

        @Override
        public SignResult createSignature(byte[] payload, String keyName, String password, String algorithm,
                String signatureType) {
            throw new UnsupportedOperationException();
        }
    }
}
