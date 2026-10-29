package com.securosys.hsm.client.jce;

import com.securosys.hsm.client.SigningKeyRequests;
import com.securosys.hsm.client.HsmKeyAttributes;
import com.securosys.hsm.dto.CreateKeyDto;
import com.securosys.hsm.exception.BusinessException;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JceClientSigningKeyRequestTest {

    @Test
    void createsRsa2048SigningKeyRequest() {
        CreateKeyDto request = SigningKeyRequests.create("key", "password", "RS256");

        assertEquals("RSA", request.getAlgorithm());
        assertEquals(2048, request.getKeySize());
        assertNull(request.getCurveOid());
        assertSigningOnly(request);
    }

    @Test
    void createsP256SigningKeyRequest() {
        CreateKeyDto request = SigningKeyRequests.create("key", "password", "ES256");

        assertEquals("EC", request.getAlgorithm());
        assertEquals("1.2.840.10045.3.1.7", request.getCurveOid());
        assertNull(request.getKeySize());
        assertSigningOnly(request);
    }

    @Test
    void rejectsUnsupportedSignatureAlgorithm() {
        assertThrows(BusinessException.class,
                () -> SigningKeyRequests.create("key", "password", "HS256"));
    }

    @Test
    void mapsJavaKeysWithoutAttestationData() throws Exception {
        java.security.KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        HsmKeyAttributes attributes = JceClient.keyAttributes("key", rsa.getPrivate(), rsa.getPublic());

        assertEquals("RSA", attributes.getAlgorithm());
        assertEquals("RSA", JceClient.parsePublicKey(attributes.getPublicKey()).getAlgorithm());
        assertNull(attributes.getXml());
        assertNull(attributes.getXmlSignature());
        assertNull(attributes.getAttestationKeyName());
    }

    private static void assertSigningOnly(CreateKeyDto request) {
        assertTrue(request.getAttributes().getSign());
        assertFalse(request.getAttributes().getDecrypt());
        assertFalse(request.getAttributes().getUnwrap());
        assertTrue(request.getAttributes().getSensitive());
        assertFalse(request.getAttributes().isExtractable());
        assertFalse(request.getAttributes().isDestroyable());
    }
}
