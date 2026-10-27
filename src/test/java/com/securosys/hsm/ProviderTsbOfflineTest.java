/**
 * Copyright (c)2026 Securosys SA
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
package com.securosys.hsm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;

import com.securosys.hsm.provider.key.SecurosysTsbKeyProvider;
import com.securosys.hsm.provider.key.SecurosysTsbKeyProviderFactory;
import com.securosys.hsm.provider.signature.SecurosysSignatureSignerContext;
import com.sun.net.httpserver.HttpServer;

/**
 * TSB key provider against a fake TSB on localhost: no HSM, no Keycloak container.
 */
public class ProviderTsbOfflineTest {
    private static final String LABEL = "hsm-key";

    private static KeyPair keyPair;
    private static String publicKey;
    private static HttpServer tsb;
    private static String url;
    private static final AtomicInteger calls = new AtomicInteger();
    private static final SecurosysTsbKeyProviderFactory factory = new SecurosysTsbKeyProviderFactory();

    @BeforeAll
    static void startFakeTsb() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = generator.generateKeyPair();
        publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());

        tsb = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        tsb.createContext("/v1/key/attributes", exchange -> {
            calls.incrementAndGet();
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            boolean known = body.contains("\"" + LABEL + "\"");
            byte[] out = (known
                    ? "{\"json\":{\"label\":\"" + LABEL + "\",\"algorithm\":\"EC\",\"publicKey\":\"" + publicKey + "\"}}"
                    : "{\"errorCode\":650,\"reason\":\"res.error.key.not.existent\"}").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(known ? 200 : 404, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        tsb.createContext("/v1/synchronousSign", exchange -> {
            calls.incrementAndGet();
            try {
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String payload = body.replaceAll(".*\"payload\":\"([^\"]+)\".*", "$1");
                Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
                signature.initSign(keyPair.getPrivate());
                signature.update(Base64.getDecoder().decode(payload));
                byte[] out = ("{\"signature\":\"" + Base64.getEncoder().encodeToString(signature.sign()) + "\"}")
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, out.length);
                exchange.getResponseBody().write(out);
            } catch (Exception e) {
                exchange.sendResponseHeaders(500, -1);
            }
            exchange.close();
        });
        tsb.start();
        url = "http://127.0.0.1:" + tsb.getAddress().getPort();
        factory.init(null);
    }

    @AfterAll
    static void stopFakeTsb() {
        tsb.stop(0);
    }

    @Test
    void saveStoresPublicKeyAndStableKid() {
        ComponentModel model = model(" " + url + " ", LABEL, "ES256");
        factory.validateConfiguration(null, null, model);
        assertEquals(url, model.get(SecurosysTsbKeyProviderFactory.TSB_URL));
        assertEquals(publicKey, model.get(SecurosysTsbKeyProviderFactory.PUBLIC_KEY));
        String kid = model.get("kid");
        factory.validateConfiguration(null, null, model);
        assertEquals(kid, model.get("kid"), "saving again must keep the kid of the same key");
    }

    @Test
    void saveRejectsMissingKeyAndWrongKeyType() {
        assertThrows(ComponentValidationException.class,
                () -> factory.validateConfiguration(null, null, model(url, "missing", "ES256")));
        assertThrows(ComponentValidationException.class,
                () -> factory.validateConfiguration(null, null, model(url, LABEL, "RS256")));
    }

    @Test
    void signsWithoutReadingTheKeyAgain() throws Exception {
        ComponentModel model = model(url, LABEL, "ES256");
        factory.validateConfiguration(null, null, model);
        int before = calls.get();
        KeyWrapper key = new SecurosysTsbKeyProvider(null, model).getKeysStream().findFirst().orElseThrow();
        assertEquals(before, calls.get(), "the key comes from the saved public key, not from the TSB");

        byte[] data = "header.payload".getBytes(StandardCharsets.UTF_8);
        byte[] signature = new SecurosysSignatureSignerContext(key).sign(data);
        Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(keyPair.getPublic());
        verifier.update(data);
        assertTrue(verifier.verify(signature));
    }

    @Test
    void unreachableTsbKeepsTheKeyAndFailsFast() throws Exception {
        // Nothing listens on this port: the key is still offered (no software fallback key),
        // signing fails, and the next attempt fails at once instead of waiting again.
        ComponentModel model = model("http://127.0.0.1:9", LABEL, "ES256");
        model.put(SecurosysTsbKeyProviderFactory.PUBLIC_KEY, publicKey);
        model.put("kid", "offline");
        KeyWrapper key = new SecurosysTsbKeyProvider(null, model).getKeysStream().findFirst().orElseThrow();
        assertNotNull(key.getPublicKey());

        byte[] data = "header.payload".getBytes(StandardCharsets.UTF_8);
        assertThrows(SignatureException.class, () -> new SecurosysSignatureSignerContext(key).sign(data));
        long start = System.currentTimeMillis();
        SignatureException again = assertThrows(SignatureException.class,
                () -> new SecurosysSignatureSignerContext(key).sign(data));
        assertTrue(System.currentTimeMillis() - start < 1000, "second attempt must not reach the TSB");
        assertTrue(again.getMessage().contains("unreachable"), again.getMessage());
    }

    private static ComponentModel model(String tsbUrl, String label, String algorithm) {
        ComponentModel model = new ComponentModel();
        model.setConfig(new MultivaluedHashMap<>());
        model.put("enabled", "true");
        model.put("active", "true");
        model.put("priority", "200");
        model.put(SecurosysTsbKeyProviderFactory.TSB_URL, tsbUrl);
        model.put(SecurosysTsbKeyProviderFactory.AUTH_METHOD, "NONE");
        model.put(SecurosysTsbKeyProviderFactory.KEY_LABEL, label);
        model.put(SecurosysTsbKeyProviderFactory.ALGORITHM_KEY, algorithm);
        return model;
    }
}
