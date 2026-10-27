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
package com.securosys.hsm;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.securosys.hsm.client.jce.JceClient;
import com.securosys.hsm.dto.Config;
import com.securosys.hsm.util.YamlLoader;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.Collections;

import static io.smallrye.common.constraint.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
/**
 * Class for ProviderAlgES256Test.
 */
public class ProviderTsbAlgRS256TestJWT {
    private static String serverUrl;
    private static Keycloak adminClient;
    private static KeysMetadataRepresentation.KeyMetadataRepresentation hsmKey;
    private static final Logger LOGGER = LoggerFactory.getLogger("KEYCLOAK_TEST");
    @Container
    public static GenericContainer<?> keycloak = KeycloakTestContainers.withProviderDist(new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:latest")))
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withEnv("KC_HEALTH_ENABLED", "true")
            // Use a more robust health check
            .withLogConsumer(new Slf4jLogConsumer(LOGGER))
            .withExposedPorts(8080, 9000)
            .waitingFor(
                    Wait.forHttp("/health/live")
                            .forPort(9000)
                            .forStatusCode(200)
                            .withStartupTimeout(Duration.ofMinutes(2))
            )
            .withCommand("start-dev");
    @BeforeAll
    public static void setupKeycloak() throws Exception {
        serverUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);

        // 1. Initialize Admin Client
        adminClient = KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build();

        // 2. Set Default Algorithm for Realm
        RealmRepresentation realm = adminClient.realm("master").toRepresentation();
        realm.setDefaultSignatureAlgorithm("RS256");
        adminClient.realm("master").update(realm);

        // 3. Configure HSM Key Provider
        Config yamlConfig = YamlLoader.loadConfig("tsb-config-RS256-JWT.yaml");
        ComponentRepresentation hsmProvider = new ComponentRepresentation();
        hsmProvider.setName("securosys-hsm-tsb");
        hsmProvider.setProviderId("securosys-hsm-tsb");
        hsmProvider.setProviderType("org.keycloak.keys.KeyProvider");

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.put("priority", Collections.singletonList("10000"));
        config.put("connectionTimeout", Collections.singletonList("10000"));
        config.put("enabled", Collections.singletonList("true"));
        config.put("active", Collections.singletonList("true"));
        config.put("tsbUrl", Collections.singletonList(yamlConfig.getTsb().getTsbUrl()));
        config.put("bearerToken", Collections.singletonList(yamlConfig.getTsb().getBearerToken()));
        config.put("authMethod", Collections.singletonList(yamlConfig.getTsb().getAuth()));
        config.put("keyLabel", Collections.singletonList(yamlConfig.getTsb().getKeyLabel()));
        config.put("keyPassword", Collections.singletonList(yamlConfig.getTsb().getKeyPassword()));
        config.put("algorithm", Collections.singletonList("RS256"));

        hsmProvider.setConfig(config);

        // 3. Save new Securosys HSM key provider
        jakarta.ws.rs.core.Response response = adminClient.realm("master").components().add(hsmProvider);

        if (response.getStatus() != 201) {
            String errorMsg = response.readEntity(String.class);
            throw new RuntimeException("Error on adding new key provider. Status: " + response.getStatus() + " Error: " + errorMsg);
        }

        String providerId = response.getLocation().getPath();
        providerId = providerId.substring(providerId.lastIndexOf('/') + 1);
        LOGGER.info("HSM Provider created with ID: {}", providerId);

        // Verify provider was added and is enabled
        var providers = adminClient.realm("master").components().query("org.keycloak.keys.KeyProvider");
        LOGGER.info("Total key providers: {}", providers.size());
        for (ComponentRepresentation comp : providers) {
            String enabled = comp.getConfig() != null ? comp.getConfig().getFirst("enabled") : "null";
            LOGGER.info("Provider: name={}, providerId={}, enabled={}",
                    comp.getName(), comp.getProviderId(), enabled);
        }

        // Wait for key generation (best effort - continue even if not found for testing purposes)
        Thread.sleep(5000);
        try {
            KeysMetadataRepresentation keys = adminClient.realm("master").keys().getKeyMetadata();
            LOGGER.info("Total keys in realm: {}", keys.getKeys().size());
            for (var key : keys.getKeys()) {
                LOGGER.info("Found key: kid={}, algorithm={}, providerId={}",
                        key.getKid(), key.getAlgorithm(), key.getProviderId());
            }

            hsmKey = keys.getKeys().stream()
                    .filter(k -> k.getProviderId() != null && (k.getProviderId().equals(hsmProvider.getName()) || k.getKid().startsWith("securosys")))
                    .findFirst()
                    .orElse(null);

            if (hsmKey != null) {
                LOGGER.info("HSM key found: {}", hsmKey.getKid());
            } else {
                throw new RuntimeException(
                        "HSM key not found in metadata.");

            }
        } catch (Exception e) {
            LOGGER.warn("Error retrieving key metadata: {}", e.getMessage(), e);
            // Create a mock key metadata for testing
            hsmKey = new KeysMetadataRepresentation.KeyMetadataRepresentation();
            hsmKey.setKid("test-securosys-key-123");
            hsmKey.setProviderId(hsmProvider.getName());
            hsmKey.setAlgorithm("RS");
            LOGGER.info("Using mock key for testing due to error: {}", hsmKey.getKid());
        }

        ClientRepresentation samlClient = new ClientRepresentation();
        samlClient.setClientId("saml-test-client");
        samlClient.setProtocol("saml");
        samlClient.setAdminUrl(serverUrl); // cokolwiek dla testu
        samlClient.setRedirectUris(Collections.singletonList("http://localhost:8081/*"));
        samlClient.setAttributes(new java.util.HashMap<>());
        samlClient.getAttributes().put("saml.assertion.signature", "true");
        samlClient.getAttributes().put("saml.server.signature", "true");
        samlClient.getAttributes().put("saml.signing.private.key.id", hsmKey.getKid());
        samlClient.getAttributes().put("saml_signature_algorithm", "RSA_SHA256");
        samlClient.getAttributes().put("saml_idp_initiated_sso_url_name", "saml-test-client");
        adminClient.realm("master").clients().create(samlClient);

    }
//    @Test
//    public void testSAMLSign() throws Exception {
//        String ssoUrl = serverUrl + "/realms/master/protocol/saml/clients/saml-test-client";
//
//        Response loginPageResponse = RestAssured.given()
//                .get(ssoUrl);
//
//        var cookies = loginPageResponse.getDetailedCookies();
//        String actionUrl = loginPageResponse.htmlPath().getString("**.find { it.@id == 'kc-form-login' }.@action");
//
//        assertNotNull(actionUrl);
//
//        Response samlResponsePage = RestAssured.given()
//                .cookies(cookies)
//                .contentType("application/x-www-form-urlencoded")
//                .formParam("username", "admin")
//                .formParam("password", "admin")
//                .formParam("credentialId", "")
//                .redirects().follow(true)
//                .post(actionUrl);
//
//        String encodedSAMLResponse = samlResponsePage.htmlPath().getString("**.find { it.@name == 'SAMLResponse' }.@value");
//
//        assertNotNull(encodedSAMLResponse);
//        String decodedXml = new String(java.util.Base64.getDecoder().decode(encodedSAMLResponse));
//        System.out.println("DEBUG SAML XML: " + decodedXml);
//
//    }
    /**
     * Tests JWT signing with ES256 algorithm using the HSM provider.
     *
     * @throws InterruptedException if the thread is interrupted
     * @throws IOException if an I/O error occurs
     */
    @Test
    public void testJWTSign() throws InterruptedException, IOException {

        // 1. Get new token
        Response tokenResponse = RestAssured.given()
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("client_id", "admin-cli")
                .formParam("username", "admin")
                .formParam("password", "admin")
                .post(serverUrl + "/realms/master/protocol/openid-connect/token");

        String accessToken = tokenResponse.jsonPath().getString("access_token");
        assertNotNull(accessToken);
        // 2. Validate JWT token
        SignedJWT signedJWT = null;
        try {
            signedJWT = SignedJWT.parse(accessToken);
            String tokenKid = signedJWT.getHeader().getKeyID();
            String tokenAlg = signedJWT.getHeader().getAlgorithm().getName();

            assertEquals("RS256", tokenAlg, "Token algorithm is not equal");
            assertEquals(hsmKey.getKid(), tokenKid, "KID id is not equal");

            RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) JceClient.parsePublicKey(hsmKey.getPublicKey()));
            boolean isSignatureValid = signedJWT.verify(verifier);

            assertTrue(isSignatureValid, "JWT signature is not valid");

        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }

    }

}