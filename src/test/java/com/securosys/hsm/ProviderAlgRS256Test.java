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
import com.securosys.hsm.dto.Config;
import com.securosys.hsm.provider.key.SecurosysKeyProviderFactory;
import com.securosys.hsm.service.HsmService;
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
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Collections;

import static io.smallrye.common.constraint.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
public class ProviderAlgRS256Test {

    private static String serverUrl;
    private static Keycloak adminClient;
    private static KeysMetadataRepresentation.KeyMetadataRepresentation hsmKey;

    @Container
    public static GenericContainer<?> keycloak = new GenericContainer<>(DockerImageName.parse("quay.io/keycloak/keycloak:26.0"))
            .withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .withCopyFileToContainer(
                    MountableFile.forHostPath("./build/libs/keycloak-securosys-hsm-provider-1.0.0-all.jar"),"/opt/keycloak/providers/keycloak-securosys-hsm-provider.jar"
            )
            .withCopyFileToContainer(
                    MountableFile.forClasspathResource("/.secret"),"/opt/keycloak/providers/.secret"
            )
            .withCreateContainerCmdModifier(cmd -> cmd.withUser("root")) // Uruchom jako root, żeby zmienić uprawnienia
            .waitingFor(Wait.forHttp("/").forStatusCode(200));
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
        Config yamlConfig = YamlLoader.loadConfig("hsm-config-RS256.yaml");
        ComponentRepresentation hsmProvider = new ComponentRepresentation();
        hsmProvider.setName("securosys-hsm-provider");
        hsmProvider.setProviderId("securosys-hsm");
        hsmProvider.setProviderType("org.keycloak.keys.KeyProvider");

        MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
        config.put("priority", Collections.singletonList("10000"));
        config.put("connectionTimeout", Collections.singletonList("10000"));
        config.put("enabled", Collections.singletonList("true"));
        config.put("active", Collections.singletonList("true"));
        config.put("hsmHost", Collections.singletonList(yamlConfig.getHsm().getHost()));
        config.put("hsmPort", Collections.singletonList(yamlConfig.getHsm().getPort()+""));
        config.put("hsmUser", Collections.singletonList(yamlConfig.getHsm().getUser()));
        config.put("hsmSetupPassword", Collections.singletonList(yamlConfig.getHsm().getSetupPassword()));
        config.put("hsmProxyUser", Collections.singletonList(yamlConfig.getHsm().getProxyUser()));
        config.put("hsmProxyPassword", Collections.singletonList(yamlConfig.getHsm().getProxyPassword()));
        config.put("attestationKeyName", Collections.singletonList(yamlConfig.getHsm().getAttestationKeyName()));
        config.put("hsmSecretPath", Collections.singletonList(yamlConfig.getHsm().getSecretPath()));
        config.put("keyLabel", Collections.singletonList(yamlConfig.getHsm().getKeyLabel()));
        config.put("keyPassword", Collections.singletonList(yamlConfig.getHsm().getKeyPassword()));
        config.put("algorithm", Collections.singletonList("RS256"));

        hsmProvider.setConfig(config);

        // 3. Save new Securosys HSM key provider
        jakarta.ws.rs.core.Response response = adminClient.realm("master").components().add(hsmProvider);

        if (response.getStatus() != 201) {
            String errorMsg = response.readEntity(String.class);
            throw new RuntimeException("Error on adding new key provider. Status: " + response.getStatus());
        }
        Thread.sleep(5000);
        adminClient.realm("master").toRepresentation();
        KeysMetadataRepresentation keys = adminClient.realm("master").keys().getKeyMetadata();
        // 4. Search for new generated key
        Thread.sleep(5000);
        keys.getKeys().stream()
                .filter(k -> k.getKid().startsWith(SecurosysKeyProviderFactory.ID))
                .findFirst()
                .orElseThrow(() -> {
                    return new RuntimeException("Cannot find new key from provider");
                });
        // 5. Wait and Capture Key Metadata for assertions
        Thread.sleep(5000);
        keys = adminClient.realm("master").keys().getKeyMetadata();
        hsmKey = keys.getKeys().stream()
                .filter(k -> k.getProviderId().equals(hsmProvider.getName()) || k.getKid().startsWith("securosys"))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("HSM Key not found in metadata"));

        ClientRepresentation samlClient = new ClientRepresentation();
        samlClient.setClientId("saml-test-client");
        samlClient.setProtocol("saml");
        samlClient.setAdminUrl(serverUrl); // cokolwiek dla testu
        samlClient.setRedirectUris(Collections.singletonList("http://localhost:8081/*"));
        samlClient.setAttributes(new java.util.HashMap<>());
        samlClient.getAttributes().put("saml.assertion.signature", "true");
        samlClient.getAttributes().put("saml.server.signature", "true");
        samlClient.getAttributes().put("saml_signature_algorithm", "RSA_SHA256");
        samlClient.getAttributes().put("saml_idp_initiated_sso_url_name", "saml-test-client");
        adminClient.realm("master").clients().create(samlClient);

    }
    @Test
    public void testSAMLSign() throws Exception {
        String ssoUrl = serverUrl + "/realms/master/protocol/saml/clients/saml-test-client";

        Response loginPageResponse = RestAssured.given()
                .get(ssoUrl);

        var cookies = loginPageResponse.getDetailedCookies();
        String actionUrl = loginPageResponse.htmlPath().getString("**.find { it.@id == 'kc-form-login' }.@action");

        assertNotNull(actionUrl);

        Response samlResponsePage = RestAssured.given()
                .cookies(cookies)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", "admin")
                .formParam("password", "admin")
                .formParam("credentialId", "")
                .redirects().follow(true)
                .post(actionUrl);

        String encodedSAMLResponse = samlResponsePage.htmlPath().getString("**.find { it.@name == 'SAMLResponse' }.@value");

        assertNotNull(encodedSAMLResponse);
        String decodedXml = new String(java.util.Base64.getDecoder().decode(encodedSAMLResponse));
        assertTrue(decodedXml.contains(hsmKey.getKid()));
    }
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

        RSASSAVerifier verifier = new RSASSAVerifier((RSAPublicKey) HsmService.parsePublicKey(hsmKey.getPublicKey()));
        boolean isSignatureValid = signedJWT.verify(verifier);

        assertTrue(isSignatureValid, "JWT signature is not valid");

    } catch (ParseException | JOSEException e) {
        throw new RuntimeException(e);
    }

}

}