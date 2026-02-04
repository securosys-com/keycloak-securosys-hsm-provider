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

import com.securosys.hsm.dto.Config;
import com.securosys.hsm.provider.key.SecurosysKeyProviderFactory;
import com.securosys.hsm.util.YamlLoader;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.KeysMetadataRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers
public class ProviderWrongKeyTypeTest {

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
    @Test
    public void wrongKeyType() throws Exception {
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
        Config yamlConfig = YamlLoader.loadConfig("hsm-config-wrong-type.yaml");
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
        try {
            keys.getKeys().stream()
                    .filter(k -> !k.getKid().startsWith(SecurosysKeyProviderFactory.ID))
                    .findFirst()
                    .orElseThrow(() -> {
                        return new RuntimeException("Cannot find new key from provider");
                    });
        }catch (RuntimeException ex){
            assertTrue(ex.getMessage().contains("Cannot find new key from provider"),"Not expected action. Key should not be added to keycloak");
        }
        List<ComponentRepresentation> master = adminClient.realm("master").components().query();
        for(ComponentRepresentation component: master){
            if(component.getProviderId().equals("securosys-hsm")){
                assertTrue(component.getConfig().getFirst("enabled").equals("false"),"Not expected action. Component should not be active");
                assertTrue(component.getConfig().getFirst("active").equals("false"),"Not expected action. Component key should not be active");

            }
        }
    }

}