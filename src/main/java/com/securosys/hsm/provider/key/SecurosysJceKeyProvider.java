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

import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmClientFactory;
import com.securosys.hsm.client.HsmKeyAttributes;
import com.securosys.hsm.client.config.Config;
import com.securosys.hsm.client.config.JceConfig;
import com.securosys.hsm.provider.signature.SecurosysContentSigner;
import com.securosys.hsm.client.jce.JceClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

import java.math.BigInteger;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Stream;

/**
 * Key provider helper for SecurosysKeyProvider.
 */
public class SecurosysJceKeyProvider implements KeyProvider {
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

    public SecurosysJceKeyProvider(KeycloakSession session, ComponentModel model) throws KeyException {
    String timeout=model.get(SecurosysJceKeyProviderFactory.HSM_CONNECTION_TIMEOUT);
    if(timeout==null){
        timeout="10000";
    }
        this.config = JceConfig.builder()
                .port(model.get(SecurosysJceKeyProviderFactory.HSM_PORT))
                .host(model.get(SecurosysJceKeyProviderFactory.HSM_HOST))
                .user(model.get(SecurosysJceKeyProviderFactory.HSM_USER))
                .setupPassword(model.get(SecurosysJceKeyProviderFactory.HSM_SETUP_PASSWORD))
                .proxyUser(model.get(SecurosysJceKeyProviderFactory.HSM_PROXY_USER))
                .proxyPassword(model.get(SecurosysJceKeyProviderFactory.HSM_PROXY_PASSWORD))
                .attestationKeyName(model.get(SecurosysJceKeyProviderFactory.HSM_ATTESTATION_KEY_NAME))
                .timestampKeyName(model.get(SecurosysJceKeyProviderFactory.HSM_TIMESTAMP_KEY_NAME))
                .timestampSignatureAlgorithm(model.get(SecurosysJceKeyProviderFactory.HSM_TIMESTAMP_SIGNATURE_ALGORITHM))
                .secretPath(model.get(SecurosysJceKeyProviderFactory.HSM_SECRET_PATH))
                .connectionTimeout(timeout)
                .build();
        hsmClient = createHsmClient(config);
        this.kid = model.get(Attributes.KID_KEY);

        this.status = KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
        this.providerPriority = model.get(Attributes.PRIORITY_KEY, 0l);
        this.algorithm = model.get(SecurosysJceKeyProviderFactory.ALGORITHM_KEY);
        this.label = model.get(SecurosysJceKeyProviderFactory.KEY_LABEL);
        this.password = model.get(SecurosysJceKeyProviderFactory.KEY_PASSWORD);
        if (model.hasNote(NOTE_KEY)) {
            key = model.getNote(NOTE_KEY);
        } else {
            key = createKeyWrapper(session,model);
            model.setNote(NOTE_KEY, key);
        }

    }

    private HsmClient createHsmClient(Config config) throws KeyException {
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
        if(!keyAlgorithm.equals("RSA") && !keyAlgorithm.equals("EC")) {
            this.disablePlugin(session,model);
            throw new KeyException("Unexpected key algorithm "+keyAlgorithm+" for '"+label+"'.  Supported: RSA/EC");
        }
        SecurosysKeyWrapper securosysKeyWrapper = new SecurosysKeyWrapper();
        SecurosysProxyPrivateKey proxyPrivateKey = new SecurosysProxyPrivateKey(label,keyAlgorithm,config);
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
        securosysKeyWrapper.setKid(SecurosysJceKeyProviderFactory.ID+"_"+kid);
        securosysKeyWrapper.setProviderPriority(this.providerPriority);
        securosysKeyWrapper.setProviderId(model.getId());
        securosysKeyWrapper.setHsmConfig(config);
        if(keyAlgorithm.equals("EC")) {
            securosysKeyWrapper.setType(KeyType.EC);
            if(algorithm.contains("RS")) {
                this.disablePlugin(session,model);
                throw new KeyException("Unexpected signature algorithm '"+algorithm+"' for '"+label+"' EC key");
            }

        }else if(keyAlgorithm.equals("RSA")){
            securosysKeyWrapper.setType(KeyType.RSA);
            if(algorithm.contains("ES")) {
                this.disablePlugin(session,model);
                throw new KeyException("Unexpected signature algorithm '"+algorithm+"' for '"+label+"' RSA key");
            }
        }
//        keyWrapper.setCertificate(generateSelfSignedCert(keyWrapper,hsmService));

        return securosysKeyWrapper;
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
            return Stream.of(key);


    }
    public static X509Certificate generateSelfSignedCert(SecurosysKeyWrapper key, JceClient signer) {
        try {
            X500Name subject = new X500Name("CN=SecurosysProvider_" + key.getLabel());
            BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
            Date notBefore = new Date(System.currentTimeMillis() - 60_000);
            Date notAfter = new Date(System.currentTimeMillis() + 3650L * 24 * 60 * 60 * 1000);


            SecurosysContentSigner contentSigner = new SecurosysContentSigner(signer, key);


            JcaX509v3CertificateBuilder certBuilder =
                    new JcaX509v3CertificateBuilder(
                            subject, // issuer
                            serial, // serial number
                            notBefore, // valid from
                            notAfter, // valid to
                            subject, // subject
                            (PublicKey) key.getPublicKey() // EC lub RSA public key
                    );

            certBuilder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature)
            );


            return new JcaX509CertificateConverter()
                    .getCertificate(certBuilder.build(contentSigner));


        } catch (Exception e) {
            throw new RuntimeException("Failed to generate self-signed certificate", e);
        }
    }
}
