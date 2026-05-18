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

import com.securosys.hsm.dto.Config;
import com.securosys.hsm.dto.SignedKeyAttributesDto;
import com.securosys.hsm.provider.signature.SecurosysContentSigner;
import com.securosys.hsm.service.HsmService;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.*;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakSession;

import java.math.BigInteger;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Stream;

public class SecurosysKeyProvider implements org.keycloak.keys.KeyProvider {
    private static final String NOTE_KEY = SecurosysKeyWrapper.class.getName();

    private final Config config;
    private final HsmService hsmService;
    private final KeyStatus status;
    private final String kid;
    private final long providerPriority;
    private final String algorithm;
    private final SecurosysKeyWrapper key;
    private final String label;
    private final String password;
    public SecurosysKeyProvider(KeycloakSession session, ComponentModel model) throws KeyException {
    String timeout=model.get(SecurosysKeyProviderFactory.HSM_CONNECTION_TIMEOUT);
    if(timeout==null){
        timeout="10000";
    }
        this.config = Config.builder()
                .port(model.get(SecurosysKeyProviderFactory.HSM_PORT))
                .host(model.get(SecurosysKeyProviderFactory.HSM_HOST))
                .user(model.get(SecurosysKeyProviderFactory.HSM_USER))
                .setupPassword(model.get(SecurosysKeyProviderFactory.HSM_SETUP_PASSWORD))
                .proxyUser(model.get(SecurosysKeyProviderFactory.HSM_PROXY_USER))
                .proxyPassword(model.get(SecurosysKeyProviderFactory.HSM_PROXY_PASSWORD))
                .attestationKeyName(model.get(SecurosysKeyProviderFactory.HSM_ATTESTATION_KEY_NAME))
                .secretPath(model.get(SecurosysKeyProviderFactory.HSM_SECRET_PATH))
                .connectionTimeout(timeout)
                .build();
        hsmService=new HsmService(config);
        this.kid = model.get(Attributes.KID_KEY);

        this.status = KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
        this.providerPriority = model.get(Attributes.PRIORITY_KEY, 0l);
        this.algorithm = model.get(SecurosysKeyProviderFactory.ALGORITHM_KEY);
        this.label = model.get(SecurosysKeyProviderFactory.KEY_LABEL);
        this.password = model.get(SecurosysKeyProviderFactory.KEY_PASSWORD);
        if (model.hasNote(NOTE_KEY)) {
            key = model.getNote(NOTE_KEY);
        } else {
            key = createKeyWrapper(session,model);
            model.setNote(NOTE_KEY, key);
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
        SignedKeyAttributesDto keyAttributes = hsmService.getKeyAttributes(label, password);
//        CreateKeyDto createKey = new CreateKeyDto();
//        createKey.setLabel("TEST_DSA_KEY");
//        createKey.setAlgorithm("DSA");
//        createKey.setKeySize(2048);
//        createKey.setAttributes(new AttributesDto());
//        createKey.getAttributes().setDestroyable(true);
//        createKey.getAttributes().setDecrypt(true);
//        createKey.getAttributes().setEncrypt(true);
//        createKey.getAttributes().setSign(true);
//        createKey.getAttributes().setVerify(true);
//        createKey.getAttributes().setExtractable(false);
//        createKey.getAttributes().setSensitive(false);
//        createKey.setPolicy(null);
//        hsmService.createKeyIfNotExists(createKey);

        if(!keyAttributes.getJson().getAlgorithm().equals("RSA") && !keyAttributes.getJson().getAlgorithm().equals("EC")) {
            this.disablePlugin(session,model);
            throw new KeyException("Unexpected key algorithm "+keyAttributes.getJson().getAlgorithm()+" for '"+label+"'.  Supported: RSA/EC");
        }
        SecurosysKeyWrapper securosysKeyWrapper = new SecurosysKeyWrapper();
        SecurosysProxyPrivateKey proxyPrivateKey = new SecurosysProxyPrivateKey(label,keyAttributes.getJson().getAlgorithm(),config);
        securosysKeyWrapper.setPrivateKey(proxyPrivateKey);
        securosysKeyWrapper.setPublicKey(hsmService.getPublicKey(keyAttributes));
        securosysKeyWrapper.setUse(KeyUse.SIG);
        securosysKeyWrapper.setAlgorithm(algorithm);
        securosysKeyWrapper.setStatus(status);
        securosysKeyWrapper.setLabel(label);
        securosysKeyWrapper.setPassword(password);
        securosysKeyWrapper.setKid(SecurosysKeyProviderFactory.ID+"_"+kid);
        securosysKeyWrapper.setProviderPriority(this.providerPriority);
        securosysKeyWrapper.setProviderId(model.getId());
        securosysKeyWrapper.setHsmConfig(config);
        if(keyAttributes.getJson().getAlgorithm().equals("EC")) {
            securosysKeyWrapper.setType(KeyType.EC);
            if(algorithm.contains("RS")) {
                this.disablePlugin(session,model);
                throw new KeyException("Unexpected signature algorithm '"+algorithm+"' for '"+label+"' EC key");
            }

        }else if(keyAttributes.getJson().getAlgorithm().equals("RSA")){
            securosysKeyWrapper.setType(KeyType.RSA);
            if(algorithm.contains("ES")) {
                this.disablePlugin(session,model);
                throw new KeyException("Unexpected signature algorithm '"+algorithm+"' for '"+label+"' RSA key");
            }
        }
        securosysKeyWrapper.setPublicKey(hsmService.getPublicKey(keyAttributes));
//        keyWrapper.setCertificate(generateSelfSignedCert(keyWrapper,hsmService));

        return securosysKeyWrapper;
    }

    @Override
    public Stream<KeyWrapper> getKeysStream() {
            return Stream.of(key);


    }
    public static X509Certificate generateSelfSignedCert(SecurosysKeyWrapper key, HsmService signer) {
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
