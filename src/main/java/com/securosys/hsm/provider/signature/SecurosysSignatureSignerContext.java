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


package com.securosys.hsm.provider.signature;

import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureException;
import org.keycloak.crypto.SignatureSignerContext;

import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmClientFactory;
import com.securosys.hsm.client.config.Config;
import com.securosys.hsm.dto.SignResult;
import com.securosys.hsm.provider.key.SecurosysKeyWrapper;

/**
 * Signature provider implementation for SecurosysSignatureSignerContext.
 */
public class SecurosysSignatureSignerContext implements SignatureSignerContext {

    private final SecurosysKeyWrapper key;

    // Constructor for User Keys (via Label)
    public SecurosysSignatureSignerContext(String keyLabel,String keyAlgorithm,SecurosysKeyWrapper key) {
        this.key = new SecurosysKeyWrapper();
        this.key.setKid("securosys_user_"+keyLabel);
        this.key.setLabel(keyLabel);
        if(keyAlgorithm.startsWith("RS")){
            this.key.setType(KeyType.RSA);
        }else{
            this.key.setType(KeyType.EC);
        }
        this.key.setHsmConfig(key.getHsmConfig());
        this.key.setAlgorithm(keyAlgorithm);
        this.key.setPrivateKey(key.getPrivateKey());
        this.key.setPublicKey(key.getPublicKey());
    }
    public SecurosysSignatureSignerContext(KeyWrapper key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null!");
        }

        if (key instanceof SecurosysKeyWrapper) {
            this.key = (SecurosysKeyWrapper) key;
        } else {
            this.key = new SecurosysKeyWrapper();
            this.key.setKid(key.getKid());
            this.key.setAlgorithm(key.getAlgorithm());
            this.key.setPrivateKey(key.getPrivateKey());
            this.key.setPublicKey(key.getPublicKey());
        }
    }

    @Override
    public String getKid() {
        return key.getKid();
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public String getHashAlgorithm() {
        return JavaAlgorithm.getJavaAlgorithmForHash(getAlgorithm());
    }

    @Override
    public byte[] sign(byte[] bytes) throws SignatureException {
        Config config = key.getHsmConfig();
        try {
            HsmClient hsmClient = HsmClientFactory.create(config);
            if(key.getType().equals("EC")) {
                SignResult raw = hsmClient.createSignature(bytes, key.getLabel(), key.getPassword(), key.getAlgorithm(), "RAW");
                return raw.getSignature();
            }else{
                SignResult der = hsmClient.createSignature(bytes, key.getLabel(), key.getPassword(), key.getAlgorithm(), "DER");
                return der.getSignature();
            }
        } catch (Throwable e) {
            throw new SignatureException("HSM signature failed", e);
        }
    }
}
