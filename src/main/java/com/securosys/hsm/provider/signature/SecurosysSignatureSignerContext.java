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

import com.securosys.hsm.dto.SignResult;
import com.securosys.hsm.provider.key.SecurosysKeyWrapper;
import com.securosys.hsm.service.HsmService;
import org.keycloak.crypto.*;

public class SecurosysSignatureSignerContext implements SignatureSignerContext {

    private final SecurosysKeyWrapper key;

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
        HsmService hsmService = new HsmService(key.getHsmConfig());
        try {
            if(key.getType().equals("EC")) {
                SignResult raw = hsmService.createSignature(bytes, key.getLabel(), key.getPassword(), key.getAlgorithm(), "RAW");
                return raw.getSignature();
            }else{
                SignResult der = hsmService.createSignature(bytes, key.getLabel(), key.getPassword(), key.getAlgorithm(), "DER");
                return der.getSignature();
            }
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }

    }
}