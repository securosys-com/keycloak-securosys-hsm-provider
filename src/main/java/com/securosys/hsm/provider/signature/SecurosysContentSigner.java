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
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

public class SecurosysContentSigner implements ContentSigner {

    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final HsmService signer;
    private final AlgorithmIdentifier algId;
    private final SecurosysKeyWrapper key;
    public SecurosysContentSigner(HsmService signer, SecurosysKeyWrapper key) {
        this.signer = signer;
        AlgorithmIdentifier rsaAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA256withRSA");

        AlgorithmIdentifier ecdsaAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                .find("SHA256withECDSA");
        if(key.getType().equals("EC")){
            this.algId =ecdsaAlgId;

        }else{
            this.algId = rsaAlgId;
        }
        this.key=key;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algId;
    }

    @Override
    public OutputStream getOutputStream() {
        return buffer;
    }

    @Override
    public byte[] getSignature() {

        try {
            SignResult der = signer.createSignature(buffer.toByteArray(), key.getLabel(), key.getPassword(), key.getAlgorithm(), "DER");
            return der.getSignature();
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
    }
}