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

import java.security.*;

import com.securosys.hsm.dto.SignResult;
import com.securosys.hsm.provider.key.SecurosysProxyPrivateKey;
import com.securosys.hsm.service.HsmService;

public class SecurosysSignatureSpi extends SignatureSpi {
    private HsmService hsmService;
    private final String algorithm;
    private SecurosysProxyPrivateKey key;
    private java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();

    public SecurosysSignatureSpi(String algorithm, HsmService hsmService) {
        this.algorithm = algorithm;
        this.hsmService = hsmService;
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SecurosysProxyPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of HSMProxyPrivateKey");
        }
        this.key = (SecurosysProxyPrivateKey) privateKey;
    }

    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            byte[] dataToSign = buffer.toByteArray();
            buffer.reset();
            if(this.hsmService==null){
                this.hsmService=new HsmService(this.key.getHsmConfig());
            }

            try {
                if (key.getAlgorithm().equals("EC")) {
                    SignResult raw = hsmService.createSignature(dataToSign, key.getLabel(), key.getPassword(), algorithm, "RAW");
                    return raw.getSignature();
                } else {
                    SignResult der = hsmService.createSignature(dataToSign, key.getLabel(), key.getPassword(), algorithm, "DER");
                    return der.getSignature();
                }
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
        } catch (Exception e) {
            throw new SignatureException("HSM Signing failed", e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return false;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException();
    }

    @Override
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException();
    }
}