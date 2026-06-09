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

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import com.securosys.hsm.client.HsmClient;
import com.securosys.hsm.client.HsmClientFactory;
import com.securosys.hsm.client.jce.JceClient;
import com.securosys.hsm.dto.SignResult;
import com.securosys.hsm.provider.key.SecurosysProxyPrivateKey;

/**
 * Service Provider Interface (SPI) implementation for digital signatures using Securosys HSM.
 * This class extends SignatureSpi to provide signing capabilities backed by HSM operations.
 */
public class SecurosysSignatureSpi extends SignatureSpi {
    private HsmClient hsmClient;
    private final String algorithm;
    private SecurosysProxyPrivateKey key;
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    /**
     * Constructs a new SecurosysSignatureSpi with the specified algorithm and HSM service.
     *
     * @param algorithm the signature algorithm (e.g., "RS256", "ES256")
     * @param jceClient the HSM service for performing cryptographic operations
     */
    public SecurosysSignatureSpi(String algorithm, JceClient jceClient) {
        this.algorithm = algorithm;
        this.hsmClient = jceClient;
    }

    /**
     * Initializes this signature object for signing with the given private key.
     *
     * @param privateKey the private key to use for signing
     * @throws InvalidKeyException if the key is not a SecurosysProxyPrivateKey
     */
    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof SecurosysProxyPrivateKey)) {
            throw new InvalidKeyException("Key must be an instance of HSMProxyPrivateKey");
        }
        this.key = (SecurosysProxyPrivateKey) privateKey;
    }

    /**
     * Updates the data to be signed with a single byte.
     *
     * @param b the byte to update the signature data with
     */
    @Override
    protected void engineUpdate(byte b) {
        buffer.write(b);
    }

    /**
     * Updates the data to be signed with the specified bytes.
     *
     * @param b the byte array containing the data
     * @param off the offset in the byte array
     * @param len the number of bytes to use
     */
    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
        buffer.write(b, off, len);
    }

    /**
     * Signs the accumulated data and returns the signature.
     *
     * @return the signature bytes
     * @throws SignatureException if signing fails
     */
    @Override
    protected byte[] engineSign() throws SignatureException {
        try {
            byte[] dataToSign = buffer.toByteArray();
            buffer.reset();
            if (this.hsmClient == null) {
                this.hsmClient = HsmClientFactory.create(this.key.getHsmConfig());
            }

        try {
            return performSignature(dataToSign);
        } catch (Throwable throwable) {
            throw new SignatureException("HSM signature failed", throwable);
        }
        } catch (Exception e) {
            throw new SignatureException("HSM Signing failed", e);
        }
    }

    /**
     * Performs the actual signature operation based on the key algorithm.
     *
     * @param dataToSign the data to sign
     * @return the signature bytes
     * @throws SignatureException if the HSM operation fails
     */
    private byte[] performSignature(byte[] dataToSign) throws SignatureException {
        try {
            if (key.getAlgorithm().equals("EC")) {
                SignResult raw = hsmClient.createSignature(dataToSign, key.getLabel(), key.getPassword(), algorithm, "RAW");
                return raw.getSignature();
            } else {
                SignResult der = hsmClient.createSignature(dataToSign, key.getLabel(), key.getPassword(), algorithm, "DER");
                return der.getSignature();
            }
        } catch (Throwable throwable) {
            throw new SignatureException("HSM signature failed", throwable);
        }
    }

    /**
     * Verifies the signature. This implementation always returns false as verification
     * is not supported in this SPI.
     *
     * @param sigBytes the signature bytes
     * @return false, as verification is not supported
     * @throws SignatureException never thrown in this implementation
     */
    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return false;
    }

    /**
     * Initializes this signature object for verification. Not supported.
     *
     * @param publicKey the public key
     * @throws InvalidKeyException always thrown as this operation is not supported
     */
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new UnsupportedOperationException();
    }

    /**
     * Sets a parameter. Not supported.
     *
     * @param param the parameter name
     * @param value the parameter value
     */
    @Override
    protected void engineSetParameter(String param, Object value) {
        throw new UnsupportedOperationException();
    }

    /**
     * Gets a parameter. Not supported.
     *
     * @param param the parameter name
     * @return never returns, always throws UnsupportedOperationException
     */
    @Override
    protected Object engineGetParameter(String param) {
        throw new UnsupportedOperationException();
    }
}
