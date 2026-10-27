/**
 * Copyright (c)2026 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 **/

package com.securosys.hsm.provider.signature;

import com.securosys.hsm.provider.key.SecurosysKeyWrapper;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Signature provider implementation for SecurosysSignatureProvider.
 */
public class SecurosysSignatureProvider implements SignatureProvider {

    private final KeycloakSession session;
    private final String algorithmId;

    public SecurosysSignatureProvider(KeycloakSession session, String algorithmId) {
        this.session = session;
        this.algorithmId = algorithmId;
    }

    @Override
    public SignatureSignerContext signer() throws SignatureException {
        KeyWrapper activeKey = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.SIG, algorithmId);
        return createSignerContext(activeKey);
    }

    @Override
    public SignatureSignerContext signer(KeyWrapper key) throws SignatureException {
        return createSignerContext(key);
    }


    private SignatureSignerContext createSignerContext(KeyWrapper key) {
        // 3. Fallback to standard logic if no user key is found
        if (key instanceof SecurosysKeyWrapper) {
            return new SecurosysSignatureSignerContext(key);
        }
        return new AsymmetricSignatureSignerContext(key);
    }
    @Override
    public SignatureVerifierContext verifier(String kid) throws VerificationException {
        KeyWrapper key = session.keys().getKey(session.getContext().getRealm(), kid, KeyUse.SIG, algorithmId);
        if (key != null) {
            return new ServerAsymmetricSignatureVerifierContext(key);
        }
        throw new VerificationException("Key not found for kid: " + kid);
    }

    @Override
    public SignatureVerifierContext verifier(KeyWrapper key) throws VerificationException {
        return new ServerAsymmetricSignatureVerifierContext(key);
    }

    @Override
    public boolean isAsymmetricAlgorithm() {
        return true;
    }

    @Override
    public void close() {
        // No-op
    }

}
