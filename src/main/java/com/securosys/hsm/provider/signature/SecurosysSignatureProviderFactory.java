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

import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * Signature provider implementation for SecurosysSignatureProviderFactory.
 */
public class SecurosysSignatureProviderFactory implements SignatureProviderFactory {
    private final String algorithm;

    public SecurosysSignatureProviderFactory(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public SignatureProvider create(KeycloakSession session) {
        return new SecurosysSignatureProvider(session, getId());
    }

    @Override
    public String getId() {
        return algorithm;
    }
}

