/**
 * Copyright (c)2025 Securosys SA, authors: Tomasz Madej
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
package com.securosys.hsm.service;

import com.securosys.hsm.dto.CreateKeyDto;
import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;
import com.securosys.primus.jce.PrimusProvider;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

public class PrimusKeyGeneratorFactory {

    private static final String JCE_PROVIDER = PrimusProvider.getProviderName();

    public static KeyGenerator getKeyGenerator(CreateKeyDto createKey) {
        final String keyAlgorithm = createKey.getAlgorithm();

        try {
            KeyGenerator primusKeyGenerator = KeyGenerator.getInstance(createKey.getAlgorithm(), JCE_PROVIDER);

            // Initialize the KeyPairGenerator with the parameters for the specified algorithm.
            if (List.of("AES", "ChaCha20", "Camellia").contains(keyAlgorithm)) {
                final Integer keySize = createKey.getKeySize();
                primusKeyGenerator.init(keySize);
            }
            if (keyAlgorithm.equals("TDEA")) {
                primusKeyGenerator.init(0);
            }

            return primusKeyGenerator;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new BusinessException("Key creation failed.", BusinessReason.ERROR_IN_HSM, e);
        }
    }

}
