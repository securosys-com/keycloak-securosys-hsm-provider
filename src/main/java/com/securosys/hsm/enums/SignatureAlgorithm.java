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
package com.securosys.hsm.enums;

import com.securosys.primus.jce.spi2.SignatureAlgorithms;

import java.util.Set;

public class SignatureAlgorithm {

    private SignatureAlgorithm() {
        // Prevent instantiation
    }

    public static final String SHA224_WITH_RSA_PSS = "SHA224withRSA/PSS";
    public static final String SHA256_WITH_RSA_PSS = "SHA256withRSA/PSS";
    public static final String SHA384_WITH_RSA_PSS = "SHA384withRSA/PSS";
    public static final String SHA512_WITH_RSA_PSS = "SHA512withRSA/PSS";

    public static final String NONE_WITH_DSA = "NONEwithDSA";
    public static final String SHA224_WITH_DSA = "SHA224withDSA";
    public static final String SHA256_WITH_DSA = "SHA256withDSA";
    public static final String SHA384_WITH_DSA = "SHA384withDSA";
    public static final String SHA512_WITH_DSA = "SHA512withDSA";

    public static final String NONE_WITH_RSA = "NONEwithRSA";
    public static final String SHA224_WITH_RSA = "SHA224withRSA";
    public static final String SHA256_WITH_RSA = "SHA256withRSA";
    public static final String SHA384_WITH_RSA = "SHA384withRSA";
    public static final String SHA512_WITH_RSA = "SHA512withRSA";

    public static final String DOUBLE_SHA256_WITH_ECDSA = "DOUBLE_SHA256_WITH_ECDSA";

    public static final String NONESHA224_WITH_RSA = "NONESHA224withRSA";
    public static final String NONESHA256_WITH_RSA = "NONESHA256withRSA";
    public static final String NONESHA384_WITH_RSA = "NONESHA384withRSA";
    public static final String NONESHA512_WITH_RSA = "NONESHA512withRSA";

    public static final String NONE_WITH_ECDSA = "NONEwithECDSA";
    public static final String SHA1_WITH_ECDSA = "SHA1withECDSA";
    public static final String SHA224_WITH_ECDSA = "SHA224withECDSA";
    public static final String SHA256_WITH_ECDSA = "SHA256withECDSA";
    public static final String SHA384_WITH_ECDSA = "SHA384withECDSA";
    public static final String SHA512_WITH_ECDSA = "SHA512withECDSA";

    public static final String SHA3224_WITH_ECDSA = "SHA3224withECDSA";
    public static final String SHA3256_WITH_ECDSA = "SHA3256withECDSA";
    public static final String SHA3384_WITH_ECDSA = "SHA3384withECDSA";
    public static final String SHA3512_WITH_ECDSA = "SHA3512withECDSA";

    public static final String SHA256_WITH_ECDSA_DETERMINISTIC = "SHA256withECDDSA"; // RFC6979

    public static final String EDDSA = "EdDSA";

    public static final String KECCAK224_WITH_ECDSA = "KECCAK224withECDSA";
    public static final String KECCAK256_WITH_ECDSA = "KECCAK256withECDSA";
    public static final String KECCAK384_WITH_ECDSA = "KECCAK384withECDSA";
    public static final String KECCAK512_WITH_ECDSA = "KECCAK512withECDSA";

    public static final String ISS_KERL = "ISS_KERL";

    public static final String SHA1_WITH_RSA = "SHA1withRSA";
    public static final String SHA1_WITH_DSA = "SHA1withDSA";
    public static final String NONESHA1_WITH_RSA = "NONESHA1withRSA";
    public static final String SHA1_WITH_RSA_PSS = "SHA1withRSA/PSS";

    public static final String BLS = "BLS";
    public static final String DILITHIUM = "Dilithium";
    public static final String SPHINCS_PLUS = "SphincsPlus";
    public static final String KYBER = "Kyber";

    private static final Set<String> ALLOWED_ALGORITHMS = Set.of(
            SignatureAlgorithm.SHA256_WITH_ECDSA,
            SignatureAlgorithm.SHA384_WITH_ECDSA,
            SignatureAlgorithm.SHA512_WITH_ECDSA,
            SignatureAlgorithm.SHA256_WITH_RSA,
            SignatureAlgorithm.SHA384_WITH_RSA,
            SignatureAlgorithm.SHA512_WITH_RSA
    );

    public static boolean allowedAlgorithms(String algorithm) {
        return algorithm != null && ALLOWED_ALGORITHMS.contains(algorithm);
    }

    public static String getOnlyHash(String algorithm){
        String[] alg = algorithm.split("with");
        return alg[0];
    }
    /**
     * Utility: check if an algorithm string is valid.
     */
    public static boolean isValid(String algorithm) {
        try {
            for (var field : SignatureAlgorithms.class.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers())
                        && field.getType().equals(String.class)
                        && field.get(null).equals(algorithm)) {
                    return true;
                }
            }
        } catch (IllegalAccessException ignored) {
        }
        return false;
    }
}
