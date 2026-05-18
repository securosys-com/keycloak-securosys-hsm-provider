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

/**
 * Enumeration of HSM request types for different cryptographic operations.
 * Each type corresponds to a specific operation that can be performed on the HSM.
 */
public enum HsmRequestType {
    /**
     * Request to sign data.
     */
    SIGN(Values.SIGN),
    /**
     * Request to block a key.
     */
    BLOCK(Values.BLOCK),
    /**
     * Request to unblock a key.
     */
    UNBLOCK(Values.UNBLOCK),
    /**
     * Request to modify a key or its attributes.
     */
    MODIFY(Values.MODIFY),
    /**
     * Request to decrypt data.
     */
    DECRYPT(Values.DECRYPT),
    /**
     * Request to unwrap a key.
     */
    UNWRAP(Values.UNWRAP),
    /**
     * Request to sign a certificate signing request (CSR).
     */
    CSRSIGN(Values.CSRSIGN),
    /**
     * Request to sign a certificate.
     */
    CRTSIGN(Values.CRTSIGN),
    /**
     * Request for self-signing operation.
     */
    SELFSIGN(Values.SELFSIGN);

    private String value;

    /**
     * Constructs an HsmRequestType with the given string value.
     *
     * @param value the string representation of the request type
     */
    HsmRequestType(String value) {
        this.value = value;
    }

    /**
     * Returns the string representation of this request type.
     *
     * @return the string value
     */
    @Override
    public String toString() {
        return this.value;
    }

    // Kind of a work-around in order to be able to use the enum also for the
    // @DiscriminatorValue annotation in the sub-classes.
    /**
     * Inner class containing string constants for the enum values.
     * This allows using the values in annotations.
     */
    public static class Values {

        public static final String SIGN = "sign";

        public static final String BLOCK = "block";

        public static final String UNBLOCK = "unblock";

        public static final String MODIFY = "modify";

        public static final String DECRYPT = "decrypt";

        public static final String UNWRAP = "unwrap";

        public static final String CSRSIGN = "csrsign";

        public static final String CRTSIGN = "crtsign";

        public static final String SELFSIGN = "selfsign";
    }
}
