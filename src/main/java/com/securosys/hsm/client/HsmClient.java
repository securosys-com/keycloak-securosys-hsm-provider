// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client;

import java.security.PublicKey;

import com.securosys.hsm.dto.SignResult;

/**
 * Common provider-facing operations supported by Securosys HSM clients.
 */
public interface HsmClient {
    HsmKeyAttributes fetchKeyAttributes(String keyLabel, String keyPassword) throws Exception;

    PublicKey getPublicKey(HsmKeyAttributes keyAttributes) throws Exception;

    SignResult createSignature(byte[] payload, String keyName, String password, String algorithm, String signatureType)
            throws Throwable;
}
