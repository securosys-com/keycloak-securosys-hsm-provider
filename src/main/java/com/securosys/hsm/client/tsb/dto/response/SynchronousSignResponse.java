// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.dto.response;

/**
 * Response body for POST /v1/synchronousSign.
 */
public class SynchronousSignResponse {
    private String signature;
    private String publicNonce;

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getPublicNonce() {
        return publicNonce;
    }

    public void setPublicNonce(String publicNonce) {
        this.publicNonce = publicNonce;
    }
}
