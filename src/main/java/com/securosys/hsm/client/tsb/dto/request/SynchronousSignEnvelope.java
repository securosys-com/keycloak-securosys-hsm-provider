// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.dto.request;

/**
 * Request body for POST /v1/synchronousSign.
 */
public class SynchronousSignEnvelope {
    private SynchronousSignRequest signRequest;

    public SynchronousSignEnvelope() {
    }

    public SynchronousSignEnvelope(SynchronousSignRequest signRequest) {
        this.signRequest = signRequest;
    }

    public SynchronousSignRequest getSignRequest() {
        return signRequest;
    }

    public void setSignRequest(SynchronousSignRequest signRequest) {
        this.signRequest = signRequest;
    }
}
