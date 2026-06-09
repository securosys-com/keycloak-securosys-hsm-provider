// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.dto.request;

import java.util.ArrayList;
import java.util.List;

import com.securosys.hsm.enums.PayloadType;

/**
 * Nested signRequest payload for POST /v1/synchronousSign.
 */
public class SynchronousSignRequest {
    private String payload;
    private PayloadType payloadType = PayloadType.UNSPECIFIED;
    private String signKeyName;
    private String keyPassword;
    private String signatureAlgorithm;
    private String signatureType;
    private List<String> signedApprovals = new ArrayList<>();

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public PayloadType getPayloadType() {
        return payloadType;
    }

    public void setPayloadType(PayloadType payloadType) {
        this.payloadType = payloadType;
    }

    public String getSignKeyName() {
        return signKeyName;
    }

    public void setSignKeyName(String signKeyName) {
        this.signKeyName = signKeyName;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    public List<String> getSignedApprovals() {
        return signedApprovals;
    }

    public void setSignedApprovals(List<String> signedApprovals) {
        this.signedApprovals = signedApprovals;
    }
}
