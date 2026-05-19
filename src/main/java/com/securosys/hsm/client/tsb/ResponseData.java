// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

public class ResponseData {
    private final String body;
    private final int statusCode;

    public ResponseData(String body, int statusCode) {
        this.body = body;
        this.statusCode = statusCode;
    }

    public String getBody() { return body; }
    public int getStatusCode() { return statusCode; }
}