// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

import java.util.List;

public class ApiKeyTypes {
    private List<String> keyManagementToken;
    private List<String> keyOperationToken;
    private List<String> approverToken;
    private List<String> serviceToken;
    private List<String> approverKeyManagementToken;

    public ApiKeyTypes() {}

    public List<String> getKeyManagementToken() { return keyManagementToken; }
    public void setKeyManagementToken(List<String> keyManagementToken) { this.keyManagementToken = keyManagementToken; }

    public List<String> getKeyOperationToken() { return keyOperationToken; }
    public void setKeyOperationToken(List<String> keyOperationToken) { this.keyOperationToken = keyOperationToken; }

    public List<String> getApproverToken() { return approverToken; }
    public void setApproverToken(List<String> approverToken) { this.approverToken = approverToken; }

    public List<String> getServiceToken() { return serviceToken; }
    public void setServiceToken(List<String> serviceToken) { this.serviceToken = serviceToken; }

    public List<String> getApproverKeyManagementToken() { return approverKeyManagementToken; }
    public void setApproverKeyManagementToken(List<String> approverKeyManagementToken) { this.approverKeyManagementToken = approverKeyManagementToken; }
}