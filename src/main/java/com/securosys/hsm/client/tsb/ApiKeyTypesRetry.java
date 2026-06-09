// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb;

public class ApiKeyTypesRetry {
    private int keyManagementTokenIndex = 0;
    private int keyOperationTokenIndex = 0;
    private int approverTokenIndex = 0;
    private int serviceTokenIndex = 0;
    private int approverKeyManagementTokenIndex = 0;

    public int getKeyManagementTokenIndex() { return keyManagementTokenIndex; }
    public void setKeyManagementTokenIndex(int keyManagementTokenIndex) { this.keyManagementTokenIndex = keyManagementTokenIndex; }

    public int getKeyOperationTokenIndex() { return keyOperationTokenIndex; }
    public void setKeyOperationTokenIndex(int keyOperationTokenIndex) { this.keyOperationTokenIndex = keyOperationTokenIndex; }

    public int getApproverTokenIndex() { return approverTokenIndex; }
    public void setApproverTokenIndex(int approverTokenIndex) { this.approverTokenIndex = approverTokenIndex; }

    public int getServiceTokenIndex() { return serviceTokenIndex; }
    public void setServiceTokenIndex(int serviceTokenIndex) { this.serviceTokenIndex = serviceTokenIndex; }

    public int getApproverKeyManagementTokenIndex() { return approverKeyManagementTokenIndex; }
    public void setApproverKeyManagementTokenIndex(int approverKeyManagementTokenIndex) { this.approverKeyManagementTokenIndex = approverKeyManagementTokenIndex; }
}