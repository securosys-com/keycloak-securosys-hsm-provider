// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.policy;

import java.util.List;

public class Group {
    private String name;
    private int quorum;
    private List<Approval> approvals;

    public Group() {}

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public int getQuorum() { return quorum; }
    public void setQuorum(int quorum) { this.quorum = quorum; }

    public List<Approval> getApprovals() { return approvals; }
    public void setApprovals(List<Approval> approvals) { this.approvals = approvals; }
}
