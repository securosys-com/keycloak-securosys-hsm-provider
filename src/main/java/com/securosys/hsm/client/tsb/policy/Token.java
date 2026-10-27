// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.policy;

import java.util.List;

public class Token {
    private String name;
    private int timelock;
    private int timeout;
    private List<Group> groups;

    public Token() {}

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public int getTimelock() { return timelock; }
    public void setTimelock(int timelock) { this.timelock = timelock; }

    public int getTimeout() { return timeout; }
    public void setTimeout(int timeout) { this.timeout = timeout; }

    public List<Group> getGroups() { return groups; }
    public void setGroups(List<Group> groups) { this.groups = groups; }
}
