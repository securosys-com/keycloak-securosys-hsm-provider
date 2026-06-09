// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.policy;

public class Approval {
    private String typeOfKey;
    private String name;
    private String value;

    public Approval() {}

    public String getTypeOfKey() { return typeOfKey; }
    public void setTypeOfKey(String typeOfKey) { this.typeOfKey = typeOfKey; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
}
