// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.policy;

public class Policy {
    private Rule ruleUse;
    private Rule ruleBlock;
    private Rule ruleUnblock;
    private Rule ruleModify;
    private KeyStatus keyStatus;

    public Policy() {}

    public Rule getRuleUse() { return ruleUse; }
    public void setRuleUse(Rule ruleUse) { this.ruleUse = ruleUse; }

    public Rule getRuleBlock() { return ruleBlock; }
    public void setRuleBlock(Rule ruleBlock) { this.ruleBlock = ruleBlock; }

    public Rule getRuleUnblock() { return ruleUnblock; }
    public void setRuleUnblock(Rule ruleUnblock) { this.ruleUnblock = ruleUnblock; }

    public Rule getRuleModify() { return ruleModify; }
    public void setRuleModify(Rule ruleModify) { this.ruleModify = ruleModify; }

    public KeyStatus getKeyStatus() { return keyStatus; }
    public void setKeyStatus(KeyStatus keyStatus) { this.keyStatus = keyStatus; }
}
