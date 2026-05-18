/**
 * Copyright (c)2025 Securosys SA, authors: Tomasz Madej
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p>
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 **/
package com.securosys.hsm.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.Objects;

/**
 * Base class for policy without key-status field (as this field is not needed/supported
 * when modifying the policy of a key)
 */
public class ModifyPolicyDto {

    @Valid
    private Rule ruleUse;

    @Valid
    private Rule ruleBlock;

    @Valid
    private Rule ruleUnblock;

    @Valid
    private Rule ruleModify;

    public Rule getRuleUse() {
        return ruleUse;
    }

    public void setRuleUse(Rule ruleUse) {
        this.ruleUse = ruleUse;
    }

    public Rule getRuleBlock() {
        return ruleBlock;
    }

    public void setRuleBlock(Rule ruleBlock) {
        this.ruleBlock = ruleBlock;
    }

    public Rule getRuleUnblock() {
        return ruleUnblock;
    }

    public void setRuleUnblock(Rule ruleUnblock) {
        this.ruleUnblock = ruleUnblock;
    }

    public Rule getRuleModify() {
        return ruleModify;
    }

    public void setRuleModify(Rule ruleModify) {
        this.ruleModify = ruleModify;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        ModifyPolicyDto that = (ModifyPolicyDto) o;
        return Objects.equals(ruleUse, that.ruleUse) &&
                Objects.equals(ruleBlock, that.ruleBlock) &&
                Objects.equals(ruleUnblock, that.ruleUnblock) &&
                Objects.equals(ruleModify, that.ruleModify);
    }

    @Override
    public int hashCode() {
        return Objects.hash(ruleUse, ruleBlock, ruleUnblock, ruleModify);
    }

    @Override
    public String toString() {
        return "ModifyPolicyDto{" +
                "ruleUse=" + ruleUse +
                ", ruleBlock=" + ruleBlock +
                ", ruleUnblock=" + ruleUnblock +
                ", ruleModify=" + ruleModify +
                '}';
    }

    public enum ApprovalType {
        certificate, // NOSONAR, needs to be lowercase to match the XML format which is lowercase
        public_key // NOSONAR, and if using @JsonProperty to map to lower case, the generated swagger documentation is wrong
    }

    public static class Rule {

        @Valid
        @NotNull
        private List<Token> tokens;

        public List<Token> getTokens() {
            return tokens;
        }

        public void setTokens(List<Token> tokens) {
            this.tokens = tokens;
        }

        @Override
        public String toString() {
            return "Rule{" +
                    "tokens=" + tokens +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Rule rule = (Rule) o;
            return Objects.equals(tokens, rule.tokens);
        }

        @Override
        public int hashCode() {
            return Objects.hash(tokens);
        }
    }

    public static class Token {

        private String name;

        @NotNull
        private Integer timelock;

        @NotNull
        private Integer timeout;

        private List<Group> groups;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Integer getTimelock() {
            return timelock;
        }

        public void setTimelock(Integer timelock) {
            this.timelock = timelock;
        }

        public Integer getTimeout() {
            return timeout;
        }

        public void setTimeout(Integer timeout) {
            this.timeout = timeout;
        }

        public List<Group> getGroups() {
            return groups;
        }

        public void setGroups(List<Group> groups) {
            this.groups = groups;
        }

        @Override
        public String toString() {
            return "Token{" +
                    "name='" + name + '\'' +
                    ", timelock=" + timelock +
                    ", timeout=" + timeout +
                    ", groups=" + groups +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Token token = (Token) o;
            return Objects.equals(name, token.name) &&
                    Objects.equals(timelock, token.timelock) &&
                    Objects.equals(timeout, token.timeout) &&
                    Objects.equals(groups, token.groups);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, timelock, timeout, groups);
        }
    }

    public static class Group {

        private String name;

        @NotNull
        private Integer quorum;

        @NotNull
        private List<Approval> approvals;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public Integer getQuorum() {
            return quorum;
        }

        public void setQuorum(Integer quorum) {
            this.quorum = quorum;
        }

        public List<Approval> getApprovals() {
            return approvals;
        }

        public void setApprovals(List<Approval> approvals) {
            this.approvals = approvals;
        }

        @Override
        public String toString() {
            return "Group{" +
                    "name='" + name + '\'' +
                    ", quorum=" + quorum +
                    ", approvals=" + approvals +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Group group = (Group) o;
            return Objects.equals(name, group.name) &&
                    Objects.equals(quorum, group.quorum) &&
                    Objects.equals(approvals, group.approvals);
        }

        @Override
        public int hashCode() {
            return Objects.hash(name, quorum, approvals);
        }
    }

    public static class Approval {

        @NotNull
        private ApprovalType type;

        private String name;

        @NotEmpty
        private String value;

        public ApprovalType getType() {
            return type;
        }

        public void setType(ApprovalType type) {
            this.type = type;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return "Approval{" +
                    "type='" + type + '\'' +
                    ", name='" + name + '\'' +
                    ", value='" + value + '\'' +
                    '}';
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Approval approval = (Approval) o;
            return Objects.equals(type, approval.type) &&
                    Objects.equals(name, approval.name) &&
                    Objects.equals(value, approval.value);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, name, value);
        }
    }
}
