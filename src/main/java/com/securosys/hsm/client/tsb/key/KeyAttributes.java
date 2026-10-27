// Copyright (c) 2025 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client.tsb.key;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.securosys.hsm.client.tsb.policy.Policy;

/**
 * DTO for key attributes
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class KeyAttributes {
    private String id;
    private String uuid;
    private String label;
    private Map<String, Boolean> attributes;
    private double keySize;
    private int keyUsageCount;
    private String createTime;
    private String attestTime;
    private Policy policy;
    private Map<String, Object> derivedAttributes;
    private String publicKey;
    private String algorithm;
    private String algorithmOid;
    private String curveOid;
    private String version;
    private boolean active;
    private String xml;
    private String xmlSignature;
    private String attestationKeyName;

    public KeyAttributes() {}

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }

    public Map<String, Boolean> getAttributes() { return attributes; }
    public void setAttributes(Map<String, Boolean> attributes) { this.attributes = attributes; }

    public double getKeySize() { return keySize; }
    public void setKeySize(double keySize) { this.keySize = keySize; }

    public Policy getPolicy() { return policy; }
    public void setPolicy(Policy policy) { this.policy = policy; }

    public Map<String, Object> getDerivedAttributes() { return derivedAttributes; }
    public void setDerivedAttributes(Map<String, Object> derivedAttributes) { this.derivedAttributes = derivedAttributes; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    public String getAlgorithmOid() { return algorithmOid; }
    public void setAlgorithmOid(String algorithmOid) { this.algorithmOid = algorithmOid; }

    public String getCurveOid() { return curveOid; }
    public void setCurveOid(String curveOid) { this.curveOid = curveOid; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public String getXml() { return xml; }
    public void setXml(String xml) { this.xml = xml; }

    public String getXmlSignature() { return xmlSignature; }
    public void setXmlSignature(String xmlSignature) { this.xmlSignature = xmlSignature; }

    public String getAttestationKeyName() { return attestationKeyName; }
    public void setAttestationKeyName(String attestationKeyName) { this.attestationKeyName = attestationKeyName; }

    public String getUuid() { return uuid; }
    public void setUuid(String uuid) { this.uuid = uuid; }

    public int getKeyUsageCount() { return keyUsageCount; }
    public void setKeyUsageCount(int keyUsageCount) { this.keyUsageCount = keyUsageCount; }

    public String getCreateTime() { return createTime; }
    public void setCreateTime(String createTime) { this.createTime = createTime; }

    public String getAttestTime() { return attestTime; }
    public void setAttestTime(String attestTime) { this.attestTime = attestTime; }
}
