// Copyright (c) 2026 Securosys SA.
// SPDX-License-Identifier: MPL-2.0
package com.securosys.hsm.client;

/**
 * Normalized key attributes shared by JCE and TSB clients.
 */
public class HsmKeyAttributes {
    private final String label;
    private final String algorithm;
    private final String publicKey;
    private final String xml;
    private final String xmlSignature;
    private final String attestationKeyName;

    public HsmKeyAttributes(String label, String algorithm, String publicKey, String xml, String xmlSignature,
            String attestationKeyName) {
        this.label = label;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.xml = xml;
        this.xmlSignature = xmlSignature;
        this.attestationKeyName = attestationKeyName;
    }

    public String getLabel() {
        return label;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getXml() {
        return xml;
    }

    public String getXmlSignature() {
        return xmlSignature;
    }

    public String getAttestationKeyName() {
        return attestationKeyName;
    }
}
