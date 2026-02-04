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



public class SignedKeyAttributesDto {

    private String xml;

    private KeyAttributesDto json;

    private String xmlSignature;

    private String attestationKeyName;

    public String getXml() {
        return xml;
    }

    public void setXml(String xml) {
        this.xml = xml;
    }

    public KeyAttributesDto getJson() {
        return json;
    }

    public void setJson(KeyAttributesDto json) {
        this.json = json;
    }

    public String getXmlSignature() {
        return xmlSignature;
    }

    public void setXmlSignature(String xmlSignature) {
        this.xmlSignature = xmlSignature;
    }

    public String getAttestationKeyName() {
        return attestationKeyName;
    }

    public void setAttestationKeyName(String attestationKeyName) {
        this.attestationKeyName = attestationKeyName;
    }

    @Override
    public String toString() {
        return "SignedKeyAttributesDto{" +
                "xml='" + xml + '\'' +
                ", json=" + json +
                ", xmlSignature='" + xmlSignature + '\'' +
                ", attestationKeyName='" + attestationKeyName + '\'' +
                '}';
    }
}
