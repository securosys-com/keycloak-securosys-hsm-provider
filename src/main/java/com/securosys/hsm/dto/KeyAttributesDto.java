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

import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlRootElement;
import com.securosys.hsm.dto.AddressTruncatedDto;
import com.securosys.hsm.dto.DerivedKeyAttributesDto;
import lombok.Data;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

@Data
@SuppressWarnings("unused")
@JacksonXmlRootElement(localName = "private_key")
public class KeyAttributesDto {

    private String label;

    private String id;
    private String uuid;

    private String algorithm;

    @JacksonXmlProperty(localName = "algorithm_oid")
    private String algorithmOid;

    @JacksonXmlProperty(localName = "curve_oid")
    private String curveOid;

    @JacksonXmlProperty(localName = "derivation_value")
    private DerivedKeyAttributesDto derivedAttributes;

    @JacksonXmlProperty(localName = "key_size")
    private Integer keySize;

    @JacksonXmlProperty(localName = "create_time")
    private String createTime;

    @JacksonXmlProperty(localName = "attest_time")
    private String attestTime;

    @JacksonXmlProperty(localName = "public_key")
    private String publicKey;

    @JacksonXmlProperty(localName = "address_truncated")
    private AddressTruncatedDto addressTruncated;

    private Attributes attributes;

    private PolicyDto policy;

    @Data
    public static class Attributes {

        private Boolean decrypt;

        private Boolean sign;

        @JacksonXmlProperty(localName = "eka_sign")
        private Boolean ekaSign;

        private Boolean unwrap;

        private Boolean derive;

        private Boolean sensitive;

        @JacksonXmlProperty(localName = "always_sensitive")
        private Boolean alwaysSensitive;

        private Boolean extractable;

        @JacksonXmlProperty(localName = "never_extractable")
        private Boolean neverExtractable;

        private Boolean modifiable;

        private Boolean copyable;

        private Boolean destroyable;
    }
}
