package com.securosys.hsm.dto;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
/**
 * Data transfer object for TsbConfig.
 */
public class TsbConfig{
    private String tsbUrl;
    private String auth;
    private String bearerToken;
    private String mtlsP12Path;
    private String mtlsP12Password;
    private String keyOperationApiKey;
    private String keyManagementApiKey;
    private String keyLabel;
    private String keyPassword;
    private String algorithm;
}
