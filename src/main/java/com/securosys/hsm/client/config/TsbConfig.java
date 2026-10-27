package com.securosys.hsm.client.config;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
@Builder
public class TsbConfig extends Config {
    private String tsbUrl;
    private String auth;
    private String bearerToken;
    private String mtlsP12Path;
    private String mtlsP12Password;
    private String keyOperationApiKey;
    private String keyManagementApiKey;



}
