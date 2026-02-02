package com.securosys.hsm.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class HsmConfig {
    private String host;
    private int port;
    private String user;

    @JsonProperty("setupPassword")
    private String setupPassword;

    private String proxyUser;
    private String proxyPassword;
    private String attestationKeyName;
    private String secretPath;
    private String keyLabel;
    private String keyPassword;
    private String algorithm;

}