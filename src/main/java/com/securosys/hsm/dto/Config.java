package com.securosys.hsm.dto;

import com.securosys.hsm.service.HsmService;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
public class Config {
    private String port;
    private String host;
    private String user;
    private String setupPassword;
    private String keyLabel;
    private String keyPassword;
    private String proxyUser;
    private String proxyPassword;
    private String attestationKeyName;
    private String connectionTimeout;
    private String secretPath;
}
