package com.securosys.hsm.client.config;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@EqualsAndHashCode(callSuper = true)
@Data
@Builder
@NoArgsConstructor  // Necessary for many frameworks and @Data
@AllArgsConstructor // Necessary for @Builder to work on the class level
public class JceConfig extends Config {
    /** HSM host address (IP or hostname) */
    private String host;
    /** HSM port number as String (e.g., "2400") */
    private String port;
    /** HSM username for authentication */
    private String user;
    /** Setup password for initial HSM authentication */
    private String setupPassword;
    /** Proxy username if HSM access requires proxy */
    private String proxyUser;
    /** Proxy password if HSM access requires proxy */
    private String proxyPassword;
    /** Name of attestation key for certificate operations */
    private String attestationKeyName;
    /** Name of timestamp key for timestamp operations */
    private String timestampKeyName;
    /** Signature algorithm for timestamp operations */
    private String timestampSignatureAlgorithm;
    /** Connection timeout in milliseconds as String */
    private String connectionTimeout;
    /** Path to secret file for authentication */
    private String secretPath;


}
