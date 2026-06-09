
package com.securosys.hsm.client.config;

import lombok.*;

/**
 * HSM connection configuration holding all credentials and connection parameters
 * for the Securosys Primus HSM.
 *
 * Note: connectionTimeout is stored as String and converted to milliseconds by HsmService
 */
/**
 * Data transfer object for Config.
 */
@Getter
@Setter
public abstract class Config {
    /** Default key label for operations */
    private String keyLabel;
    /** Key password for cryptographic operations */
    private String keyPassword;
}
