package com.securosys.hsm.dto;

import lombok.Data;

@Data
/**
 * Data transfer object for Config.
 */
public class Config {
    private HsmConfig hsm;
    private TsbConfig tsb;
}
