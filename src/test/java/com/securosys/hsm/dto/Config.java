package com.securosys.hsm.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class Config {
    private HsmConfig hsm;

    // Getter i Setter
    public HsmConfig getHsm() { return hsm; }
    public void setHsm(HsmConfig hsm) { this.hsm = hsm; }
}
