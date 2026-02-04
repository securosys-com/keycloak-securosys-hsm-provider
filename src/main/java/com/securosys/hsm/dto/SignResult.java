package com.securosys.hsm.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SignResult {
    private byte[] signature;
    private byte[] publicNonce;
}