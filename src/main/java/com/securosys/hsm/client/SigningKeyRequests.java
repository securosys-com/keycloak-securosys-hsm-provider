package com.securosys.hsm.client;

import com.securosys.hsm.dto.AttributesDto;
import com.securosys.hsm.dto.CreateKeyDto;
import com.securosys.hsm.exception.BusinessException;
import com.securosys.hsm.exception.BusinessReason;

/** Builds the common key-creation request used by JCE and TSB clients. */
public final class SigningKeyRequests {
    private SigningKeyRequests() {
    }

    public static CreateKeyDto create(String keyLabel, String keyPassword, String signatureAlgorithm) {
        boolean ec = signatureAlgorithm != null && signatureAlgorithm.startsWith("ES");
        boolean rsa = signatureAlgorithm != null && signatureAlgorithm.startsWith("RS");
        if (!ec && !rsa) {
            throw new BusinessException(
                    "Cannot generate a signing key for algorithm '" + signatureAlgorithm + "'.",
                    BusinessReason.ERROR_ALGORITHM_NOT_SUPPORTED_BY_KEY);
        }

        AttributesDto attributes = new AttributesDto();
        attributes.setDecrypt(false);
        attributes.setSign(true);
        attributes.setUnwrap(false);
        attributes.setSensitive(true);
        attributes.setExtractable(false);
        attributes.setDestroyable(false);

        CreateKeyDto request = new CreateKeyDto();
        request.setLabel(keyLabel);
        request.setPassword(keyPassword == null ? null : keyPassword.toCharArray());
        request.setAlgorithm(ec ? "EC" : "RSA");
        request.setAttributes(attributes);
        if (ec) {
            request.setCurveOid("1.2.840.10045.3.1.7"); // secp256r1 / P-256
        } else {
            request.setKeySize(2048);
        }
        return request;
    }
}
