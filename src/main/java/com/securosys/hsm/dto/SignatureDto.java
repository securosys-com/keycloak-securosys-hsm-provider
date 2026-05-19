package com.securosys.hsm.dto;



public class SignatureDto {

	private String signature;

//	@NotEmpty
//	@Schema(description = "The message digest algorithm that was used for computing the request signature.",
//			example = "SHA-256",
//			allowableValues = { MessageDigestAlgorithms.SHA_224,
//					MessageDigestAlgorithms.SHA_256,
//					MessageDigestAlgorithms.SHA_384,
//					MessageDigestAlgorithms.SHA_512,
//					MessageDigestAlgorithms.SHA3_224,
//					MessageDigestAlgorithms.SHA3_256,
//					MessageDigestAlgorithms.SHA3_384,
//					MessageDigestAlgorithms.SHA3_512,
//			})
//	private String digestAlgorithm;

    private String signatureAlgorithm;

	private String publicKey = null;
	private String certificate = null;


	public String getSignature() {
		return signature;
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

//	public String getDigestAlgorithm() {
//		return digestAlgorithm;
//	}

//	public void setDigestAlgorithm(String digestAlgorithm) {
//		this.digestAlgorithm = digestAlgorithm;
//	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
