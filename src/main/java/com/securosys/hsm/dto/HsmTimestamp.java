
package com.securosys.hsm.dto;

/**
 * Data transfer object for HsmTimestamp.
 */
public class HsmTimestamp {

	private byte[] payload;

	private byte[] timestamp;

	private byte[] timestampSignature;

	private String integrityKeyName;

	public HsmTimestamp(byte[] payload, byte[] timestamp, byte[] timestampSignature, String integrityKeyName) {
		this.payload = payload;
		this.timestamp = timestamp;
		this.timestampSignature = timestampSignature;
		this.integrityKeyName = integrityKeyName;
	}

	public byte[] getTimestamp() {
		return timestamp;
	}

	public byte[] getTimestampSignature() {
		return timestampSignature;
	}

	public byte[] getPayload() {
		return payload;
	}

	public String getIntegrityKeyName() {
		return integrityKeyName;
	}

}
