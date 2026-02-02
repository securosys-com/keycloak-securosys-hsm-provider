/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: 136 $
 * Date of last edit : $Date: 2016-05-09 14:39:52 +0200 (Mon, 09 May 2016) $
 */

package com.securosys.hsm.exception;

public class TechnicalException extends ReasonBasedException {

	private static final long serialVersionUID = 1L;

	public TechnicalException(String message, TechnicalReason reason, Throwable cause) {
		super(message, reason, cause);
	}

	public TechnicalException(String message, TechnicalReason reason) {
		super(message, reason);
	}

}
