/*
 * Author            : AdNovum Informatik AG
 * Version Number    : $Revision: 136 $
 * Date of last edit : $Date: 2016-05-09 14:39:52 +0200 (Mon, 09 May 2016) $
 */

package com.securosys.hsm.exception;

public class BusinessException extends ReasonBasedException {

	private static final long serialVersionUID = 1L;

	public BusinessException(String message, BusinessReason reason, Throwable cause) {
		super(message, reason, cause);
	}

	public BusinessException(String message, BusinessReason reason) {
		super(message, reason);
	}

}
