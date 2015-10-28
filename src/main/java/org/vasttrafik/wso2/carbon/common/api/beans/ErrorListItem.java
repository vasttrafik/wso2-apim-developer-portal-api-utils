package org.vasttrafik.wso2.carbon.common.api.beans;

/**
 *
 * @author Daniel Oskarsson <daniel.oskarsson@gmail.com>
 */
public class ErrorListItem {

	private Long code;
	private String message;

	public Long getCode() {
		return code;
	}

	public void setCode(Long code) {
		this.code = code;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
