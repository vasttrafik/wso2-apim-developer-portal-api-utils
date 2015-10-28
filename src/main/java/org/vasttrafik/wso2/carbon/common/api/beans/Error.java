package org.vasttrafik.wso2.carbon.common.api.beans;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Daniel Oskarsson <daniel.oskarsson@gmail.com>
 */
public class Error {

	private Long code;
	private String message;
	private String description;
	private String moreInfo;
	private List<ErrorListItem> items = new ArrayList<ErrorListItem>();

	public Error() {
	}

	public Error(Long code, String message) {
		this.code = code;
		this.message = message;
	}

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

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getMoreInfo() {
		return moreInfo;
	}

	public void setMoreInfo(String moreInfo) {
		this.moreInfo = moreInfo;
	}

	public List<ErrorListItem> getItems() {
		return items;
	}

	public void setItems(List<ErrorListItem> items) {
		this.items = items;
	}

}
