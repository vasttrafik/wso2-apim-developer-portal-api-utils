package org.vasttrafik.wso2.carbon.common.api.beans;

/**
 * @author Daniel Oskarsson <daniel.oskarsson@gmail.com>
 */
public class Credentials {

    private String userName;
    private String credential;
    private String totp;

    public String getUserName() {
        return userName;
    }

    public String getCredential() {
        return credential;
    }

	public String getTotp() {
		return totp;
	}

	public void setTotp(String totp) {
		this.totp = totp;
	}
}
