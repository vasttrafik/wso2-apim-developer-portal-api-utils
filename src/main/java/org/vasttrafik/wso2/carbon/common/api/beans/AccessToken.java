package org.vasttrafik.wso2.carbon.common.api.beans;

/**
 * @author Daniel Oskarsson <daniel.oskarsson@gmail.com>
 */
public class AccessToken {

    @SuppressWarnings("unused")
	private String token;
    @SuppressWarnings("unused")
	private String refreshToken;
    @SuppressWarnings("unused")
	private Long expires;
    
    public static AccessToken valueOf(final String token, final String refreshToken, final Long expires) {
        final AccessToken accessToken = new AccessToken();
        accessToken.token = token;
        accessToken.refreshToken = refreshToken;
        accessToken.expires=expires;
        return accessToken;
    }
}
