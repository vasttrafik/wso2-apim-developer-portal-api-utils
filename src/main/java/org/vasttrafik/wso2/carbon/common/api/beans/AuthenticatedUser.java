package org.vasttrafik.wso2.carbon.common.api.beans;

import org.vasttrafik.wso2.carbon.identity.oauth.authcontext.JWTToken;

/**
 * @author Daniel Oskarsson <daniel.oskarsson@gmail.com>
 */
public class AuthenticatedUser {

    private Integer userId;
    private String userName;
    private String[] roles;
    private AccessToken accessToken;
    private boolean enabledTotp = false;
    
    public AuthenticatedUser() {	
    }
    
    public AuthenticatedUser(JWTToken jwtToken) {
    	if (jwtToken != null) {
    		userId = jwtToken.getEndUserId();
    		userName = jwtToken.getEndUserName();
    		roles = jwtToken.getEndUserRoles();
    		accessToken = AccessToken.valueOf(
    				jwtToken.getToken(), 
    				null, 
    				jwtToken.getExpirationTime());
    	}
    }

	public Integer getUserId() {
		return userId;
	}

	public void setUserId(Integer userId) {
		this.userId = userId;
	}

	public String getUserName() {
		return userName;
	}

	public void setUserName(String userName) {
		this.userName = userName;
	}

	public String[] getRoles() {
		return roles;
	}

	public void setRoles(String[] roles) {
		this.roles = roles;
	}

	public AccessToken getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(AccessToken accessToken) {
		this.accessToken = accessToken;
	}
    
    public boolean isEnabledTotp() {
		return enabledTotp;
	}

	public void setEnabledTotp(boolean enabledTotp) {
		this.enabledTotp = enabledTotp;
	}

	public boolean hasRole(String role) {
    	if (roles != null) {
    		for (String s : roles)
    			if (s.equalsIgnoreCase(role))
    				return true;
    	}
    	return false;
    }
    
    public static AuthenticatedUser valueOf(
    		final Integer userId, 
    		final String userName, 
    		final String[] roles,
    		final AccessToken accessToken
    ) 
    {
        final AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserId(userId);
        authenticatedUser.setUserName(userName);
        authenticatedUser.setRoles(roles);
        authenticatedUser.setAccessToken(accessToken);
        return authenticatedUser;
    }
}
