package org.vasttrafik.wso2.carbon.identity.oauth.authcontext;

import com.nimbusds.jwt.JWTClaimsSet;

public final class JWTToken {
	
	private JWTClaimsSet claimsSet;
	
	private String token;
	
	public JWTToken(JWTClaimsSet claimsSet, String token) {
		this.claimsSet = claimsSet;
		this.token = token;
	}
	
	public String getToken() {
		return token;
	}
	
	public String getEndUserName() {
		try {
			return claimsSet.getStringClaim("http://wso2.org/gateway/enduser");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public Integer getEndUserId() {
		String userId = null;
		try {
			userId = claimsSet.getStringClaim("http://wso2.org/claims/identity/id");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return (userId != null ? Integer.valueOf(userId) : null);
	}
	
	public String[] getEndUserRoles() {
		String userRoles = null;
		try {
			userRoles = claimsSet.getStringClaim("http://wso2.org/claims/role");
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return (userRoles != null ? userRoles.split(",") : null);
	}
	
	public Long getIssuedTime() {
		return claimsSet.getIssueTime().getTime();
	}
	
	public Long getExpirationTime() {
		long expirationTime = 0L;
		try {
			return claimsSet.getLongClaim("http://wso2.org/gateway/exp");     
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return expirationTime;
	}
	
	public boolean hasExpired() {
		long now = System.currentTimeMillis();
		
		if (now > getExpirationTime())
			return true;
		else
			return false;
	}
	
	public boolean isAccountLocked() {
		boolean locked = false;
		
		try {
			locked = Boolean.valueOf(claimsSet.getStringClaim(
					"http://wso2.org/claims/identity/accountLocked"));
		}
		catch (Exception e) {}
		
		return locked;
	}
}
