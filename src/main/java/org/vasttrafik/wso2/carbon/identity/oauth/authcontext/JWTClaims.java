package org.vasttrafik.wso2.carbon.identity.oauth.authcontext;

import net.minidev.json.JSONObject;

public final class JWTClaims {
	
	private JSONObject claims;
	
	public JWTClaims(JSONObject claims) throws IllegalArgumentException {
		if (claims == null)
			throw new IllegalArgumentException("Null claim object");
		else
			this.claims = claims;
	}
	
	public String getEndUser() {
		return (String)claims.get("http://wso2.org/gateway/enduser");
	}
	
	public Integer getEndUserId() {
		String userId = (String)claims.get("http://wso2.org/claims/identity/id");
		return Integer.valueOf(userId);
	}
	
	public String[] getUserRoles() {
		String roles = (String)claims.get("http://wso2.org/claims/role");
		
		if (roles != null) 
			return roles.split(",");
		else
			return new String[0];
	}
	
	public boolean isAccountLocked() {
		String locked = (String)claims.get("http://wso2.org/claims/identity/accountLocked");
		
		if (locked != null)
			return Boolean.valueOf(locked);
		else
			return false;
	}
	
	public boolean hasExpired() {
		Object expires = claims.get("http://wso2.org/gateway/exp");
		
		if (expires != null && expires instanceof Long) {
			long now = System.currentTimeMillis();
			
			if (now > (Long)expires)
				return true;
			else
				return false;
		}
		return true;
	}
}
