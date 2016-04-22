package org.vasttrafik.wso2.carbon.identity.oauth.authcontext;

import java.util.SortedMap;

//import org.wso2.carbon.user.api.UserStoreException;
//import org.wso2.carbon.user.api.UserStoreManager;
//import org.wso2.carbon.base.MultitenantConstants;
//import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authcontext.DefaultClaimsRetriever;

import org.vasttrafik.wso2.carbon.identity.api.utils.UserAdminUtils;

public class JWTClaimsRetriever extends DefaultClaimsRetriever {

    @Override
	public SortedMap<String, String> getClaims(String endUserName, String[] requestedClaims) throws IdentityOAuth2Exception {
	    // Get the default claims
	    SortedMap<String, String> claimValues = super.getClaims(endUserName, requestedClaims);
		
		/*try {
		    // Get a user store manager
		    UserStoreManager userStoreManager = OAuthComponentServiceHolder.getRealmService()
			    .getTenantUserRealm(MultitenantConstants.SUPER_TENANT_ID)
				.getUserStoreManager();
				
			if (userStoreManager == null)
			    throw new IdentityOAuth2Exception("Failed to retrieve user store manager");
				
		    // Get the user id
			int userId = userStoreManager.getUserId(endUserName);
			// Put it in the claims map
			claimValues.put("http://wso2.org/claims/identity/id", String.valueOf(userId));
            // Return result
            return claimValues;		
		}
		catch (UserStoreException use) {
		    throw new IdentityOAuth2Exception("Failed to retrieve user id from user store:" + use.getMessage());
		}*/
		try {
			// Get the user id
			int userId = UserAdminUtils.getUserId(endUserName);
			// Put it in the claims map
			claimValues.put("http://wso2.org/claims/identity/id", String.valueOf(userId));
            // Return result
            return claimValues;		
		}
		catch (Exception e) {
			throw new IdentityOAuth2Exception("Failed to retrieve user id:" + e.getMessage());
		}
	}
}