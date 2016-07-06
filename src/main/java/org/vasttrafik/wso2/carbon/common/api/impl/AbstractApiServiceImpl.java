package org.vasttrafik.wso2.carbon.common.api.impl;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.ws.rs.NotAuthorizedException;

import org.vasttrafik.wso2.carbon.common.api.beans.AuthenticatedUser;
import org.vasttrafik.wso2.carbon.common.api.beans.Error;
import org.vasttrafik.wso2.carbon.common.api.utils.ResponseUtils;
import org.vasttrafik.wso2.carbon.identity.oauth.authcontext.JWTToken;
import org.vasttrafik.wso2.carbon.identity.oauth.authcontext.JWTTokenValidator;

/**
 * Base class for API resources.
 * @author Lars Andersson, Västtrafik AB
 *
 */
public abstract class AbstractApiServiceImpl {
	
	/**
	 * Claims body retrieved from JWT token
	 */
	protected AuthenticatedUser authenticatedUser;
	
	/**
	 * Default constructor
	 */
	public AbstractApiServiceImpl() {
	}
	
	/**
	 * Authorizes the request by validating the JWT token supplied as parameter authorization,
	 * @param authorization A JWT token
	 * @throws NotAuthorizedException If token is missing, invalid or has expired
	 */
	protected AuthenticatedUser authorize(String authorization) throws NotAuthorizedException {
		boolean authorized = false;
		long errorCode = 1101L; // Token has expired;
		
		if (authorization != null) {
			// Create a JWT validator and validate token
			JWTTokenValidator jwtValidator = new JWTTokenValidator(authorization);
			
			if (jwtValidator.isValid()) {
				JWTToken jwtToken = jwtValidator.getJWTToken();
			
				// Make sure the token hasn't expired
				if (!jwtToken.hasExpired() && !jwtToken.isAccountLocked()) {
					authenticatedUser = new AuthenticatedUser(jwtToken);
					authorized = true;
				}
			}
			else {
				errorCode = 1102L; // Invalid token
			}
		} 
		else {
			errorCode = 1105L; // Token is missing
		}
		
		if (!authorized) {
			ResponseUtils responseUtils = getResponseUtils();
			Error error = responseUtils.buildError(errorCode, null);
			throw new NotAuthorizedException(error);
		}
		
		return authenticatedUser;
	}
	
	/**
	 * Retrieves the end user id from the JWT token that was used to authorize
	 * @return The end user id found in the JWT token
	 * @throws NotAuthorizedException If the request was never authorized with a prior 
	 * call to the authorize method
	 */
	protected Integer getEndUserId() throws NotAuthorizedException {
		assertAuthenticatedUser();
		return authenticatedUser.getUserId();
	}
	
	/**
	 * Retrieves the end user name from the JWT token that was used to authorize
	 * @return The end user name found in the JWT token
	 * @throws NotAuthorizedException If the request was never authorized with a prior 
	 * call to the authorize method
	 */
	protected String getEndUserName() throws NotAuthorizedException {
		assertAuthenticatedUser();
		return authenticatedUser.getUserName();
	}
	
	/**
	 * Retrieves the end user roles from the JWT token that was used to authorize
	 * @return A list of user roles found in the JWT token
	 * @throws NotAuthorizedException If the request was never authorized with a prior 
	 * call to the authorize method
	 */
	protected String[] getUserRoles() throws NotAuthorizedException {
		assertAuthenticatedUser();
		return authenticatedUser.getRoles();
	}
	
	/**
	 * Checks if the JWT token used to authorize contains a roles claim that
	 * contains the role supplied as parameter role
	 * @param role The role to check for in the JWT token
	 * @return true if the role was found, false otherwise
	 * @throws NotAuthorizedException If the request was never authorized with a prior 
	 * call to the authorize method
	 */
	protected boolean hasRole(String role) throws NotAuthorizedException {
		assertAuthenticatedUser();
		
		String[] roles = authenticatedUser.getRoles();
		for (String s : roles)
			if (s.equalsIgnoreCase(role))
				return true;
		
		return false;
	}
	
	/**
	 * Checks if the JWT token used to authorize contains a roles claim that
	 * contains the admin role
	 * @return true if the role was found, false otherwise
	 * @throws NotAuthorizedException If the request was never authorized with a prior 
	 * call to the authorize method
	 */
	protected boolean isAdmin() throws NotAuthorizedException {
		assertAuthenticatedUser();
		return hasRole("community-admin");
	}
	
	/**
	 * Asserts that the end user id claim of the JWT token is the same as another id, 
	 * or that the user is an admin
	 * @param enityId The id to check
	 * @return true if the id's match or the user is an admin
	 */
	protected boolean isOwnerOrAdmin(Object entityId) throws NotAuthorizedException {
		Integer endUserId = getEndUserId();
		return ((endUserId != null && endUserId.equals(entityId)) || isAdmin());
	}
	
	/**
	 * Convert a date formatted according to the RFC 822 format to ISO 8601 format.
	 * @param ifModifiedSince HTTP header containing RFC 822 formatted date string
	 * @return Date string formatted according to ISO 8601
	 * @throws ParseException
	 */
	protected String rfc822ToISO8601Date(String ifModifiedSince) throws ParseException {
		if (ifModifiedSince != null && !"".equals(ifModifiedSince)) {
			SimpleDateFormat rfc822  = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z");
			SimpleDateFormat iso8601 = new SimpleDateFormat("yyyy-mm-DD'T'HH:mm:ss");
		
			Date rfc822Date = rfc822.parse(ifModifiedSince);
			return iso8601.format(rfc822Date);
		}
		else {
			return null;
		}
	}
	
	protected abstract ResponseUtils getResponseUtils();
	
	/**
	 * Makes sure we are authorized and have a JWT validator
	 * @throws NotAuthorizedException
	 */
	private void assertAuthenticatedUser() throws NotAuthorizedException {
		if (authenticatedUser == null) {
			ResponseUtils responseUtils = getResponseUtils();
			Error error = responseUtils.buildError(1101L, null);
			throw new NotAuthorizedException(error);
		}
	}
}
