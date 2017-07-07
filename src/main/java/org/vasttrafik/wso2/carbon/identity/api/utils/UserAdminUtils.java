package org.vasttrafik.wso2.carbon.identity.api.utils;

import org.vasttrafik.wso2.carbon.common.api.utils.ClientUtils;
import org.wso2.carbon.um.ws.api.stub.ClaimDTO;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_TokenValidationContextParam;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;

import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotAuthorizedException;

/**
 * @author Lars Andersson
 *
 */
public class UserAdminUtils {

	private static final OAuth2TokenValidationServiceStub oauthStub = ClientUtils.getOAuth2TokenValidationServiceStub();
	private static final RemoteUserStoreManagerServiceStub userStoreStub = ClientUtils.getRemoteUserStoreManagerServiceStub();

	public static String validateToken(Integer userId, String authHeader) throws Exception {
		try {
			String userName = validateToken(authHeader);

			ClientUtils.authenticateIfNeeded(userStoreStub._getServiceClient());
			Integer realUserId = userStoreStub.getUserId(userName);

			if (!realUserId.equals(userId)) {
				throw new Exception("Unauthorized");
			} else {
				return userName;
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static String validateToken(String authHeader) throws Exception {

		final String[] values = authHeader == null ? new String[0] : authHeader.split(" ");
		if (values.length != 2 || !"bearer".equalsIgnoreCase(values[0])) {
			throw new Exception("Authorization header missing or invalid");
		}
		final String token = values[1];

		try {
			ClientUtils.authenticateIfNeeded(oauthStub._getServiceClient());

			OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
			OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessToken = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
			accessToken.setIdentifier(token);
			accessToken.setTokenType("bearer");
			requestDTO.setAccessToken(accessToken);
			OAuth2TokenValidationRequestDTO_TokenValidationContextParam[] context = new OAuth2TokenValidationRequestDTO_TokenValidationContextParam[1];
			OAuth2TokenValidationRequestDTO_TokenValidationContextParam item = new OAuth2TokenValidationRequestDTO_TokenValidationContextParam();
			context[0] = item;
			requestDTO.setContext(context);
			OAuth2TokenValidationResponseDTO responseDTO = oauthStub.validate(requestDTO);

			String userName = null;
			if (!responseDTO.getValid()) {
				throw new Exception(responseDTO.getErrorMsg());
			} else {
				userName = responseDTO.getAuthorizedUser();
			}

			return userName;
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
	}

	public static void authenticateCredentials(final String userName, final String credential) {
		try {
			ClientUtils.authenticateIfNeeded(userStoreStub._getServiceClient());
			if (!userStoreStub.authenticate(userName, credential)) {
				throw new NotAuthorizedException("Unauthorized");
			}
		} catch (final Exception exception) {
			throw new InternalServerErrorException(exception);
		}
	}
	public static int getUserId(final String userName) {
		try {
			ClientUtils.authenticateIfNeeded(userStoreStub._getServiceClient());
			return userStoreStub.getUserId(userName);
		} catch (final Exception exception) {
			throw new InternalServerErrorException(exception);
		}
	}
	public static String getUserClaimValue(final String userName, final String claimUri, final String profileName) {
		try {
			ClientUtils.authenticateIfNeeded(userStoreStub._getServiceClient());
			
			for(ClaimDTO claimDTO : userStoreStub.getUserClaimValues(userName, profileName)) {
				if(claimDTO.getClaimUri().equals(claimUri)) {
					return claimDTO.getValue();
				}
			}
			return null;

		} catch (final Exception exception) {
			exception.printStackTrace();
			throw new InternalServerErrorException(exception);
		}
	}
}
