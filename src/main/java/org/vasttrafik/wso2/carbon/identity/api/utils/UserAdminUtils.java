package org.vasttrafik.wso2.carbon.identity.api.utils;

import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_TokenValidationContextParam;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;

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

		final String[] values = authHeader.split(" ");
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
			OAuth2TokenValidationRequestDTO_TokenValidationContextParam[] context = new OAuth2TokenValidationRequestDTO_TokenValidationContextParam[0];
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

}
