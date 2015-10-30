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
		String userName = null;
		String token = extractTokenFromAuthHeader(authHeader);

		if (token == null) {
			throw new Exception("Authorization header missing or invalid");
		}

		try {
			ClientUtils.authenticateIfNeeded(oauthStub._getServiceClient());

			OAuth2TokenValidationRequestDTO requestDTO = new OAuth2TokenValidationRequestDTO();
			OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessToken = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
			accessToken.setIdentifier(token);
			accessToken.setTokenType("bearer");
			requestDTO.setAccessToken(accessToken);
			OAuth2TokenValidationRequestDTO_TokenValidationContextParam[] context = new OAuth2TokenValidationRequestDTO_TokenValidationContextParam[0];
			requestDTO.setContext(context);
			OAuth2TokenValidationResponseDTO responseDTO = oauthStub.validate(requestDTO);

			if (!responseDTO.getValid()) {
				throw new Exception(responseDTO.getErrorMsg());
			} else {
				userName = responseDTO.getAuthorizedUser();
			}

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

	private static String extractTokenFromAuthHeader(String authHeader) {
		final String oauthHeaderSplitter = ",";
		final String consumerKeySegmentDelimiter = " ";
		final String consumerKeyHeaderSegment = " ";

		if (authHeader == null) {
			return null;
		}

		if (authHeader.startsWith("OAuth ") || authHeader.startsWith("oauth ")) {
			authHeader = authHeader.substring(authHeader.indexOf("o"));
		}

		String[] headers = authHeader.split(oauthHeaderSplitter);

		if (headers != null) {
			for (String header : headers) {
				String[] elements = header.split(consumerKeySegmentDelimiter);
				if (elements != null && elements.length > 1) {
					int j = 0;
					boolean isConsumerKeyHeaderAvailable = false;

					for (String element : elements) {
						if (!"".equals(element.trim())) {
							if (consumerKeyHeaderSegment.equals(elements[j].trim())) {
								isConsumerKeyHeaderAvailable = true;
							} else if (isConsumerKeyHeaderAvailable) {
								return removeLeadingAndTrailing(elements[j].trim());
							}
						}
						j++;
					}
				}
			}
		}
		return null;
	}

	private static String removeLeadingAndTrailing(String base) {
		String result = base;

		if (base.startsWith("\"") || base.endsWith("\"")) {
			result = base.replace("\"", "");
		}
		return result.trim();
	}

}
