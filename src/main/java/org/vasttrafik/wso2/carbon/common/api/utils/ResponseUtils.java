package org.vasttrafik.wso2.carbon.common.api.utils;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;
import org.vasttrafik.wso2.carbon.common.api.beans.Error;

/**
 * @author Lars Andersson
 *
 */
public class ResponseUtils {

	public static void checkParameter(String parameterName, boolean required, String[] validValues, String value) throws BadRequestException {
		try {
			/**
			 * Check for missing required parameter value
			 */
			if (required && value == null) {
				throw new Exception();
			}

			/**
			 * Check for valid parameter value
			 */
			if (value != null) {
				if (validValues != null && validValues.length > 0) {
					for (int i = 0; i < validValues.length; i++) {
						if (validValues[i].equalsIgnoreCase(value)) {
							return;
						}
					}
					throw new Exception();
				}
			}
		} catch (Exception e) {
			Response response = invalidRequestParameter(parameterName);
			throw new BadRequestException(response);
		}
	}

	public static Response invalidRequestParameter(String parameterName) {
		String message = "Ogiltigt v�rde f�r parameter.";
		String description = "Parametern " + parameterName + " saknas eller �r ogiltigt.";
		return buildError(400, 400L, message, description, "");
	}

	public static Response badRequest(String message, String description, String moreInfo) {
		return buildError(400, 400L, message, description, moreInfo);
	}

	public static Response unauthorized(String message, String description, String moreInfo) {
		return buildError(401, 401L, message, description, moreInfo);
	}

	public static Response notFound(String resource) {
		String message = "Den efterfr�gade resursen saknas.";
		String description = "Resursen " + resource + " saknas p� servern";
		Response response = buildError(404, 404L, message, description, "");
		return response;
	}

	public static Response buildError(int status, Long code, String message, String description, String moreInfo) {
		Error error = new Error();
		error.setCode(code);
		error.setMessage(message);
		error.setDescription(description);
		error.setMoreInfo(moreInfo);
		return Response.status(status).entity(error).build();
	}
}
