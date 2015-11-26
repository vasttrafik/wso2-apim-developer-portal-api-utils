package org.vasttrafik.wso2.carbon.common.api.utils;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;

import org.vasttrafik.wso2.carbon.common.api.beans.Error;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.ClientErrorException;
import javax.ws.rs.core.Response;

/**
 * @author Lars Andersson
 *
 */
public class ResponseUtils {

    private static Locale SWEDISH = new Locale("sv", "SE");
	
	public static void checkParameter(String resourceBundle, String parameterName, boolean required, String[] validValues, String value) throws BadRequestException {
		try {
			/**
			 * Check for missing required parameter value
			 */
			if (required && value == null) {
				value = "null";
				throw new Exception();
			}

			/**
			 * Check for valid parameter value
			 */
			if (value != null) {
				if (validValues != null && validValues.length > 0) {
					for (int i = 0; i < validValues.length; i++) {
						if (validValues[i].equalsIgnoreCase(value))
							return;
					}
					throw new Exception();
				}
			}
		}
		catch (Exception e) {
			throw new BadRequestException(badRequest(resourceBundle, 1000L, new Object[][]{{value},{parameterName}}));
		}
	}
	
	public static void preconditionFailed(String resourceBundle, Long code, Object[][] args) throws ClientErrorException {
		Error error = buildError(resourceBundle, code, args);
		Response response = Response.status(Response.Status.PRECONDITION_FAILED).entity(error).build();
		
		throw new ClientErrorException(response);
	}

	public static Response badRequest(String resourceBundle, Long code, Object[][] args) throws BadRequestException {
		Error error = buildError(resourceBundle, code, args);
		Response response = Response.status(Response.Status.BAD_REQUEST).entity(error).build();

		return response;
	}
	
	public static String getErrorMessage(String resourceBundle, String error, Object[] args) {
		AbstractErrorListResourceBundle bundle = (AbstractErrorListResourceBundle)
				ResourceBundle.getBundle(resourceBundle, SWEDISH, ResponseUtils.class.getClassLoader());
		
		if (bundle != null) {
			try {
				return bundle.getMessage(error, args);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
		return error;
	}
	
	public static Error buildError(String resourceBundle, Long code, Object[][] args) {
		AbstractErrorListResourceBundle bundle = (AbstractErrorListResourceBundle)
				ResourceBundle.getBundle(resourceBundle, SWEDISH, ResponseUtils.class.getClassLoader());
		
		if (bundle != null) {
			try {
				return bundle.getError(code, args);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
		return new Error();
	}
	
	public static Response buildError(int status, Long code, String message, String description, String moreInfo) {
		Error error = new Error();
		error.setCode(code);
		error.setMessage(message);
		error.setDescription(description);
		error.setMoreInfo(moreInfo);
		return Response.status(status).entity(error).build();
	}

	public static Response serverError(Exception e) {
		Error error = new Error();
		error.setMessage(e.getMessage());

		Throwable t = e.getCause();

		if (t != null) {
			OutputStream os = new ByteArrayOutputStream();
			PrintWriter writer = new PrintWriter(os);
			t.printStackTrace(writer);
			error.setDescription("Cause:" + t.getMessage());
			error.setMoreInfo(writer.toString());
		}

		return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
	}

	public static Response notAuthorizedError(Exception e) {
		Error error = new Error();
		error.setMessage(e.getMessage());

		Throwable t = e.getCause();

		if (t != null) {
			OutputStream os = new ByteArrayOutputStream();
			PrintWriter writer = new PrintWriter(os);
			t.printStackTrace(writer);
			error.setDescription("Cause:" + t.getMessage());
			error.setMoreInfo(writer.toString());
		}

		return Response.status(Response.Status.UNAUTHORIZED).entity(error).build();
	}

	public static Response serverError(String resourceBundle, Long code, Object[][] args) {
		final Error error = buildError(resourceBundle, code, args);
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
	}

	public static Response notAuthorizedError(String resourceBundle, Long code, Object[][] args) {
		final Error error = buildError(resourceBundle, code, args);
		return Response.status(Response.Status.UNAUTHORIZED).entity(error).build();
	}

	public static Response notFound(String resourceBundle, Long code, Object[][] args) {
		final Error error = buildError(resourceBundle, code, args);
		return Response.status(Response.Status.NOT_FOUND).entity(error).build();
	}

}