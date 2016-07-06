package org.vasttrafik.wso2.carbon.common.api.utils;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Locale;
import java.util.ResourceBundle;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.ClientErrorException;
import javax.ws.rs.core.Response;

import org.vasttrafik.wso2.carbon.common.api.beans.Error;
import org.vasttrafik.wso2.carbon.common.api.utils.AbstractErrorListResourceBundle;

/**
 * @author Lars Andersson
 *
 */
public class ResponseUtils {
	
	/**
	 * Resource bundle to use when constructing messages and responses
	 */
	private AbstractErrorListResourceBundle resourceBundle = null;
	
	/**
	  * Default locale
	  */
	private static Locale SWEDISH = new Locale("sv", "SE");
	
    public ResponseUtils(AbstractErrorListResourceBundle resourceBundle) {
    	this.resourceBundle = resourceBundle;
    }
	
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
	
	public void checkParameter(String parameterName, boolean required, String[] validValues, String value) throws BadRequestException {
		try {
			
			if (required && value == null) {
				value = "null";
				throw new Exception();
			}

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
			throw new BadRequestException(badRequest(1000L, new Object[][]{{value},{parameterName}}));
		}
	}
	
	public static void preconditionFailed(String resourceBundle, Long code, Object[][] args) throws ClientErrorException {
		Error error = buildError(resourceBundle, code, args);
		Response response = Response.status(Response.Status.PRECONDITION_FAILED).entity(error).build();
		
		throw new ClientErrorException(response);
	}
	
	public void preconditionFailed(Long code, Object[][] args) throws ClientErrorException {
		Error error = buildError(code, args);
		Response response = Response.status(Response.Status.PRECONDITION_FAILED).entity(error).build();
		throw new ClientErrorException(response);
	}
	
	public static Response badRequest(String resourceBundle, Long code, Object[][] args) throws BadRequestException {
		Error error = buildError(resourceBundle, code, args);
		Response response = Response.status(Response.Status.BAD_REQUEST).entity(error).build();
		return response;
	}

	public Response badRequest(Long code, Object[][] args) throws BadRequestException {
		Error error = buildError(code, args);
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
	
	public String getErrorMessage(String error, Object[] args) {
		if (resourceBundle != null) {
			try {
				return resourceBundle.getMessage(error, args);
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
	
	public Error buildError(Long code, Object[][] args) {
		if (resourceBundle != null) {
			try {
				return resourceBundle.getError(code, args);
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		}
		return new Error();
	}
	
	public static Response serverError(String resourceBundle, Long code, Object[][] args) {
		final Error error = buildError(resourceBundle, code, args);
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
	}
	
	public Response serverError(Long code, Object[][] args) {
		final Error error = buildError(code, args);
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
	}
	
	public static Response notAuthorizedError(String resourceBundle, Long code, Object[][] args) {
		final Error error = buildError(resourceBundle, code, args);
		return Response.status(Response.Status.UNAUTHORIZED).entity(error).build();
	}

	public Response notAuthorizedError(Long code, Object[][] args) {
		final Error error = buildError(code, args);
		return Response.status(Response.Status.UNAUTHORIZED).entity(error).build();
	}
	
	public static Response notFound(String resourceBundle, Long code, Object[][] args) {
		final Error error = buildError(resourceBundle, code, args);
		return Response.status(Response.Status.NOT_FOUND).entity(error).build();
	}

	public Response notFound(Long code, Object[][] args) {
		final Error error = buildError(code, args);
		return Response.status(Response.Status.NOT_FOUND).entity(error).build();
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
		Error error = getError(e, 1004L);
		return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(error).build();
	}

	public static Response notAuthorizedError(Exception e) {
		Error error = getError(e, null);
		return Response.status(Response.Status.UNAUTHORIZED).entity(error).build();
	}
	
	private static Error getError(Exception e, Long code) {
		Error error = new Error();
		
		if (code != null)
			error.setCode(code);
		
		error.setMessage(e.getMessage());
        StringBuffer sb = new StringBuffer(getStackTrace(e));
        
		Throwable t = e.getCause();

		if (t != null) {
			sb.append("CausedBy:" + t.getMessage());
			sb.append(getStackTrace(t));
		}

		error.setDescription(sb.toString());
		return error;
	}
	
	private static String getStackTrace(Throwable t) {
		String stacktrace = "";
		
		if (t != null) {
			OutputStream os = new ByteArrayOutputStream();
			PrintWriter writer = new PrintWriter(os);
			t.printStackTrace(writer);
			stacktrace = writer.toString();
			
			StringWriter sw = new StringWriter();
			t.printStackTrace(new PrintWriter(sw));
			stacktrace = sw.toString();
		}
		
		return stacktrace;
	}
}