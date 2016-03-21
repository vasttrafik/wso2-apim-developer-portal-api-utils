package org.vasttrafik.wso2.carbon.common.api.exceptions;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;
import javax.validation.ValidationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;

import org.vasttrafik.wso2.carbon.common.api.beans.Error;
import org.vasttrafik.wso2.carbon.common.api.beans.ErrorListItem;
import org.vasttrafik.wso2.carbon.common.api.utils.AbstractErrorListResourceBundle;
import org.vasttrafik.wso2.carbon.common.api.utils.ResponseUtils;

public class GenericExceptionMapper implements ExceptionMapper<ValidationException> {
		
	/**
	 * Resource bundle to use when constructing messages and responses
	 */
	protected AbstractErrorListResourceBundle resourceBundle = null;
	
	/**
	 * ResponseUtils instance
	 */
	protected ResponseUtils responseUtils = null;
	

	public GenericExceptionMapper(String bundleName) {
		init(bundleName);
	}

	@Override
	public Response toResponse(ValidationException exception) {
		if (exception instanceof ConstraintViolationException)
			return toConstraintViolationExceptionResponse((ConstraintViolationException)exception);
		else
			return Response.serverError().entity(exception.getMessage()).build();
	}
	
	protected Response toConstraintViolationExceptionResponse(ConstraintViolationException constraintViolation) {
		Error error = null;
		
		try {
			// Create a generic Error entity for validation exceptions
			error = responseUtils.buildError(1000L, null);
		}
		catch (Exception e) {
			e.printStackTrace();
			error = new Error();
		}
		
		error.setMoreInfo("");
		
		// Get the constraint violations
		Set<ConstraintViolation<?>> violations = constraintViolation.getConstraintViolations();
		
		if (violations != null) {
			List<ErrorListItem> items = new ArrayList<ErrorListItem>();
			
			for (ConstraintViolation<?> violation : violations) {
				ErrorListItem item = new ErrorListItem();
				item.setCode(1000L); // Generic error code for validation errors
				item.setMessage(violation.getMessage());
				items.add(item);
			}
			error.setItems(items);
		}
		
		return Response.status(Status.BAD_REQUEST).entity(error).build();
	}
	
	private void init(String bundleName) {
		try {
			// Get system country and language
			String country  = System.getProperty("user.country");
			String language = System.getProperty("user.language");
			
			// Create Locale
			Locale locale = new Locale(language, country);
			
			// Load the resource bundle
			resourceBundle = (AbstractErrorListResourceBundle)
					ResourceBundle.getBundle(bundleName, /*locale*/new Locale("sv", "SE"), getClass().getClassLoader());

			// Create a ResponseUtils instance
			responseUtils =  new ResponseUtils(resourceBundle);
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
