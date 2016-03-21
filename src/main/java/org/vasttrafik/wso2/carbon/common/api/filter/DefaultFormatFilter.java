package org.vasttrafik.wso2.carbon.common.api.filter;

import java.io.IOException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerResponseContext;
import javax.ws.rs.container.ContainerResponseFilter;
import javax.ws.rs.ext.Provider;

/**
 * @author Lars Andersson
 *
 */
@Provider
public class DefaultFormatFilter implements ContainerResponseFilter {

	@Override
	public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext)
			throws IOException {

		setResponseHeaders(responseContext);
	}

	private void setResponseHeaders(ContainerResponseContext responseContext) {
		Object contentType = responseContext.getHeaders().getFirst("Content-Type");
		
		// If JSON content, make sure the character encoding is UTF-8
		if (contentType != null && "application/json".equalsIgnoreCase(contentType.toString()))
			responseContext.getHeaders().putSingle("Content-Type", contentType + "; charset=utf-8");
		
		// Set CORS Headers
		responseContext.getHeaders().add("Access-Control-Allow-Origin",  "*");
		responseContext.getHeaders().add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS");
		responseContext.getHeaders().add("Access-Control-Allow-Headers", "Accept,X-JWT-Assertion,Access-Control-Allow-Origin,Content-Length,Content-Type,If-None-Match,If-Modified-Since");
	}
}
