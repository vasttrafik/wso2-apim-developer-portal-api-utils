package org.vasttrafik.wso2.carbon.apimgt.hostobjects;

import java.util.Iterator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jaggeryjs.scriptengine.exceptions.ScriptException;
import org.mozilla.javascript.*;
import org.wso2.carbon.apimgt.api.APIConsumer;
import org.wso2.carbon.apimgt.api.APIManagementException;
import org.wso2.carbon.apimgt.api.model.API;
import org.wso2.carbon.apimgt.api.model.APIIdentifier;
import org.wso2.carbon.apimgt.hostobjects.APIStoreHostObject;
import org.wso2.carbon.apimgt.impl.utils.APIUtil;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;

public final class VTAPIStoreHostObject extends APIStoreHostObject {
	
	
	private static final long serialVersionUID = 1947045451725374161L;
	private static final Log LOG = LogFactory.getLog(VTAPIStoreHostObject.class);
	private static final String hostObjectName = "VTStore";
	
	public VTAPIStoreHostObject() throws APIManagementException {
		super();
	}
	
	public VTAPIStoreHostObject(String loggedInUser) throws APIManagementException {
		super(loggedInUser);
	}
	
	@Override
    public String getClassName() {
        return hostObjectName;
    }
	
	public static Scriptable jsConstructor(Context cx, Object[] args, Function Obj,boolean inNewExpr)
			throws ScriptException, APIManagementException 
	{
		if (args != null && args.length != 0) {
			String username = (String) args[0];
			return new VTAPIStoreHostObject(username);
		}
		return new VTAPIStoreHostObject(null);
	}
	
	public static NativeObject jsFunction_getPaginatedAPIs(Context cx, Scriptable thisObj, Object[] args, Function funObj)
			throws ScriptException, APIManagementException 
	{
		APIConsumer apiConsumer = getConsumer(thisObj);
		String tenantDomain;
		String loggedInUser = getUsername(thisObj);
		int start = 0;
		int end = -1;

		if (args[0] != null) {
			tenantDomain = (String) args[0];
		} 
		else {
			tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
		}

		try {
			start = Integer.parseInt((String) args[1]);
		}
		catch (Exception e) {}
		
		try {
			end = Integer.parseInt((String) args[2]);
		}
		catch (Exception e) {}

		return getPaginatedAPIs(apiConsumer, loggedInUser, tenantDomain, start, end);
	}


	private static String getUsername(Scriptable obj) {
		return ((VTAPIStoreHostObject)obj).getUsername();
	}

	private static APIConsumer getConsumer(Scriptable thisObj) {
		return ((VTAPIStoreHostObject) thisObj).getApiConsumer();
	}
	
	private static NativeObject getPaginatedAPIs(APIConsumer apiConsumer, String loggedInUser, String tenantDomain, int start, int end) {
		List<API> apiSet;
        
        NativeArray myn = new NativeArray(0);
        NativeObject result = new NativeObject();
        
        try {
            if (tenantDomain != null && !MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
            } 
            else {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, true);

            }
            apiSet = apiConsumer.getAllAPIs();

        } catch (APIManagementException e) {
            LOG.error("Error from Registry API while getting API Information", e);
            return result;
        } catch (Exception e) {
            LOG.error("Error while getting API Information", e);
            return result;
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        
        if (apiSet != null) {
        	int i = 0, j = 0;
                
        	for (Iterator<API> it = apiSet.iterator(); it.hasNext(); i++) {
        		// Get the API
                API api = it.next();
                APIIdentifier apiIdentifier = api.getId();
                        		
                // Get the status and visibleRoles
        		String status = api.getStatus().toString();
        		String visibility = api.getVisibility();
                
                if (shouldInclude(loggedInUser, status, visibility)) {
            
                	// Should we get this particular row?
            		if (i < start || (i > end && end != -1))
            			continue;
                   
                	NativeObject row = new NativeObject();
                	row.put("name", row, apiIdentifier.getApiName());
                	row.put("provider", row, APIUtil.replaceEmailDomainBack(apiIdentifier.getProviderName()));
                	row.put("version", row, apiIdentifier.getVersion());
                	row.put("context", row, api.getContext());
                	row.put("status", row, status);
                	row.put("visibility", row, visibility);
                	row.put("visibleRoles", row, api.getVisibleRoles());
                	row.put("description", row, api.getDescription());
                	row.put("isAdvertiseOnly", row, api.isAdvertiseOnly());

                	if (api.getThumbnailUrl() == null) {
                		row.put("thumbnailurl", row, "images/api-default.png");
                	} else {
                		row.put("thumbnailurl", row, APIUtil.prependWebContextRoot(api.getThumbnailUrl()));
                	}
                
                	String apiOwner = APIUtil.replaceEmailDomainBack(api.getApiOwner());

                	if (apiOwner == null) {
                		apiOwner = APIUtil.replaceEmailDomainBack(apiIdentifier.getProviderName());
                	}
                
                	row.put("apiOwner", row, apiOwner);
                	myn.put(j++, myn, row);
                }
        	}

        	result.put("apis", result, myn);
        	result.put("totalLength", result, j);
        }

        return result;
	}
	
	private static boolean shouldInclude(String loggedInUser, String status, String visibility) {
		LOG.error("Logged in user=" + loggedInUser);
		
		if ("admin".equalsIgnoreCase(loggedInUser)) {
			if (!"PUBLISHED".equalsIgnoreCase(status) && 
				!"PROTOTYPED".equalsIgnoreCase(status) && 
				!"DEPRECATED".equalsIgnoreCase(status))
				return false;
			else
				return "public".equalsIgnoreCase(visibility);
		}
		else
			return true;
	}
}

