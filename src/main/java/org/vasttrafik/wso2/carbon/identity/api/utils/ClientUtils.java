package org.vasttrafik.wso2.carbon.identity.api.utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Hashtable;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.axis2.transport.http.HttpTransportProperties;

import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.claim.mgt.stub.ClaimManagementServiceStub;
import org.wso2.carbon.identity.mgt.stub.UserInformationRecoveryServiceStub;
import org.wso2.carbon.identity.mgt.stub.UserIdentityManagementAdminServiceStub;
import org.wso2.carbon.identity.oauth.stub.OAuthAdminServiceStub;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.registry.ws.stub.WSRegistryServiceStub;
import org.wso2.carbon.um.ws.api.stub.RemoteUserStoreManagerServiceStub;
import org.wso2.carbon.user.core.config.RealmConfigXMLProcessor;
import org.wso2.carbon.user.api.RealmConfiguration;

/**
 * @author Lars Andersson
 *
 * This class contains useful methods for retrieving service stubs to make calls to admin service. Also, this class manages authentication and keeps track of
 * when a service client last made a call to service, and if needed, performs a new authentication to retrieve and set a valid session cookie. For this to work,
 * clients need to first retrieve an instance of the relevant client stub, then check if authentication if needed BEFORE making a service call.
 *
 */
public final class ClientUtils {

	/**
	 * User Name to access WSO2 Carbon Server
	 */
	public static final String ADMIN_USER_NAME = "admin";

	/**
	 * Password of the User who access the WSO2 Carbon Server
	 */
	public static String ADMIN_PASSWORD = "";

	/**
	 * Trust store path
	 */
	public static String TRUST_STORE = "";

	/**
	 * Password of the trust store
	 */
	public static String TRUST_STORE_PASSWORD = "";

	/**
	 * The API Manager Host
	 */
	public static String HOST_NAME;
	
	/**
	 * The API Manager Port
	 */
	private static short HOST_PORT = 9443;

	/**
	 * WSO2 Carbon Server port offset
	 */
	public static short PORT_OFFSET;

	/**
	 * Web services URL
	 */
	private static String SERVICES_URL = "";

	/**
	 * Session cookie
	 */
	private static String authCookie;

	/**
	 * Authentication admin stub
	 */
	private static AuthenticationAdminStub authenticationStub = null;

	/**
	 * Remote user manager stub
	 */
	private static RemoteUserStoreManagerServiceStub userStoreStub = null;

	/**
	 * OAuth2 token validation stub
	 */
	private static OAuth2TokenValidationServiceStub tokenValidationStub = null;

	/**
	 * OAuth admin stub
	 */
	private static OAuthAdminServiceStub adminService = null;

	/**
	 * User information recovery stub
	 */
	private static UserInformationRecoveryServiceStub userInformationRecoveryStub = null;
	
	/**
	 * User identity management stub
	 */
	private static UserIdentityManagementAdminServiceStub userIdentityManagementStub = null;

	/**
	 * Claim management stub
	 */
	private static ClaimManagementServiceStub claimMgmtStub = null;

	/**
	 * Registry service stub
	 */
	private static WSRegistryServiceStub registryStub = null;

	/**
	 * Authentication mapping. We will keep track of all requests being made with the different service clients to make sure the correct session cookie is
	 * always set.
	 */
	private static Hashtable<ServiceClient, Long> serviceClients = new Hashtable<ServiceClient, Long>();

	/**
	 * Session timeout. If no authentication calls have come in this period, we need to authenticate to get a new cookie to avoid authentication issues making
	 * admin calls.
	 */
	private static final long timeIntervalBetweenAuthentication = 300000L;

	/**
	 * Configuration context
	 */
	private static ConfigurationContext configContext;

	/**
	 * Retrieves a service stub that can be used to call the RemoteUserStoreManagerService service.
	 *
	 * @return A RemoteUserStoreManagerServiceStub service stub.
	 */
	public static RemoteUserStoreManagerServiceStub getRemoteUserStoreManagerServiceStub() {
		if (userStoreStub == null) {
			final String serviceURL = SERVICES_URL + "RemoteUserStoreManagerService";

			try {
				userStoreStub = new RemoteUserStoreManagerServiceStub(configContext, serviceURL);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return userStoreStub;
	}

	/**
	 * Retrieves a service stub that can be used to call the OAuthAdminService service.
	 *
	 * @return A OAuthAdminServiceStub service stub.
	 */
	public static OAuthAdminServiceStub getOAuthAdminServiceStub() {
		if (adminService == null) {
			final String serviceURL = SERVICES_URL + "OAuthAdminService";

			try {
				adminService = new OAuthAdminServiceStub(configContext, serviceURL);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return adminService;
	}

	/**
	 * Retrieves a service stub that can be used to call the OAuth2TokenValidationService service.
	 *
	 * @return A OAuth2TokenValidationServiceStub service stub.
	 */
	public static OAuth2TokenValidationServiceStub getOAuth2TokenValidationServiceStub() {
		if (tokenValidationStub == null) {
			final String serviceURL = SERVICES_URL + "OAuth2TokenValidationService";

			try {
				tokenValidationStub = new OAuth2TokenValidationServiceStub(configContext, serviceURL);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return tokenValidationStub;
	}

	/**
	 * Retrieves a service stub that can be used to call the UserInformationRecoveryService service.
	 *
	 * @return A UserInformationRecoveryServiceStub service stub.
	 */
	public static UserInformationRecoveryServiceStub getUserInformationRecoveryServiceStub() {
		if (userInformationRecoveryStub == null) {
			final String serviceURL = SERVICES_URL + "UserInformationRecoveryService";

			try {
				userInformationRecoveryStub = new UserInformationRecoveryServiceStub(configContext, serviceURL);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return userInformationRecoveryStub;
	}
	
	/**
	 * Retrieves a service stub that can be used to call the UserIdentityManagementAdminService service.
	 *
	 * @return A UserIdentityManagementAdminServiceStub service stub.
	 */
	public static UserIdentityManagementAdminServiceStub getUserIdentityManagementServiceStub() {
		if (userIdentityManagementStub == null) {
			final String serviceURL = SERVICES_URL + "UserIdentityManagementAdminService";

			try {
				userIdentityManagementStub = new UserIdentityManagementAdminServiceStub(configContext, serviceURL);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return userIdentityManagementStub;
	}
	
	/**
	 * Retrieves a service stub that can be used to call the UserInformationRecoveryService service.
	 *
	 * @return A UserInformationRecoveryServiceStub service stub.
	 */
	public static ClaimManagementServiceStub getClaimManagementServiceStub() {
		if (claimMgmtStub == null) {
			final String serviceURL = SERVICES_URL + "ClaimManagementService";

			try {
				claimMgmtStub = new ClaimManagementServiceStub(configContext, serviceURL);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return claimMgmtStub;
	}

	/**
	 * Retrieves a service stub that can be used to call the RemoteUserStoreManagerService service.
	 *
	 * @return A RemoteUserStoreManagerServiceStub service stub.
	 * @throws RegistryException
	 */
	public static WSRegistryServiceStub getWSRegistryServiceStub() {
		if (registryStub == null) {
			final String serviceURL = SERVICES_URL + "WSRegistryService";

			try {
				registryStub = new WSRegistryServiceStub(configContext, serviceURL);
			} catch (Throwable t) {
				t.printStackTrace();
			}
		}
		return registryStub;
	}

	/**
	 * Checks if we need to authenticate to get a session cookie we can use to call admin services. Then, sets the cookie as a header.
	 *
	 * @param serviceClient The service client wishing to make an admin service call.
	 * @throws Exception
	 */
	public static void authenticateIfNeeded(ServiceClient serviceClient) throws Exception {
		Long lastAuthentication = serviceClients.get(authenticationStub._getServiceClient());

		/**
		 * If null or time exceeded, authenticate to get a session cookie
		 */
		if (lastAuthentication == null || timeExceeded(lastAuthentication)) {
			if (lastAuthentication == null) {
				initializeServiceClient(authenticationStub._getServiceClient());
			}

			authenticate();
		}

		/**
		 * Next, check when the service client made the last call to check authentication
		 */
		lastAuthentication = serviceClients.get(serviceClient);

		/**
		 * If null or time exceeded, set the session cookie
		 */
		if (lastAuthentication == null || timeExceeded(lastAuthentication)) {
			if (lastAuthentication == null) {
				initializeServiceClient(serviceClient);
			}

			setCookie(serviceClient);
		}

		/**
		 * Remember when we checked
		 */
		serviceClients.put(serviceClient, System.currentTimeMillis());
	}

	/**
	 * Checks if the time elapsed between last check for authentication status has exceeded the default value.
	 *
	 * @param lastAuthentication The last time a check was made.
	 * @return
	 */
	private static boolean timeExceeded(Long lastAuthentication) {
		Long currentTimeMillis = System.currentTimeMillis();
		return ((currentTimeMillis - lastAuthentication) > timeIntervalBetweenAuthentication);
	}

	/**
	 * Performs service authentication, if needed, by calling the AuthenticationAdmin service. Then sets the session cookie returned and also stores it for
	 * subsequent calls to other admin services.
	 */
	private static void authenticate() {
		try {
			/**
			 * Authenticate User
			 */
			boolean authenticate = authenticationStub.login(ADMIN_USER_NAME, ADMIN_PASSWORD, HOST_NAME);

			if (authenticate) {
				/**
				 * Get the service client
				 */
				ServiceClient serviceClient = authenticationStub._getServiceClient();
				/**
				 * Retrieve the cookie to use for subsequent communications
				 */
				authCookie = (String) serviceClient.getServiceContext().getProperty(HTTPConstants.COOKIE_STRING);
				/**
				 * Set the cookie
				 */
				setCookie(serviceClient);
				/**
				 * Remember the time when we authenticated
				 */
				serviceClients.put(serviceClient, System.currentTimeMillis());
			} 
			else {
				throw new Exception("User " + ADMIN_USER_NAME + " failed to authenticate");
			}
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Initializes the service client
	 *
	 * @param serviceClient The service client to initialize
	 */
	private static void initializeServiceClient(ServiceClient serviceClient) {
		/**
		 * Setting basic auth headers for authentication for carbon server
		 */
		HttpTransportProperties.Authenticator auth = new HttpTransportProperties.Authenticator();
		auth.setUsername(ADMIN_USER_NAME);
		auth.setPassword(ADMIN_PASSWORD);
		auth.setPreemptiveAuthentication(true);

		/**
		 * Setting a authenticated cookie that is received from Carbon server. If you have authenticated with Carbon server earlier, you can use that cookie, if
		 * it has not been expired
		 */
		Options option = serviceClient.getOptions();
		option.setProperty(HTTPConstants.COOKIE_STRING, null);
		option.setProperty(org.apache.axis2.transport.http.HTTPConstants.AUTHENTICATE, auth);
		option.setManageSession(true);
	}

	/**
	 * Set the session cookie in the service client.
	 *
	 * @param serviceClient The service client
	 */
	private static void setCookie(ServiceClient serviceClient) {
		if (serviceClient != null) {
			Options option = serviceClient.getOptions();
			option.setProperty(HTTPConstants.COOKIE_STRING, authCookie);
		}
	}

	private static void initialize() {
		try {
			/**
			 * Get the server configuration (carbon.xml) and the trust store password
			 */
			ServerConfiguration config = ServerConfiguration.getInstance();
			TRUST_STORE_PASSWORD = config.getFirstProperty("Security.TrustStore.Password");

			/**
			 * Use the provided hostname. Fall back to use "localhost" if the hostname cannot be provided.
			 */
			try {
				HOST_NAME = InetAddress.getLocalHost().getHostName();
			} catch (final UnknownHostException exception) {
				HOST_NAME = "localhost";
			}

			/**
			 * Get the server port offset
			 */
			PORT_OFFSET = Short.valueOf(config.getFirstProperty("Ports.Offset"));
			HOST_PORT += PORT_OFFSET;
			SERVICES_URL = "https://" + HOST_NAME + ":" + HOST_PORT + "/services/";
			
			/**
			 * Get the user store configuration (user-mgmt.xml) and the admin password
			 */
			RealmConfiguration realmConfig = new RealmConfigXMLProcessor().buildRealmConfigurationFromFile();
			ADMIN_PASSWORD = realmConfig.getAdminPassword();
			
			/**
			 * Call to https://<host>:9443/services/ uses HTTPS protocol. Therefore we need to validate the server certificate or CA chain. The server certificate
			 * is looked up in the trust store.
			 */
			String CARBON_HOME = System.getProperty("carbon.home");
			TRUST_STORE = CARBON_HOME + "/repository/resources/security/client-truststore.jks";

			System.setProperty("javax.net.ssl.trustStore", TRUST_STORE);
			System.setProperty("javax.net.ssl.trustStorePassword", TRUST_STORE_PASSWORD);
			
			/**
			 * Create a configuration context. A configuration context contains information for axis2 environment. This is needed to create an axis2 service
			 * client
			 */
			configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(null, null);

			/**
			 * Create an authentication client stub. This will be used to authenticate all calls to WSO2 services
			 */
			authenticationStub = new AuthenticationAdminStub(configContext, SERVICES_URL + "AuthenticationAdmin");
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	static {
		initialize();
	}
}
