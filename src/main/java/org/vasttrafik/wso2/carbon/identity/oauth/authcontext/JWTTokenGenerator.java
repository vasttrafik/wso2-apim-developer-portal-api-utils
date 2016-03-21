package org.vasttrafik.wso2.carbon.identity.oauth.authcontext;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.util.ClaimCache;
import org.wso2.carbon.identity.oauth.util.ClaimCacheKey;
import org.wso2.carbon.identity.oauth.util.UserClaims;
import org.wso2.carbon.identity.oauth2.authcontext.ClaimsRetriever;

/**
 * This class represents a JSON Web Token generator. It is the default JWTGenerator class, by default
 * configured by the TokenGeneratorImplClass element in the identity.xml config file. However, due to
 * the tight coupling between OAuth and JWT, this class has been modified to allow token generation
 * based on username and credential, thus eliminating the need for OAuth.
 * 
 * The JWT header and body are base64 encoded separately and concatenated with a dot.
 * Finally the token is signed using SHA256 with RSA algorithm.
 */
public class JWTTokenGenerator {
	
	/**
	 * Private class to encapsulate access to keystore configuration
	 * @author andersson.lars
	 *
	 */
	private class KeyStoreConfig {
		
		// Server configuration instance (carbon.xml)
		private ServerConfiguration serverConfig;
		
		public KeyStoreConfig(ServerConfiguration serverConfig) {
			this.serverConfig = serverConfig;
		}
		
		/**
		 * Retrieves the name of the keystore
		 * @return
		 */
		public String getKeyStore() {
			String keyStore = getLocation();
			int index = keyStore.lastIndexOf("/");
	    	return keyStore.substring(++index);
		}
		
		/**
		 * Retrieves the key store location
		 * @return
		 */
		public String getLocation() {
			return serverConfig.getFirstProperty("Security.KeyStore.Location");	
		}
		
		/**
		 * Retrieves the key alias
		 * @return
		 */
		public String getKeyAlias() {
			return serverConfig.getFirstProperty("Security.KeyStore.KeyAlias");
		}
		
		/**
		 * Retrieves the key password
		 * @return
		 */
		public String getKeyPassword() {
			return serverConfig.getFirstProperty("Security.KeyStore.KeyPassword");
		}
		
	}

    private static final Log log = LogFactory.getLog(JWTTokenGenerator.class);

    private static final String API_GATEWAY_ID = "http://wso2.org/gateway";
    private static final String NONE = "NONE";

    private static final Base64 base64Url = new Base64(0, null, true);

    private static volatile long ttl = -1L;

    private ClaimsRetriever claimsRetriever;

    private JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS256.getName());

    private boolean includeClaims = true;
    private boolean enableSigning = true;
    private static boolean initialized = false;

    private static ServerConfiguration serverConfiguration = ServerConfiguration.getInstance();
    private static Map<Integer, Key> privateKeys = new ConcurrentHashMap<Integer, Key>();
    private static Map<Integer, Certificate> publicCerts = new ConcurrentHashMap<Integer, Certificate>();
    private static Map<Integer, String> thumbPrints = new ConcurrentHashMap<Integer, String>();

    private ClaimCache claimsLocalCache;
    
    private String userAttributeSeparator = ",,,";  

	/**
	  * Default constructor. Creates a local claims cache with timeout according to setting in identity.xml
	  * OAuth -> AuthorizationGrantCacheTimeout element, defaults to -1.
	  */
    public JWTTokenGenerator() {
    	this(true, true);
    }

    public JWTTokenGenerator(boolean includeClaims, boolean enableSigning) {
    	claimsLocalCache = ClaimCache.getInstance();
    	
        this.includeClaims = includeClaims;
        this.enableSigning = enableSigning;
        signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.NONE.getName());
        
        if (!initialized) {
        	try {
        		init();
        	}
        	catch (Exception e) {
        		e.printStackTrace();
        	}
        }
    }

    /**
     * Reads the ClaimsRetrieverImplClass from identity.xml ->
     * OAuth -> TokenGeneration -> ClaimsRetrieverImplClass.
     *
     * @throws Exception
     */
    public void init() throws Exception {
        if (includeClaims && enableSigning) {
            String claimsRetrieverImplClass = OAuthServerConfiguration.getInstance().getClaimsRetrieverImplClass();
            String sigAlg =  OAuthServerConfiguration.getInstance().getSignatureAlgorithm();
            
            if(sigAlg != null && !sigAlg.trim().isEmpty()){
                signatureAlgorithm = mapSignatureAlgorithm(sigAlg);
            }
            
            if(claimsRetrieverImplClass != null){
                try{
                    claimsRetriever = (ClaimsRetriever)Class.forName(claimsRetrieverImplClass).newInstance();
                    claimsRetriever.init();
                } 
				catch (ClassNotFoundException e){
                    log.error("Cannot find class: " + claimsRetrieverImplClass, e);
                } 
				catch (InstantiationException e) {
                    log.error("Error instantiating " + claimsRetrieverImplClass, e);
                } 
				catch (IllegalAccessException e) {
                    log.error("Illegal access to " + claimsRetrieverImplClass, e);
                } 
				catch (Exception e){
                    log.error("Error while initializing " + claimsRetrieverImplClass, e);
                }
            }
        }
        
        initialized = true;
    }

    /**
     * Generates the JWT token.
     *
	 * @param userName The username that should be authenticated and encoded into the token
     * @return signed JWT token
     * @throws IdentityException If authentication failure occurs
     */
	public JWTToken generateToken(String userName) 
		throws IdentityException 
	{
		// Set the default tenant id and domain
		int tenantID = -1234;
		String tenantDomain = null;
		
		// Get the current time and the token expiry time
        long currentTime = Calendar.getInstance().getTimeInMillis();
        long expireIn = currentTime + 1000 * 60 * getTTL();

        // Create the default claim set
        JWTClaimsSet claimsSet = new JWTClaimsSet();
        claimsSet.setIssuer(API_GATEWAY_ID);
        claimsSet.setSubject(userName);
		claimsSet.setIssueTime(new Date(System.currentTimeMillis()));
        claimsSet.setExpirationTime(new Date(expireIn));
        claimsSet.setClaim(API_GATEWAY_ID+"/applicationname","portal-api,community-api,identity-mgmt-api");
        claimsSet.setClaim(API_GATEWAY_ID+"/enduser",userName);
        
        // For some reason, when token is serialized, milliseconds are converted to seconds, so the
        // iss and exp attributes are off. However, adding these as custom claims works
        claimsSet.setClaim(API_GATEWAY_ID+"/iss",new Date(System.currentTimeMillis()));
        claimsSet.setClaim(API_GATEWAY_ID+"/exp",expireIn);
        
        // Get the user claims
        getUserClaims(claimsSet, userName, tenantID);
        
        // Get the JWT
        JWT jwt = getJWT(claimsSet, tenantDomain, tenantID);

        // Return the JWT token
		return new JWTToken(claimsSet, jwt.serialize());
    }
	
	/**
	 * If a claims retriever has been configured, retrieves the user claims
	 * @param claimsSet
	 * @param userName
	 * @param tenantID
	 * @throws IdentityException
	 */
	protected void getUserClaims(JWTClaimsSet claimsSet, String userName, int tenantID) 
		throws IdentityException
	{
		if(claimsRetriever != null){
            String[] requestedClaims = claimsRetriever.getDefaultClaims(userName);
			
            ClaimCacheKey cacheKey = null;
            UserClaims result = null;

            if(requestedClaims != null) {
                cacheKey = new ClaimCacheKey(userName, requestedClaims);
                result = (UserClaims)claimsLocalCache.getValueFromCache(cacheKey);
            }

            SortedMap<String,String> claimValues = null;
			
            if (result != null) {
                claimValues = result.getClaimValues();
            } 
			else {
                claimValues = claimsRetriever.getClaims(userName, requestedClaims);
                UserClaims userClaims = new UserClaims(claimValues);
                claimsLocalCache.addToCache(cacheKey, userClaims);
            }

            String claimSeparator = ",";
				
            if (StringUtils.isBlank(claimSeparator)) {
                userAttributeSeparator = claimSeparator;
            }

            if(claimValues != null) {
                Iterator<String> it = new TreeSet(claimValues.keySet()).iterator();
                
				while (it.hasNext()) {
                    String claimURI = it.next();
                    String claimVal = claimValues.get(claimURI);
                    
                    List<String> claimList = new ArrayList<String>();
                    
					if (userAttributeSeparator != null && claimVal.contains(userAttributeSeparator)) {
                        StringTokenizer st = new StringTokenizer(claimVal, userAttributeSeparator);
						
                        while (st.hasMoreElements()) {
                            String attValue = st.nextElement().toString();
							
                            if (StringUtils.isNotBlank(attValue)) {
                                claimList.add(attValue);
                            }
                        }
                        claimsSet.setClaim(claimURI, claimList.toArray(new String[claimList.size()]));
                    } 
					else {
                        claimsSet.setClaim(claimURI, claimVal);
                    }
                }
            }
        }
	}
	
	/**
	 * Construct a JWT with the supplied claims set
	 * @param claimsSet
	 * @param tenantDomain
	 * @param tenantID
	 * @return
	 * @throws IdentityException
	 */
	protected JWT getJWT(JWTClaimsSet claimsSet, String tenantDomain, int tenantID) 
		throws IdentityException
	{
		JWT jwt = null;
		
        if(!JWSAlgorithm.NONE.equals(signatureAlgorithm)){
            JWSHeader header = new JWSHeader(JWSAlgorithm.RS256);
            header.setX509CertThumbprint(new Base64URL(getThumbPrint(tenantDomain, tenantID)));
            
            jwt = new SignedJWT(header, claimsSet);
            jwt = signJWT((SignedJWT)jwt, tenantDomain, tenantID);
        } 
		else {
            jwt = new PlainJWT(claimsSet);
        }
        
        return jwt;
	}

    /**
     * Sign with given RSA Algorithm
     *
     * @param signedJWT
     * @param jwsAlgorithm
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected SignedJWT signJWTWithRSA(SignedJWT signedJWT, JWSAlgorithm jwsAlgorithm, String tenantDomain, int tenantId)
            throws IdentityException {

        try {
            Key privateKey = getPrivateKey(tenantId);
            JWSSigner signer = new RSASSASigner((RSAPrivateKey) privateKey);
            signedJWT.sign(signer);
            return signedJWT;
        } 
		catch (JOSEException e) {
            log.error("Error in obtaining tenant's keystore", e);
            throw new IdentityException("Error in obtaining tenant's keystore", e);
        } 
		catch (Exception e) {
            log.error("Error in obtaining tenant's keystore", e);
            throw new IdentityException("Error in obtaining tenant's keystore", e);
        }
    }

    /**
     * Generic Signing function
     *
     * @param signedJWT
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws IdentityException
     */
    protected JWT signJWT(SignedJWT signedJWT, String tenantDomain, int tenantId)
            throws IdentityException {

        if (JWSAlgorithm.RS256.equals(signatureAlgorithm) || 
		    JWSAlgorithm.RS384.equals(signatureAlgorithm) ||
            JWSAlgorithm.RS512.equals(signatureAlgorithm)) 
		{
            return signJWTWithRSA(signedJWT, signatureAlgorithm, tenantDomain, tenantId);
        } 
		else 
		if (JWSAlgorithm.HS256.equals(signatureAlgorithm) ||
            JWSAlgorithm.HS384.equals(signatureAlgorithm) ||
            JWSAlgorithm.HS512.equals(signatureAlgorithm)) {
            // return signWithHMAC(payLoad,jwsAlgorithm,tenantDomain,tenantId); implementation
            // need to be done
        } 
		else 
		if (JWSAlgorithm.ES256.equals(signatureAlgorithm) ||
            JWSAlgorithm.ES384.equals(signatureAlgorithm) ||
            JWSAlgorithm.ES512.equals(signatureAlgorithm)) {
            // return signWithEC(payLoad,jwsAlgorithm,tenantDomain,tenantId); implementation
            // need to be done
        }
        
        log.error("UnSupported Signature Algorithm");
        throw new IdentityException("UnSupported Signature Algorithm");
    }

    /**
     * This method map signature algorithm define in identity.xml to nimbus
     * signature algorithm
     * format, Strings are defined inline hence there are not being used any
     * where
     *
     * @param signatureAlgorithm
     * @return
     * @throws IdentityOAuth2Exception
     */
    protected JWSAlgorithm mapSignatureAlgorithm(String signatureAlgorithm)
            throws IdentityException 
	{
        if ("SHA256withRSA".equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS256;
        } 
		else if ("SHA384withRSA".equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS384;
        } 
		else if ("SHA512withRSA".equals(signatureAlgorithm)) {
            return JWSAlgorithm.RS512;
        } 
		else if ("SHA256withHMAC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS256;
        } 
		else if ("SHA384withHMAC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS384;
        } 
		else if ("SHA512withHMAC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.HS512;
        } 
		else if ("SHA256withEC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES256;
        } 
		else if ("SHA384withEC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES384;
        } 
		else if ("SHA512withEC".equals(signatureAlgorithm)) {
            return JWSAlgorithm.ES512;
        } 
		else if(NONE.equals(signatureAlgorithm)){
            return new JWSAlgorithm(JWSAlgorithm.NONE.getName());
        }
        
        log.error("Unsupported Signature Algorithm in identity.xml");
        throw new IdentityException("Unsupported Signature Algorithm in identity.xml");
    }

    /**
     * Retrieves the configured time to live for JWT tokens from the identity.xml configuration file.
     * @return The value of the TTL element in the identity.xml config file
     */
    private long getTTL() {
        if (ttl != -1) {
            return ttl;
        }

        synchronized (JWTTokenGenerator.class) {
            if (ttl != -1) {
                return ttl;
            }
			
            String ttlValue = OAuthServerConfiguration.getInstance().getAuthorizationContextTTL();
			
            if (ttlValue != null) {
                ttl = Long.parseLong(ttlValue);
            } else {
                ttl = 15L;
            }
            
            return ttl;
        }
    }

    /**
     * Helper method to add public certificate to JWT_HEADER to signature verification.
     *
     * @param tenantDomain
     * @param tenantId
     * @throws IdentityOAuth2Exception
     */
    private String getThumbPrint(String tenantDomain, int tenantId) 
		throws IdentityException 
	{
        try {
            Certificate certificate = getCertificate(tenantDomain, tenantId);
            String thumbPrint = thumbPrints.get(tenantId);
            
            if (thumbPrint == null) {
            	//Generate the SHA-1 thumb print of the certificate
            	MessageDigest digestValue = MessageDigest.getInstance("SHA-1");
            	byte[] der = certificate.getEncoded();
            	digestValue.update(der);
            	byte[] digestInBytes = digestValue.digest();

            	String publicCertThumbprint = hexify(digestInBytes);
            	thumbPrint = new String(base64Url.encode(publicCertThumbprint.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
            	thumbPrints.put(tenantId, thumbPrint);
            }
            
            if (log.isDebugEnabled())
            	log.debug("Retrieved thumbprint:" + thumbPrint);
            
            return thumbPrint;
        } 
		catch (Exception e) {
            final String error = "Error in obtaining certificate for tenant " + tenantDomain;
            throw new IdentityException(error, e);
        }
    }
    
    /**
     * Retrieves the private key
     * @param tenantId
     * @return
     * @throws IdentityException
     */
    private Key getPrivateKey(int tenantId) 
    	throws IdentityException 
    {
    	Key privateKey = null;

        if (!(privateKeys.containsKey(tenantId))) {
        	// get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
            
            // Get keystore configuration
            KeyStoreConfig keyStoreConfig = new KeyStoreConfig(serverConfiguration);
            // Get keystore location
            String keyStore = keyStoreConfig.getKeyStore();
            // Get the key alias
            String keyAlias = keyStoreConfig.getKeyAlias();
            // Get the key password
            String KeyPassw = keyStoreConfig.getKeyPassword();
            // Convert the password into char array
            char[] password = KeyPassw.toCharArray();
            
            try {
            	// Get the private key
            	privateKey = tenantKSM.getKeyStore(keyStore)
            		.getKey(keyAlias, password);
            }
            catch (Exception e) {
            	throw new IdentityException(e.getMessage());
            }
            
            if (privateKey != null) {
                privateKeys.put(tenantId, privateKey);
            }
        }
        else {
            privateKey = privateKeys.get(tenantId);
        }
        
        if (log.isDebugEnabled())
        	log.debug("Retrieved the private key:" + privateKey.toString());
        
        return privateKey;
    }

    /**
     * Retrieves the tenant's public certificate
     * @param tenantDomain
     * @param tenantId
     * @return
     * @throws Exception
     */
    private Certificate getCertificate(String tenantDomain, int tenantId) 
    	throws Exception 
    {
        if (tenantDomain == null) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        if (tenantId == 0) {
            tenantId = -1234;
        }

        Certificate publicCert = null;

        if (!(publicCerts.containsKey(tenantId))) {
            // get tenant's key store manager
            KeyStoreManager tenantKSM = KeyStoreManager.getInstance(tenantId);
            KeyStore keyStore = null;
			
            if (!tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
                // derive key store name
                String ksName = tenantDomain.trim().replace(".", "-");
                String jksName = ksName + ".jks";
                
                keyStore = tenantKSM.getKeyStore(jksName);
                publicCert = keyStore.getCertificate(tenantDomain);
            } 
			else {
                publicCert = tenantKSM.getDefaultPrimaryCertificate();
            }
			
            if (publicCert != null) {
                publicCerts.put(tenantId, publicCert);
            }
        } 
		else {
            publicCert = publicCerts.get(tenantId);
        }
        
        if (log.isDebugEnabled())
        	log.debug("Retrieved the public certificate:" + publicCert.toString());
        
        return publicCert;
    }

    /**
     * Helper method to hexify a byte array.
     *
     * @param bytes
     * @return  hexadecimal representation
     */
    private String hexify(byte bytes[]) {
        char[] hexDigits = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

        StringBuilder buf = new StringBuilder(bytes.length * 2);

        for (int i = 0; i < bytes.length; ++i) {
            buf.append(hexDigits[(bytes[i] & 0xf0) >> 4]);
            buf.append(hexDigits[bytes[i] & 0x0f]);
        }

        return buf.toString();
    }
}
