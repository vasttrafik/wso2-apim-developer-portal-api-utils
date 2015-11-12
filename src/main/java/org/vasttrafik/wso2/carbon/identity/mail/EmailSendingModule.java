package org.vasttrafik.wso2.carbon.identity.mail;

import java.util.HashMap;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;

import org.apache.axis2.Constants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.transport.base.BaseConstants;
import org.apache.axis2.transport.mail.MailConstants;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.CarbonConfigurationContextFactory;
import org.wso2.carbon.identity.mgt.mail.DefaultEmailSendingModule;
import org.wso2.carbon.identity.mgt.mail.EmailConfig;
import org.wso2.carbon.identity.mgt.mail.Notification;

public class EmailSendingModule extends DefaultEmailSendingModule {

    @Override
    public void sendEmail() {

        Map<String, String> headerMap = new HashMap<String, String>();

        try {
			Notification notification = getNotification();
			
            if (notification == null) {
                throw new IllegalStateException("Notification not set. Please set the notification before sending messages");
            }
			
            PrivilegedCarbonContext.startTenantFlow();
			
            if (notificationData != null) {
                String tenantDomain = notificationData.getDomainName();
                
				PrivilegedCarbonContext carbonContext = PrivilegedCarbonContext.getThreadLocalCarbonContext();
                carbonContext.setTenantDomain(tenantDomain, true);
            } 

            headerMap.put(MailConstants.MAIL_HEADER_SUBJECT, notification.getSubject());

            OMElement payload = OMAbstractFactory.getOMFactory().createOMElement(
				new QName("http://ws.apache.org/commons/ns/payload", "text/html"), null);
            
			StringBuilder contents = new StringBuilder();
            contents.append(notification.getBody())
                    .append(System.getProperty("line.separator"))
                    .append(System.getProperty("line.separator"))
                    .append(notification.getFooter());
            
			payload.setText(contents.toString());
            ServiceClient serviceClient;
            ConfigurationContext configContext = 
				CarbonConfigurationContextFactory.getConfigurationContext();
            
			if (configContext != null) {
                serviceClient = new ServiceClient(configContext, null);
            } else {
                serviceClient = new ServiceClient();
            }
            
			Options options = new Options();
            options.setProperty(Constants.Configuration.ENABLE_REST, Constants.VALUE_TRUE);
            options.setProperty(MessageContext.TRANSPORT_HEADERS, headerMap);
            options.setProperty(MailConstants.TRANSPORT_MAIL_FORMAT, MailConstants.TRANSPORT_FORMAT_TEXT);
			options.setProperty("messageType", "text/html");
			options.setProperty("ContentType", "text/html");
            options.setTo(new EndpointReference("mailto:" + notification.getSendTo()));
            
			serviceClient.setOptions(options);
            serviceClient.fireAndForget(payload);
        } 
		catch (Exception e) {
            e.printStackTrace();
        } 
		finally {
            PrivilegedCarbonContext.endTenantFlow();
        }

    }
	
	@Override
    public void setNotification(Notification notification) {
        String body = notification.getBody();
        body = body.replaceAll("&lt;", "<");
        body = body.replaceAll("&#47;", "/");
        body = body.replaceAll("&gt;", ">");
		notification.setBody(body);
        
        super.setNotification(notification);
    }
}
