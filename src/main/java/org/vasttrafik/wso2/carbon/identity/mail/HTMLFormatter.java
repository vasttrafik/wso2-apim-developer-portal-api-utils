package org.vasttrafik.wso2.carbon.identity.mail;

import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMOutputFormat;
import org.apache.axiom.om.util.ElementHelper;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.format.PlainTextFormatter;

public class HTMLFormatter extends PlainTextFormatter {

	@Override
    public void writeTo(MessageContext messageContext, OMOutputFormat format, OutputStream outputStream, boolean preserve) throws AxisFault {
        OMElement textElt = messageContext.getEnvelope().getBody().getFirstElement();
		
        try {
			Writer out = new OutputStreamWriter(outputStream, format.getCharSetEncoding());
            ElementHelper.writeTextTo(textElt, out, preserve);
            out.flush();
        } 
		catch (Exception e) {
            throw new AxisFault("Error extracting the text payload from the message", e);
        }
    }

	@Override
    public String getContentType(MessageContext messageContext, OMOutputFormat format, String soapAction) {
        String encoding = format.getCharSetEncoding();
        String contentType = "text/html";

        if (encoding != null) {
            contentType += "; charset=" + encoding;
        }

        // if soap action is there (can be there is soap response MEP is used) add it.
        if ((soapAction != null)
                && !"".equals(soapAction.trim())
                && !"\"\"".equals(soapAction.trim())) {
            contentType = contentType + ";action=\"" + soapAction + "\";";
        }

        return contentType;
    }
}
