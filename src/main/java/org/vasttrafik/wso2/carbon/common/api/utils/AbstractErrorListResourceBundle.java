package org.vasttrafik.wso2.carbon.common.api.utils;

import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;

import org.vasttrafik.wso2.carbon.common.api.beans.Error;

import sun.util.ResourceBundleEnumeration;

/**
 * 
 * @author Lars Andersson
 *
 */
@SuppressWarnings("restriction")
public abstract class AbstractErrorListResourceBundle extends ResourceBundle {
	
	private Map<String,Object[]> lookup = null;
	
	public Object handleGetObject(String key) {
		 if (lookup == null) {
			 loadLookup();
		 }

		 if (key == null) {
		     throw new NullPointerException();
		 }

		 return (Object)lookup.get(key); 
	 }
	 
	 public Enumeration<String> getKeys() {
		 if (lookup == null) {
			 loadLookup();
		 }
		         
		 ResourceBundle parent = this.parent;
		 return new ResourceBundleEnumeration(lookup.keySet(), (parent != null) ? parent.getKeys() : null);
	 }
	 
	 protected Set<String> handleKeySet() {
		 if (lookup == null) {
			 loadLookup();
		  }
		  return lookup.keySet();
	 }
	 
	 abstract protected Object[][] getContents();
	 
	 public String getMessage(String code, Object[] args) {
		 try {
			 Long l = Long.valueOf(code);
			 return getMessage(l, args);
		 }
		 catch (NumberFormatException nfe) {
			 return "";
		 }
	 }
	 
	 public String getMessage(Long code, Object[] args) {
		 if (lookup == null) {
			 loadLookup();
		  }
		 
		 /**
		  * Get the resources associated with the code
		  */
		 Object[] resources = null;
		 String message = null;
			
		 try {
			resources = (Object[])getObject(String.valueOf(code));
			
			if (resources != null) {
				if (args != null && args.length > 0 && args[0] != null)
					message = MessageFormat.format(resources[0].toString(), args[0]);
				else
					message = resources[0].toString();
				
			}
		 }
		 catch (Exception e) {
			e.printStackTrace();
		 }
		 return message;
	 }
	
	 public Error getError(Long code, Object[][] args) {
		 if (lookup == null) {
			 loadLookup();
		 }
		
		 /**
		  * Create the Error object
		  */
		 Error error = new Error();
		 error.setCode(code);
		
		 /**
		  * Get the resources associated with the code
		  */
		 Object[] resources = null;
		
		 try {
			resources = (Object[])getObject(String.valueOf(code));
		 }
		 catch (Exception e) {
			e.printStackTrace();
		 }
		
		 if (resources != null) {
			/**
			 * Set the error message attribute value
			 */
			if (resources.length > 0 && resources[0] != null) {
				if (args != null && args.length > 0 && args[0] != null)
					error.setMessage(MessageFormat.format(resources[0].toString(), args[0]));
				else
					error.setMessage(resources[0].toString());
			}
			/**
			 * Set the error description attribute value
			 */
			if (resources.length > 1 && resources[1] != null) {
				if (args != null && args.length > 1 && args[1] != null) {
					error.setDescription(MessageFormat.format(resources[1].toString(), args[1]));
				}else{
					error.setDescription(resources[1].toString());
				}
			}
			/**
			 * Set the more info attribute value
			 */
			if (resources.length > 2 && resources[2] != null) {
				if (args != null && args.length > 2 && args[2] != null)
					error.setMessage(MessageFormat.format(resources[2].toString(), args[2]));
				else
					error.setMessage(resources[2].toString());
			}
		}
		
		return error;
	}
	
	private synchronized void loadLookup() {
		if (lookup != null)
			return;
		
		Object[][] contents = getContents();
		        
		HashMap<String,Object[]> temp = new HashMap<String,Object[]>(contents.length);
		        
		for (int i = 0; i < contents.length; ++i) {
			// key must be non-null String, value must be non-null
			String key = (String) contents[i][0];
			Object[] values = new Object[contents[i].length - 1];
			
			for (int j = 1; j < contents[i].length; j++)
				values[j-1] = contents[i][j];
			
			if (key == null || values == null) {
				throw new NullPointerException();
			}
		    temp.put(key, values);
		}
		lookup = temp;
	}
}
