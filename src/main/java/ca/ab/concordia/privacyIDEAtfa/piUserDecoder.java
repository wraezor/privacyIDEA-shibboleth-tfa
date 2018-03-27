/*******************************************************************************
 * Copyright 2018 Michael Simon, Jordan Dohms
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 ******************************************************************************/
package ca.ab.concordia.privacyIDEAtfa;

import java.util.ArrayList;
import java.util.List;

import javax.json.JsonArray;
import javax.json.JsonObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class piUserDecoder {

	private static Logger logger = LoggerFactory.getLogger(piUserDecoder.class);
	
	public piUser decode(JsonObject object) {
		piUser user = new piUser();
		user.setUserId(JsonHelper.getStringOrNull(object, "userid"));
		user.setUserName(JsonHelper.getStringOrNull(object, "username"));
		user.setSurName(JsonHelper.getStringOrNull(object, "surname"));
		user.setGivenName(JsonHelper.getStringOrNull(object, "givenname"));
		user.setEmail(JsonHelper.getStringOrNull(object, "email"));
		user.setUserIdResolver(JsonHelper.getStringOrNull(object, "resolver"));
		
		return user;
	}
	
	public List<piUser> decodeUserList(JsonObject object) {
        JsonObject result = object.getJsonObject("result");
        
        Boolean status = result.getBoolean("status", false);
	    
        if (logger.isDebugEnabled())
	    	logger.debug("LinOTP Session status {} and value {}", status);

    	List<piUser> userList = new ArrayList<piUser>();

    	if (status && result.containsKey("value") && result.containsKey("value")) {
        	
        	JsonArray data = result.getJsonArray("value");
        	
        	for (int i=0; i<data.size(); i++) {
    	        if (logger.isDebugEnabled())
    		    	logger.debug("LinOTP processing user {}", i);

    	        JsonObject jo = data.getJsonObject(i);
        		
    	        piUser user = decode(jo);
        		
    	        userList.add(user);
        	}
        	
        }
    	
    	return userList;
	}
}
