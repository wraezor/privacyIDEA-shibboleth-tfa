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

public class piTokenInfoDecoder {

	private static Logger logger = LoggerFactory.getLogger(piTokenInfoDecoder.class);
	
	public piTokenInfo decode(JsonObject object) {
		piTokenInfo token = new piTokenInfo();
		token.setTokenId(JsonHelper.getLongOrNull(object, "id"));
		token.setTokenType(JsonHelper.getStringOrNull(object, "tokentype"));
		//token.setTokenInfo(JsonHelper.getStringOrNull(object, "tokeninfo"));
		token.setTokenDesc(JsonHelper.getStringOrNull(object, "description"));
		token.setSerial(JsonHelper.getStringOrNull(object, "serial"));
		token.setActive(JsonHelper.getBooleanOrNull(object, "active"));
		token.setFailCount(JsonHelper.getLongOrNull(object, "failcount"));
		token.setMaxFailCount(JsonHelper.getLongOrNull(object, "maxfail"));
		
		return token;
	}
	
	public List<piTokenInfo> decodeTokenList(JsonObject object) {
        JsonObject result = object.getJsonObject("result");
        
        Boolean status = result.getBoolean("status", false);
	    
        if (logger.isDebugEnabled())
	    	logger.debug("Session status {} and value {}", status);

    	List<piTokenInfo> tokenList = new ArrayList<piTokenInfo>();

    	if (status && result.containsKey("value") && result.getJsonObject("value").containsKey("tokens")) {
        	
        	JsonArray data = result.getJsonObject("value").getJsonArray("tokens");
        	
        	for (int i=0; i<data.size(); i++) {
    	        if (logger.isDebugEnabled())
    		    	logger.debug("Processing token {}", i);
                //System.out.println("Processing token");
    	        JsonObject jo = data.getJsonObject(i);
        		
    	        piTokenInfo token = decode(jo);
        		
        		tokenList.add(token);
        	}
        	
        }
    	
    	return tokenList;
	}
}
