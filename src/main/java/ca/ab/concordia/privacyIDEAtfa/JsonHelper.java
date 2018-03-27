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

import javax.json.JsonObject;

public class JsonHelper {

	public static Long getLongOrNull(JsonObject object, String key) {
		if (object.containsKey(key)) {
			return object.getJsonNumber(key).longValue();
		}
		else {
			return null;
		}
	}

	public static String getStringOrNull(JsonObject object, String key) {
		if (object.containsKey(key)) {
			return object.getJsonString(key).getString();
		}
		else {
			return null;
		}
	}
	
	public static Boolean getBooleanOrNull(JsonObject object, String key) {
		if (object.containsKey(key)) {
			return object.getBoolean(key);
		}
		else {
			return null;
		}
	}
	
}
