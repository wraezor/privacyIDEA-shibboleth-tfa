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

public class piTokenInfo {

	private long 		tokenId;
	private String 	serial;
	private String 	tokenType;
	private String 	tokenInfo;
	private String 	tokenDesc;
	private long 		failCount;
	private long 		maxFailCount;
	private boolean isActive;
	
	public long getTokenId() {
		return tokenId;
	}
	
	public void setTokenId(long tokenId) {
		this.tokenId = tokenId;
	}
	
	public String getTokenType() {
		return tokenType;
	}
	
	public void setTokenType(String tokenType) {
		this.tokenType = tokenType;
	}
	
	public String getTokenInfo() {
		return tokenInfo;
	}
	
	public void setTokenInfo(String tokenInfo) {
		this.tokenInfo = tokenInfo;
	}
	
	public String getTokenDesc() {
		return tokenDesc;
	}
	
	public void setTokenDesc(String tokenDesc) {
		this.tokenDesc = tokenDesc;
	}
	
	public boolean isActive() {
		return isActive;
	}
	
	public void setActive(boolean isActive) {
		this.isActive = isActive;
	}

	public String getSerial() {
		return serial;
	}

	public void setSerial(String serial) {
		this.serial = serial;
	}

	public long getFailCount() {
		return failCount;
	}

	public void setFailCount(long failCount) {
		this.failCount = failCount;
	}

	public long getMaxFailCount() {
		return maxFailCount;
	}

	public void setMaxFailCount(long maxFailCount) {
		this.maxFailCount = maxFailCount;
	}
}
