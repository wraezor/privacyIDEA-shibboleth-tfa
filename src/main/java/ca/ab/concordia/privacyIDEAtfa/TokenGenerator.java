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
/*package ca.ab.concordia.privacyIDEAtfa;

import java.util.List;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.session.context.SessionContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

import com.google.common.base.Function;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenGenerator extends AbstractProfileAction<SAMLObject, SAMLObject> {

	private final Logger logger = LoggerFactory.getLogger(TokenGenerator.class);

	protected TokenContext tokenCtx;
	
	private Function<ProfileRequestContext,String> usernameLookupStrategy;
	protected String username;

	private String host;
	private String serviceUsername;
	private String servicePassword;
	private Boolean checkCert;
	private Boolean createEmailToken;
	
	public TokenGenerator() {
		usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
	}

    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
    }
    
	@Override
	protected boolean doPreExecute(ProfileRequestContext<SAMLObject, SAMLObject> profileRequestContext) {
		logger.debug("Entering GenerateNewToken doPreExecute");

        if (!super.doPreExecute(profileRequestContext)) {
            return false;
        }

		try {
			AuthenticationContext authenticationContext = profileRequestContext.getSubcontext(AuthenticationContext.class);
			if (authenticationContext == null) {
	        	logger.warn("{} No AuthenticationContext is set", getLogPrefix());
	        	return false;
			}
			
			tokenCtx = profileRequestContext.getSubcontext(AuthenticationContext.class)
					.getSubcontext(TokenContext.class, true);

			username = usernameLookupStrategy.apply(profileRequestContext);

	        if (username == null) {
	        	logger.warn("{} No previous SubjectContext or Principal is set", getLogPrefix());
	        	return false;
	        }
			
	    	logger.debug("{} PrincipalName from SubjectContext is {}", getLogPrefix(), username);
	    	tokenCtx.setUsername(username);
	    	
			return true;
		} catch (Exception e) {
			logger.debug("Error with doPreExecute", e);
			return false;		
		}
	}	

    @Override
	protected void doExecute(@Nonnull final ProfileRequestContext<SAMLObject, SAMLObject> profileRequestContext) {
    	logger.debug("Entering GenerateNewToken doExecute");
			
		try {
			piConnection connection = new piConnection(host, checkCert);
			//connection.requestAdminSession();
			List<piTokenInfo> tokenList = connection.getTokenInfoList(username);
			
			if (createEmailToken && tokenList.size() == 0) {
				List<piUser> userList = connection.getUserList("userid", username);
				if (userList.size() == 1) {
					connection.initEmailToken(username, userList.get(0).getEmail());
					tokenList = connection.getTokenInfoList(username);
				}
			}
			
			tokenCtx.setTokenList(tokenList);
			
			//connection.generateToken(tokenCtx);
			
		} catch (Exception e) {
			logger.debug("Failed to create new token", e);
		}
		
	}

	public void setHost(@Nonnull @NotEmpty final String fieldName) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		host = fieldName;
	}

	public void setServiceUsername(@Nonnull @NotEmpty final String fieldName) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		serviceUsername = fieldName;
	}

	public void setServicePassword(@Nonnull @NotEmpty final String fieldName) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		servicePassword = fieldName;
	}

	public void setCheckCert(@Nonnull @NotEmpty final Boolean fieldName) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		checkCert = fieldName;
	}

	public void setCreateEmailToken(@Nonnull @NotEmpty final Boolean fieldName) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		createEmailToken = fieldName;
	}

}
*/