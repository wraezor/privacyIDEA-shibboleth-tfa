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

import java.util.List;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import com.google.common.base.Function;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.idp.session.context.SessionContext;
import net.shibboleth.idp.session.context.navigate.CanonicalUsernameLookupStrategy;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

public class TokenValidator extends AbstractValidationAction {

	private final Logger logger = LoggerFactory.getLogger(TokenValidator.class);

        private CanonicalUsernameLookupStrategy usernameLookupStrategy;
	private String username;
	
	private String host;
	private String serviceUsername;
	private String servicePassword;
	private Boolean checkCert;

	public TokenValidator() {
			usernameLookupStrategy = new CanonicalUsernameLookupStrategy();
	}

    @Override
    protected boolean doPreExecute(
            @Nonnull ProfileRequestContext profileRequestContext,
            @Nonnull AuthenticationContext authenticationContext) {
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }

		username = usernameLookupStrategy.apply(profileRequestContext);

        if (username == null) {
        	logger.warn("{} No previous SubjectContext or Principal is set", getLogPrefix());
        	handleError(profileRequestContext, authenticationContext, "NoCredentials", AuthnEventIds.NO_CREDENTIALS);
        	return false;
        }
        
    	logger.debug("{} PrincipalName from SubjectContext is {}", getLogPrefix(), username);
        return true;
    }
	
	@Override
	protected Subject populateSubject(Subject subject) {
		logger.debug("{} TokenValidator populateSubject is called", getLogPrefix());		
		if (StringSupport.trimOrNull(username) != null) {
			logger.debug("{} Populate subject {}", getLogPrefix(), username);
			subject.getPrincipals().add(new UsernamePrincipal(username));
			return subject;
		}
		return null;
	}
	
	@Override
	protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
			@Nonnull final AuthenticationContext authenticationContext) {
		logger.debug("{} Entering TokenValidator doExecute", getLogPrefix());		

		TokenContext tokenCtx = authenticationContext.getSubcontext(TokenContext.class, true);

		logger.debug("{} TokenValidator is called with token {} for user {}", getLogPrefix(), tokenCtx.getToken(), username);

		try {
      piConnection connection = new piConnection(host, checkCert);
      connection.authenticateConnection(serviceUsername, servicePassword);
      
      List<piTokenInfo> tokenList = connection.getTokenList(username);

      for (piTokenInfo token : tokenList) {
        logger.debug("Token: {} / Type: {}", token.getSerial(), token.getTokenType());
        boolean login = connection.validateTokenBySerial(token.getSerial(), tokenCtx.getToken());
        
        if (login == true) {
          buildAuthenticationResult(profileRequestContext, authenticationContext);
          return;
        }
      }
        
      handleError(profileRequestContext, authenticationContext, "TokenWrong",
            AuthnEventIds.INVALID_CREDENTIALS);

    }		
    catch (Exception e) { 
      logger.warn("{} Exception while validating token: {}", getLogPrefix(), e.getMessage());
      handleError(profileRequestContext, authenticationContext, e,
          AuthnEventIds.AUTHN_EXCEPTION);
    }
  }

	
	public void setHost(@Nonnull @NotEmpty final String fieldName) {
		logger.debug("{} {} is tokencode field from the form", getLogPrefix(), fieldName);
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		host = fieldName;
	}

	public void setServiceUsername(@Nonnull @NotEmpty final String fieldName) {
		logger.debug("{} {} is tokencode field from the form", getLogPrefix(), fieldName);
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		serviceUsername = fieldName;
	}

	public void setServicePassword(@Nonnull @NotEmpty final String fieldName) {
		//~ logger.debug("{} {} is tokencode field from the form", getLogPrefix(), fieldName);
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		servicePassword = fieldName;
	}

	public void setCheckCert(@Nonnull @NotEmpty final Boolean fieldName) {
		ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
		checkCert = fieldName;
	}

}
