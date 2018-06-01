# Shibboleth 2FA with PrivacyIDEA

Library to integrate a step-up authentication via second factor for Shibboleth Identity Provider (IDP) version 3.  This was shamelessly adapted from the https://github.com/cyber-simon/idp-auth-linotp repository integrating Shibboleth with LinOTP.

## Installation

Checkout or clone the repository. Build the repository with Maven. A simple `mvn package` should be sufficient.

* Copy the resulting jar (shib-2fa-<VERSION>.jar) to your Shibboleth library folder. Depending on the deployment process of your shibboleth installation, this step can vary. If you are using an unpacked war file, you have to copy the file to the `{idp.home}/war/WEB-INF/lib` folder.  In cases where the WAR is 'built', you copy it to `{idp.home}/edit-webapp/WEB-INF/lib` then run a `{idp.home}/bin/build.sh`.
* Copy `src/main/resources/conf/authn/privacyidea-authn-*` to `{idp.home}/conf/authn/`
* Copy `src/main/resources/flows/authn/privacyidea` to `{idp.home}/flows/authn/`
* Copy `src/main/resources/views/*.vm` to `{idp.home}/views/`

## Configuration

1) Use the included `src/main/resources/conf/authn/mfa-authn-config.xml` to modify or replace your existing `{idp.home}/conf/authn/mfa-authn-config.xml`

2) Edit your `conf/authn/general-authn.xml` and add the authn/MFA and authn/privacyidea authentication methods there. Change the <CONTEXT_CLASS> to something useful, that will reflect your needs. For example: `https://<your-org>/auth/2fa`. Service Providers will have to use this string, if they want to use step-up authentication.  Order is important so put the MFA one first.

```xml
    <util:list id="shibboleth.AvailableAuthenticationFlows">

        <bean id="authn/MFA" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="true"
                p:forcedAuthenticationSupported="true">
            <!--
            The list below almost certainly requires changes, and should generally be the
            union of any of the separate factors you combine in your particular MFA flow
            rules. The example corresponds to the example in mfa-authn-config.xml that
            combines IPAddress with Password.
            -->
            <property name="supportedPrincipals">
                <list>
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocol" />
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" />
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:Password" />
                    <bean parent="shibboleth.SAML1AuthenticationMethod"
                        c:method="urn:oasis:names:tc:SAML:1.0:am:password" />
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="<CONTEXT_CLASS>" />
                </list>
            </property>
        </bean>

    ....

        <bean id="authn/privacyidea" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="true"
                p:forcedAuthenticationSupported="true">
            <property name="supportedPrincipals">
                <list>
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="<CONTEXT_CLASS>" />
                </list>
            </property>
        </bean>
    
    ....
    
    </util:list>
```

Alter your `conf/idp.properties` file and add the authentication method you just created. Don't just alter the lines completely, just append the new method with a pipe (|) sign. Don't damage your existing configuration.

```
# Regular expression matching login flows to enable, e.g. IPAddress|Password
idp.authn.flows= MFA|Password|privacyidea
```

Also add the following configuration values:

```
pi.Host = <your linotp host>
pi.Serviceuser = <service user>
pi.Servicepassword = <password>
pi.Checkcert = <true: check DN of certificate match>
```

You will most probably need to customize the `vm` files view to reflect your IDP design.

## Testing

Testshib.org in conjunction with debug logging is a life saver.  Get your IDP running and you can test the login process via https://sp.testshib.org/  To enable debug logging for your class, edit `{idp.home}/conf/logback.xml`  and add the following lines:

```
    <logger name="ca.ab.concordia.privacyIDEAtfa" level="DEBUG" />
    <logger name="checkFor2FAToken" level="DEBUG" />
```
