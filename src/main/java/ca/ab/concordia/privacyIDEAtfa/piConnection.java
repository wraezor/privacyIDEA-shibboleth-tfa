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

import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonArray;
import javax.json.JsonReader;
import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class piConnection {

  private final Logger          logger = LoggerFactory.getLogger(piConnection.class);
  protected piTokenInfoDecoder  tokenDecoder;
  //protected piUserDecoder       userDecoder;
  protected CloseableHttpClient httpClient;
  //protected HttpClientContext   httpContext;
  protected String              piServer;
  protected String              tfaAuthToken;

  // Sets up class objects (HTTP client, Decoders)
  public piConnection(String piServer, Boolean checkCertificate) throws piSessionException {
    this.piServer = piServer;
    
    httpClient    = getHttpClient(checkCertificate);
    //httpContext   = getHttpContext("admin", "blah");
    
    tokenDecoder  = new piTokenInfoDecoder();
    //userDecoder   = new piUserDecoder();
    
    System.out.println("Connection created");
    logger.debug("Connection created");
  }

  // Validate server authentication
  public boolean isAuthenticated() {
    return (tfaAuthToken != null);
  }

  public String callPrivacyIdeaAPI(String path, String method, Boolean authRequired, HashMap<String, String> parameters) throws piSessionException {
    String s = "";
    CloseableHttpResponse response = null;

    try {
      URIBuilder uriBuilder = new URIBuilder().setScheme("https")
          .setHost(piServer)
          .setPath(path);

      // Add GET/POST variables to HTTP call.
      for (Map.Entry<String, String> param : parameters.entrySet()) {
         //System.out.print("Key is: "+ param.getKey() + " & Value is: ");
         //System.out.println(param.getValue());
         uriBuilder.setParameter(param.getKey(), param.getValue());
      }

      HttpPost httppost = new HttpPost(uriBuilder.build());
      HttpGet httpget = new HttpGet(uriBuilder.build());

      if (authRequired == true) {
        if (isAuthenticated() == true) {
          httppost.addHeader("Authorization" , tfaAuthToken);
          httpget.addHeader("Authorization" , tfaAuthToken);
        } else {
          System.out.println("You must authenticate first!");
        }
      }

      //System.out.print("Query sent to tfa server: ");
      //System.out.println(uriBuilder.toString());

      if (method.equals("POST")) {
        response = httpClient.execute(httppost);
      } else {
        response = httpClient.execute(httpget);
      }

      HttpEntity entity = response.getEntity();
      s = EntityUtils.toString(entity);
      if (logger.isTraceEnabled())
        logger.trace("OTP Answer: {}", s);

      //System.out.println(s);

    }  catch (Exception e) {
      logger.debug("Failed to call privacyIDEA API", e);
      throw new piSessionException("Failed to call privacyIDEA API", e);
    } finally {
      if (response != null)
        try {
          response.close();
        } catch (IOException e) {}
    }

    return s;
  }

  // Authenticate server connection for privileged operations
  public boolean authenticateConnection(String piUser, String piPassword) throws piSessionException {
    logger.debug("Trying to authenticate against server");

    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("username", piUser);
      callParameters.put("password", piPassword);
      String s = callPrivacyIdeaAPI("/auth", "POST", false, callParameters);

      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();
      if (checkAPISuccess(otp) == true) {
        JsonObject result = otp.getJsonObject("result");
        JsonObject value = result.getJsonObject("value");


        if (value.containsKey("token")) {
          tfaAuthToken = value.getString("token");
        } else {
          System.out.println("Failed to authenticate");
        }
      }
    }  catch (Exception e) {
      System.out.println(e.getMessage());
      logger.debug("An error occurred trying to authenticate", e);
      throw new piSessionException("An error occurred trying to authenticate", e);
    }
    return (tfaAuthToken != null);
  }

  public boolean checkAPISuccess(JsonObject response) throws Exception {
    if (response.containsKey("result")) {
      JsonObject result = response.getJsonObject("result");
      if (result.containsKey("status")) {
        if (result.getBoolean("status", false) == true) {
          return true;
        }
      }
    }
    return false;
  }

  // Validate existing token by supplying serial number and token (tests token only, not PIN/password)
  public boolean validateTokenBySerial(String serial, String token) throws piSessionException {
    logger.debug("Trying to validate token by serial");
    
    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("serial", serial);
      callParameters.put("pass", token);
      callParameters.put("otponly", "1");
      String s = callPrivacyIdeaAPI("/validate/check", "GET", false, callParameters);
  
      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();
      if (checkAPISuccess(otp) == true) {
        JsonObject result = otp.getJsonObject("result");
        Boolean value = result.getBoolean("value", false);

        if (logger.isDebugEnabled())
          logger.debug("Validation value {}", value);

        if (value == true) {
          logger.debug("Token validated");
          return true;
        }
      }

    }  catch (Exception e) {
      logger.debug("Faileds to validate token", e);
      throw new piSessionException("Failed to validate token", e);
    }
    
    return false;
  }

  // Validate existing token by supplying username and password/token value
  public boolean validateTokenByUser(String user, String token) throws piSessionException {
    logger.debug("Trying to validate token by user");
    
    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("user", user);
      callParameters.put("pass", token);
      String s = callPrivacyIdeaAPI("/validate/check", "GET", false, callParameters);
  
      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();
      if (checkAPISuccess(otp) == true) {
        JsonObject result = otp.getJsonObject("result");
        Boolean value = result.getBoolean("value", false);

        if (logger.isDebugEnabled())
          logger.debug("Validation value {}", value);

        if (value == true) {
          System.out.println("Token validated");
          return true;
        }
      }

    }  catch (Exception e) {
      logger.debug("Faileds to validate token", e);
      throw new piSessionException("Failed to validate token", e);
    }
    
    return false;
  }

  // Get a user's SMS token
  public String getSMSToken(String user) throws piSessionException {
    logger.debug("Trying to retrieve SMS token for {}", user);
    String foundSerial = "000000000000";
    
    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("user", user);
      String s = callPrivacyIdeaAPI("/token/", "GET", true, callParameters);

      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();

      if (checkAPISuccess(otp) == true) {
        List<piTokenInfo> tokenList = tokenDecoder.decodeTokenList(otp);

        for (piTokenInfo token : tokenList) {
          if (token.getTokenType().equals("sms")) {
            foundSerial = token.getSerial(); 
          }
        }
      }

    }  catch (Exception e) {
      System.out.println(e.getMessage());
      logger.debug("Failed to retrieve SMS token for user", e);
      throw new piSessionException("Failed to retrieve SMS token for user", e);
    }
    return foundSerial;
  }

  // Get a user's email token
  public String getEmailToken(String user) throws piSessionException {
    logger.debug("Trying to retrieve email token for {}", user);
    String foundSerial = "000000000000";
    
    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("user", user);
      String s = callPrivacyIdeaAPI("/token", "GET", true, callParameters);

      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();

      if (checkAPISuccess(otp) == true) {
        List<piTokenInfo> tokenList = tokenDecoder.decodeTokenList(otp);

        for (piTokenInfo token : tokenList) {
          if (token.getTokenType().equals("email")) {
            foundSerial = token.getSerial(); 
          }
        }
      }

    }  catch (Exception e) {
      System.out.println(e.getMessage());
      logger.debug("Failed to retrieve email token for user", e);
      throw new piSessionException("Failed to retrieve email token for user", e);
    }
    return foundSerial;
  }

  public List<piTokenInfo> getTokenList(String user) throws piSessionException {
    logger.debug("Trying to retrieve all token for {}", user);
    
    CloseableHttpResponse response = null;
      
    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("user", user);
      String s = callPrivacyIdeaAPI("/token/", "GET", true, callParameters);

      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();
        
      List<piTokenInfo> tokenList  = tokenDecoder.decodeTokenList(otp);

      return tokenList;
    }  catch (Exception e) {
      System.out.println(e.getMessage());
      logger.debug("Failed to retrieve any token for user", e);
      throw new piSessionException("Failed to retrieve any token for user", e);
    }
  }



  // Issue challenge for a specific SMS token
  public void issueSMSChallenge(String serial) throws piSessionException {
    logger.debug("Issuing SMS challenge for token {}", serial);
    
    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("serial", serial);
      String s = callPrivacyIdeaAPI("/validate/triggerchallenge", "GET", true, callParameters);

      //System.out.println(s);

      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();
      if (checkAPISuccess(otp) == false) {
        System.out.println("Unable to issue SMS challenge");
        logger.debug("{} No details, probably no challenge/response");
      }
    }  catch (Exception e) {
      logger.debug("Failed to generate SMS challenge", e);
      throw new piSessionException("Failed to generate SMS challenge", e);
    }
    
  }

  // Issue challenge for a specific E-Mail token
  public void issueEmailChallenge(String serial) throws piSessionException {
    logger.debug("Issuing Email challenge for token {}", serial);

    try {
      HashMap<String, String> callParameters = new HashMap<String, String>();
      callParameters.put("serial", serial);
      String s = callPrivacyIdeaAPI("/validate/triggerchallenge", "GET", true, callParameters);

      JsonReader reader = Json.createReader(new StringReader(s));
      JsonObject otp = reader.readObject();
      if (checkAPISuccess(otp) == false) {
        System.out.println("Unable to issue Email challenge");
        logger.debug("{} No details, probably no challenge/response");
      }
    }  catch (Exception e) {
      logger.debug("Failed to generate Email challenge", e);
      throw new piSessionException("Failed to generate Email challenge", e);
    }

  } 


  private CloseableHttpClient getHttpClient(Boolean checkCert) throws piSessionException {
    CloseableHttpClient httpclient;
    
    if (checkCert) {
      httpclient = HttpClients.createDefault();
    }
    else {
      try {
        SSLContextBuilder builder = new SSLContextBuilder();
        SSLContext sslContext = builder.loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
            sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
      } catch (KeyManagementException e) {
        throw new piSessionException(e);
      } catch (NoSuchAlgorithmException e) {
        throw new piSessionException(e);
      } catch (KeyStoreException e) {
        throw new piSessionException(e);
      }
    }

    return httpclient;
  }
  
}
