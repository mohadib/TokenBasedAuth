package org.openactive.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

/**
 * Created by mohadib on 11/20/16.
 */
@Component
public class HeaderAuthenticationProvider implements AuthenticationProvider
{
  @Autowired
  private Properties apiProperties;

  @Value("${ttl}")
  private int ttl;

  @Value("${delim}")
  private String delim;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException
  {
    HeaderAuthentication headerAuthentication = (HeaderAuthentication) authentication;
    String[] tokens = HeaderUtil.tokenizeHeader( headerAuthentication.getCredentials().toString(), ":");
    boolean authenticated = authenticateWithTokens( tokens );

    if( !authenticated ) throw new BadCredentialsException("Fail");

    UserDetails ud = new User("Jason", "", AuthorityUtils.createAuthorityList("ROLE_USER"));
    UsernamePasswordAuthenticationToken fullAuth = new UsernamePasswordAuthenticationToken(ud, null, ud.getAuthorities());
    return fullAuth;
  }

  /**
   * tokens [ username : (salt)timestamp : md5hex( userName : timestamp : userKey : systemKey )
   *
   * @param tokens
   */
  private boolean authenticateWithTokens(String[] tokens)
  {
    if (tokens.length != 3) return false;

    String userName = tokens[0];
    String timestamp = tokens[1];
    String hexed = tokens[2];

    // is timestamp older than 3 seconds?!
    try
    {
      long timeDelta = System.currentTimeMillis() - Long.parseLong(timestamp);
      if (timeDelta > ttl)
      {
        System.out.println("TOO OLD " + timeDelta);
        return false;
      }
    }
    catch ( NumberFormatException ne )
    {
      ne.printStackTrace();
      return false;
    }

    String systemKey = apiProperties.getProperty("key");
    String userKey = apiProperties.getProperty("user." + userName);

    if( systemKey == null || userKey == null )
    {
      return false;
    }

    String rebuiltKey = HeaderUtil.hashString( String.join( delim, userName, timestamp, userKey, systemKey ) );
    return rebuiltKey.equals(hexed);
  }

  private String encode(String rebuiltKey)
  {
    MessageDigest digest;
    try
    {
      digest = MessageDigest.getInstance("MD5");
    }
    catch (NoSuchAlgorithmException e)
    {
      throw new IllegalStateException("No MD5 algorithm available!");
    }
    return new String( Hex.encode( digest.digest( rebuiltKey.getBytes() ) ) );
  }

  private String[] decodeHeader(String headerValue)
  {
    for (int j = 0; j < headerValue.length() % 4; j++)
    {
      headerValue = headerValue + "=";
    }

    if (!Base64.isBase64(headerValue.getBytes()))
    {
      throw new InvalidCookieException("Cookie token was not Base64 encoded; value was '" + headerValue + "'");
    }

    String cookieAsPlainText = new String(Base64.decode(headerValue.getBytes()));

    return StringUtils.delimitedListToStringArray(cookieAsPlainText, ":");
  }

  @Override
  public boolean supports(Class<?> authentication)
  {
    return HeaderAuthentication.class.equals(authentication);
  }
}
