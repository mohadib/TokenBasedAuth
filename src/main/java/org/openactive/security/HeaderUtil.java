package org.openactive.security;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by mohadib on 11/20/16.
 */
public class HeaderUtil
{

  public static String createHeader
  (
    String username,
    String userKey,
    String systemKey,
    String delimiter,
    String subDelimiter
  )
  {
    String timestamp = System.currentTimeMillis() + "";
    String toEncode = String.join( subDelimiter, username, timestamp, userKey, systemKey );
    String encoded = HeaderUtil.hashString( toEncode );
    return new String( Base64.encode( String.join( delimiter, username, timestamp, encoded ).getBytes() ) );
  }

  public static String hashString( String stringToHash )
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
    return new String( Hex.encode( digest.digest( stringToHash.getBytes() ) ) );
  }

  public static String[] tokenizeHeader(String headerValue, String delimiter)
  {
    for (int j = 0; j < headerValue.length() % 4; j++)
    {
      headerValue = headerValue + "=";
    }

    if ( !Base64.isBase64( headerValue.getBytes() ) )
    {
      throw new InvalidCookieException( "Cookie token was not Base64 encoded; value was '" + headerValue + "'" );
    }

    String cookieAsPlainText = new String( Base64.decode( headerValue.getBytes() ) );

    return StringUtils.delimitedListToStringArray( cookieAsPlainText, delimiter );
  }
}
