package org.openactive.security;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import static org.junit.Assert.*;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

/**
 * Created by mohadib on 11/20/16.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = HeaderAuthenticationProviderTest.TestConfiguration.class)
public class HeaderAuthenticationProviderTest
{

  @Autowired
  private HeaderAuthenticationProvider headerAuthenticationProvider;

  @Value("${delim}")
  private String delim;

  @Test
  public void testAuthenticate()
  {
    // tokens [ username : (salt)timestamp : md5hex( userName : timestamp : userKey : systemKey )
    String timestamp = System.currentTimeMillis()+"";
    String encoded = encode(String.join(delim, "connect", timestamp, "66B&2YXq3s$nU*5mkweB5r6BXRs%qntu", "xd^Z6Cu?X&DzrM24+zM-cFnjfjF^Y8=g"));

    String cookieValue = new String(Base64.encode( String.join(":", "connect", timestamp, encoded).getBytes() ));
    System.out.println(cookieValue);
    HeaderAuthentication ha = new HeaderAuthentication(  cookieValue, "10.0.5.2");
    Authentication full = headerAuthenticationProvider.authenticate( ha );

    assertNotNull( full );
    assertNotNull( full.getAuthorities() );
    assertEquals(1, full.getAuthorities().size());
    assertEquals("ROLE_USER", full.getAuthorities().iterator().next().getAuthority());
    assertTrue( full.isAuthenticated() );
    assertEquals("Jason", ((UserDetails)full.getPrincipal()).getUsername());
  }


  @Test(expected = BadCredentialsException.class)
  public void testTooOldFailAuthenticate()
  {
    // tokens [ username : (salt)timestamp : md5hex( userName : timestamp : userKey : systemKey )
    String timestamp = System.currentTimeMillis()+"";
    String encoded = encode(String.join(delim, "connect", timestamp, "66B&2YXq3s$nU*5mkweB5r6BXRs%qntu", "xd^Z6Cu?X&DzrM24+zM-cFnjfjF^Y8=g"));

    String cookieValue = new String(Base64.encode( String.join(":", "connect", timestamp, encoded).getBytes() ));
    System.out.println(cookieValue);
    HeaderAuthentication ha = new HeaderAuthentication(  cookieValue, "10.0.5.2");

    try { Thread.sleep(3100); }catch ( Exception e){}

    Authentication full = headerAuthenticationProvider.authenticate( ha );
  }

  @Test(expected = BadCredentialsException.class)
  public void testFailAuthenticate()
  {
    // tokens [ username : (salt)timestamp : md5hex( userName : timestamp : userKey : systemKey )
    String timestamp = System.currentTimeMillis()+"";
    String encoded = encode(String.join(delim, "connect", timestamp, "BAD66B&2YXq3s$nU*5mkweB5r6BXRs%qntu", "xd^Z6Cu?X&DzrM24+zM-cFnjfjF^Y8=g"));

    String cookieValue = new String(Base64.encode( String.join(":", "connect", timestamp, encoded).getBytes() ));

    System.out.println(cookieValue);
    HeaderAuthentication ha = new HeaderAuthentication(  cookieValue, "10.0.5.2");
    Authentication full = headerAuthenticationProvider.authenticate( ha );
  }

  @Test
  public void testFailAuthenticateUnsupportedToken()
  {
    assertFalse( headerAuthenticationProvider.supports(UsernamePasswordAuthenticationToken.class));
  }

  private String encode(String key)
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
    return new String( Hex.encode( digest.digest( key.getBytes() ) ) );
  }

  @Configuration
  public static class TestConfiguration
  {
    @Bean
    public HeaderAuthenticationProvider headerAuthenticationProvider()
    {
      return new HeaderAuthenticationProvider();
    }

    @Bean
    public Properties apiProperties()
    {
      Properties props = new Properties();
      props.put("key", "xd^Z6Cu?X&DzrM24+zM-cFnjfjF^Y8=g");
      props.put("user.connect", "66B&2YXq3s$nU*5mkweB5r6BXRs%qntu");
      props.put("ttl", "3000");
      props.put("delim", "<<_");
      return props;
    }

    @Bean
    public PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer()
    {
      PropertySourcesPlaceholderConfigurer config = new PropertySourcesPlaceholderConfigurer();
      config.setProperties(apiProperties());
      return config;
    }
  }
}
