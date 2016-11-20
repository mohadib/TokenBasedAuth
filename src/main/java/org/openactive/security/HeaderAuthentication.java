package org.openactive.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

/**
 * Created by mohadib on 11/20/16.
 */
public class HeaderAuthentication extends AbstractAuthenticationToken
{
  private String headerValue, ipAddress;

  public HeaderAuthentication( String headerValue, String ipAddress)
  {
    super(null);
    this.headerValue = headerValue;
    this.ipAddress = ipAddress;
  }

  @Override
  public Object getCredentials()
  {
    return headerValue;
  }

  @Override
  public Object getPrincipal()
  {
    return ipAddress;
  }
}
