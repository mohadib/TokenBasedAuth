package org.openactive.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Arrays;

/**
 * Created by mohadib on 11/20/16.
 */
@Component
public class HeaderAuthenticationProvider implements AuthenticationProvider
{
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException
  {
    HeaderAuthentication headerAuthentication = (HeaderAuthentication) authentication;
    if( !"HELLO".equals( headerAuthentication.getCredentials().toString() ) ) return null;

    UserDetails ud = new User("Jason", "", AuthorityUtils.createAuthorityList("ROLE_USER"));
    UsernamePasswordAuthenticationToken fullAuth = new UsernamePasswordAuthenticationToken( ud, null, ud.getAuthorities());
    return fullAuth;
  }

  @Override
  public boolean supports(Class<?> authentication)
  {
    return HeaderAuthentication.class.equals( authentication );
  }
}
