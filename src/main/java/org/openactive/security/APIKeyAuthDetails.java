package org.openactive.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Properties;

/**
 * Created by mohadib on 11/20/16.
 */
public class APIKeyAuthDetails implements UserDetailsService
{

  @Autowired
  private Properties apiProperties;

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
  {
    String key = apiProperties.getProperty(username);
    if( key != null )
    {
      return new User( username, key, AuthorityUtils.createAuthorityList("ROLE_USER"));
    }
    return null;
  }
}
