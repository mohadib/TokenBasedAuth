package org.openactive.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Created by mohadib on 11/19/16.
 */
public class HeaderRequestMatcher implements RequestMatcher
{
  private final String headerName;
  private final AntPathRequestMatcher pathmatcher;

  public HeaderRequestMatcher(String headerName, String antPath)
  {
    this.headerName = headerName;
    pathmatcher = new AntPathRequestMatcher(antPath);
  }

  @Override
  public boolean matches(HttpServletRequest request)
  {
    if( !pathmatcher.matches( request ) ) return false;

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if( auth == null || !auth.isAuthenticated() )
    {
      return request.getHeader( headerName ) != null;
    }
    return false;
  }
}
