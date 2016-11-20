package org.openactive.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.ForwardAuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by mohadib on 11/19/16.
 */
public class HeaderAuthenticationFilter extends AbstractAuthenticationProcessingFilter
{
  private HeaderRequestMatcher matcher;

  public HeaderAuthenticationFilter(HeaderRequestMatcher matcher)
  {
    super(matcher);
    this.matcher = matcher;
  }

  @Override
  public Authentication attemptAuthentication
  (
    HttpServletRequest request,
    HttpServletResponse response
  ) throws AuthenticationException, IOException, ServletException
  {
    Authentication authToken = new HeaderAuthentication(request.getHeader(matcher.getHeaderName()), request.getRemoteAddr());
    return getAuthenticationManager().authenticate(authToken);
  }

  @Override
  protected boolean getAllowSessionCreation()
  {
    return false;
  }

  @Override
  protected void successfulAuthentication
  (
    HttpServletRequest request,
    HttpServletResponse response,
    FilterChain chain,
    Authentication authResult
  ) throws IOException, ServletException
  {
    SecurityContextHolder.getContext().setAuthentication(authResult);
    getRememberMeServices().loginSuccess(request, response, authResult);
    chain.doFilter(request, response);
  }
}
