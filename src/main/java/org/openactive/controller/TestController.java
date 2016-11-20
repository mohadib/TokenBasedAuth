package org.openactive.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by mohadib on 11/19/16.
 */
@Controller
public class TestController
{
    @RequestMapping(path = "/test", method = RequestMethod.GET)
    @ResponseBody
    @Secured("ROLE_USER")
    public String test()
    {
        return "HELLO WORLDD";
    }

  @RequestMapping(path = "/sso", method = RequestMethod.GET)
  @ResponseBody
  @Secured("ROLE_USER")
  public String sso()
  {
    return "sso";
  }
}
