package org.azure.acs

import com.google.common.base.Strings
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.jwt.JwtHelper
import org.springframework.web.filter.GenericFilterBean

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest

/**
 * User: charles
 * Date: 29/12/14
 * Time: 11:13
 * Author : cblonde@xebia.fr
 * ACS authentication at request level
 */
class AcsRequestFilter extends GenericFilterBean {
    @Override
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (request instanceof HttpServletRequest) {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request
            String authorizationHeader = httpServletRequest.getHeader("Authorization")
            if (!Strings.isNullOrEmpty(authorizationHeader)) {
                def acsAuthenticationToken = new AcsAuthenticationToken(jwtToken: JwtHelper.decode(authorizationHeader))
                SecurityContextHolder.context.setAuthentication(acsAuthenticationToken)
            }
        }
        chain.doFilter(request, response)
    }
}
