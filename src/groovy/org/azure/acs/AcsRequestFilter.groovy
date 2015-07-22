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
import javax.servlet.http.HttpServletResponse

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
        if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
            HttpServletRequest httpServletRequest = (HttpServletRequest) request
            HttpServletResponse httpServletResponse = (HttpServletResponse) response
            String authorizationHeader = httpServletRequest.getHeader("Authorization")
            try {
                if (!Strings.isNullOrEmpty(authorizationHeader)) {
                    JwtHelper.decode(authorizationHeader)
                    def acsAuthenticationToken = new AcsAuthenticationToken(token: authorizationHeader)
                    SecurityContextHolder.context.setAuthentication(acsAuthenticationToken)
                }
                chain.doFilter(request, response)
            } catch (Exception e) {
                logger.error("Unable to decode JWT token:" + e.message)
                httpServletResponse.setStatus(403)
            }

        } else {
            chain.doFilter(request, response)
        }
    }
}
