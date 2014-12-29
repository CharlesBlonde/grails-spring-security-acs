package org.azure.acs

import groovy.json.JsonSlurper
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.jwt.Jwt
import grails.util.Holders
import org.springframework.security.jwt.JwtHelper

/**
 * User: charles
 * Date: 29/04/14
 * Time: 09:43
 * Author : cblonde@xebia.fr
 */
class AcsAuthenticationToken extends AbstractAuthenticationToken {
    String token

    Collection<GrantedAuthority> authorities
    Object principal

    private AcsAuthenticationToken() {
        super([] as Collection<GrantedAuthority>)
    }

    @Override
    Object getCredentials() {
        return getJwtToken().encoded
    }

    String getUserName() {
        Jwt jwtToken = getJwtToken()
        def usernames = Holders.config.grails.plugin.springsecurity.acs.claim.usernames
        def claims = new JsonSlurper().parseText(jwtToken.claims)

        String usernameClaim = usernames.find { claims[it] != null }
        if (usernameClaim) return claims[usernameClaim]

        throw new RuntimeException("Unable to find username in token in claims $claims")
    }

    String getFullName() {
        Jwt jwtToken = getJwtToken()
        def names = Holders.config.grails.plugin.springsecurity.acs.claim.names
        def jsonToken = new JsonSlurper().parseText(jwtToken.claims)

        String nameClaim = names.find { jsonToken[it] != null }
        if (nameClaim) return jsonToken[nameClaim]

        return getUserName()
    }

    Jwt getJwtToken(){
        JwtHelper.decode(token)
    }

    @Override
    Object getPrincipal() {
        return principal
    }


}
