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
        return getField(Holders.config.grails.plugin.springsecurity.acs.claim.names)
    }

    String getField(List<String> fieldNames) {
        Jwt jwtToken = getJwtToken()
        //def names = Holders.config.grails.plugin.springsecurity.acs.claim.names
        def jsonToken = new JsonSlurper().parseText(jwtToken.claims)

        String claim = fieldNames.find {jsonToken[it] != null}
        if(claim) return jsonToken[claim]

        return getUserName()
    }

    String getFirstName() {
        return getField(Holders.config.grails.plugin.springsecurity.acs.claim.firstNames)
    }

    String getLastName() {
        return getField(Holders.config.grails.plugin.springsecurity.acs.claim.lastNames)
    }

    String getEmail() {
        return getField(Holders.config.grails.plugin.springsecurity.acs.claim.emails)
    }

    Jwt getJwtToken(){
        JwtHelper.decode(token)
    }

    Date getExpirationDate() {
        long expirationDateSeconds = new JsonSlurper().parseText(JwtHelper.decode(token).claims).exp
        if (expirationDateSeconds) {
            return new Date(expirationDateSeconds * 1000)
        } else {
            return null
        }
    }

    boolean isExpired() {
        def expirationDate = getExpirationDate()
        if (expirationDate) {
            return new Date().after(expirationDate)
        } else {
            return false
        }
    }

    @Override
    Object getPrincipal() {
        return principal
    }


}
