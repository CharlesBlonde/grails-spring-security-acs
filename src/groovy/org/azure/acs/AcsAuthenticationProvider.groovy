package org.azure.acs

import grails.plugin.springsecurity.userdetails.GrailsUserDetailsService
import groovy.util.logging.Log
import org.azure.acs.exceptions.ExpiredTokenException
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.jwt.crypto.sign.RsaKeyHelper
import org.springframework.security.jwt.crypto.sign.RsaVerifier

import java.security.interfaces.RSAPublicKey

/**
 * User: charles
 * Date: 29/04/14
 * Time: 14:16
 * Author : cblonde@xebia.fr
 */
@Log
class AcsAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    GrailsApplication grailsApplication
    GrailsUserDetailsService coreUserDetailsService

    Boolean autoCreate

    String[] defaultAuthorities

    String appUserClassName
    String authorityClassName
    String authorityJoinClassName

    boolean verifySignature
    String pubKey

    Class AppUser
    Class Authority
    Class UserAuthority

    @Override
    Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("Authenticate $authentication");
        AcsAuthenticationToken acsToken = (AcsAuthenticationToken) authentication

        if (verifySignature) {
            log.fine("Signature verification is enabled")

            def keyPair = RsaKeyHelper.parseKeyPair(pubKey)
            //will throw an exception if Signature is not valid
            acsToken.jwtToken.verifySignature(new RsaVerifier((RSAPublicKey) keyPair.public))
            if (acsToken.isExpired()) {
                throw new ExpiredTokenException("Token expired at ${acsToken.getExpirationDate()} (now: ${new Date()})")
            }
        }

        authentication.authenticated = true
        def user = AppUser.findWhere(username: authentication.getUserName())
        if (!user) {
            log.info("User ${authentication.getUserName()} doesn't exist")
            if (autoCreate) {
                log.info("Creating user ${authentication.getUserName()}")
                def newUser = grailsApplication.getDomainClass(appUserClassName).newInstance()
                newUser.username = authentication.getUserName()
                newUser.password = "fakepassword"
                newUser.fullName = authentication.getFullName()
                println AppUser
                AppUser.withTransaction {
                    newUser.save(flush: true)
                }

                defaultAuthorities.each {
                    println(it)
                    println(Authority)
                    def authority = Authority.findWhere(authority: it)
                    def authorityJoin = grailsApplication.getDomainClass(authorityJoinClassName).newInstance()
                    authorityJoin.user = newUser
                    authorityJoin.role = authority

                    UserAuthority.withTransaction {
                        authorityJoin.save(flush: true)
                    }
                }

                user = newUser
            } else {
                throw new UsernameNotFoundException("User ${authentication.getUserName()} doesn't exist")
            }
        } else {
            //Update user if needed
            AppUser.withTransaction {
                user = AppUser.findWhere(username: authentication.getUserName())
                user.fullName = authentication.getFullName()
                user.merge()
                user.save(flush: true)
            }
        }

        authentication.principal = coreUserDetailsService.loadUserByUsername(user.username, true)
        authentication.authorities = authentication.principal.getAuthorities()

        return authentication;
    }

    @Override
    boolean supports(Class<?> authentication) {
        return AcsAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Override
    void afterPropertiesSet() throws Exception {
        //TODO refactor
        if (AppUser == null) {
            if (appUserClassName && appUserClassName.length() > 0) {
                AppUser = grailsApplication.getDomainClass(appUserClassName)?.clazz
            }
            if (!AppUser) {
                log.severe("Can't find domain: $appUserClassName")
            }
        }

        if (Authority == null) {
            if (authorityClassName && authorityClassName.length() > 0) {
                Authority = grailsApplication.getDomainClass(authorityClassName)?.clazz
            }
            if (!Authority) {
                log.severe("Can't find domain: $authorityClassName")
            }
        }


        if (authorityJoinClassName && authorityJoinClassName.length() > 0) {
            UserAuthority = grailsApplication.getDomainClass(authorityJoinClassName)?.clazz
        }
        if (!UserAuthority) {
            log.severe("Can't find domain: $authorityJoinClassName")
        }

    }
}
