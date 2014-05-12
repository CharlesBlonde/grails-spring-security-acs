package org.azure.acs

import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.plugin.springsecurity.userdetails.GrailsUserDetailsService
import groovy.util.logging.Log
import groovy.util.logging.Log4j
import org.apache.log4j.Logger
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.UsernameNotFoundException

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

    Class AppUser
    Class Authority
    Class UserAuthority

    @Override
    Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("Authenticate $authentication");
        //TODO check signature !!!

        authentication.authenticated = true
        def user = AppUser.findWhere(username: authentication.getUserName())
        if (!user) {
            log.info("User ${authentication.getUserName()} doesn't exist")
            if (autoCreate) {
                //TODO use only one transaction !
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
        //authentication.authorities = user.roles.collect{ new SimpleGrantedAuthority(it)}
        //authentication.authorities = [new SimpleGrantedAuthority("ROLE_USER")]
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
