package org.azure.acs

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException

/**
 * User: charles
 * Date: 28/04/14
 * Time: 16:26
 * Author : cblonde@xebia.fr
 */
class AcsUserDetailsService extends GormUserDetailsService {

    @Override
    UserDetails loadUserByUsername(String username, boolean loadRoles) throws UsernameNotFoundException {

        def conf = SpringSecurityUtils.securityConfig
        /*
        if (!conf.openid.userLookup.openIdsPropertyName) {
            return super.loadUserByUsername(username)
        }
        */

        String userDomainClassName = conf.userLookup.userDomainClassName
        String usernamePropertyName = conf.userLookup.usernamePropertyName

        Class<?> User = grailsApplication.getDomainClass(userDomainClassName).clazz

        User.withTransaction { status ->

            def user = User.findWhere((usernamePropertyName): username)

            if (!user) {
                String openIdDomainClassName = conf.openid.domainClass
                Class<?> OpenID = grailsApplication.getDomainClass(openIdDomainClassName).clazz
                user = OpenID.findByUrl(username)?.user
            }

            if (!user) {
                log.warn "User not found: $username"
                throw new UsernameNotFoundException('User not found', username)
            }

            Collection<GrantedAuthority> authorities = loadAuthorities(user, username, loadRoles)
            createUserDetails(user, authorities)
        }
    }
}
