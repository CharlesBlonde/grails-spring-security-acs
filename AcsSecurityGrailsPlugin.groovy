import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition
import org.azure.acs.AcsAuthenticationProvider
import org.azure.acs.AcsFilter
import org.azure.acs.AcsRequestFilter

class AcsSecurityGrailsPlugin {
    // the plugin version
    def version = "0.7-SNAPSHOT"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.3 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
            "grails-app/views/error.gsp"
    ]
    List loadAfter = ['springSecurityCore']

    // TODO Fill in these fields
    def title = "Acs Security Plugin" // Headline display name of the plugin
    def author = "Charles Blonde"
    def authorEmail = "charles.blonde@gmail.com"
    def description = '''\
Microsoft ACS Authentication
'''

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/acs-security"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
//    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

    // Any additional developers beyond the author specified above.
//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

    // Location of the plugin's issue tracker.
//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

    // Online location of the plugin's browseable source code.
//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

    def doWithWebDescriptor = { xml ->
        // TODO Implement additions to web.xml (optional), this event occurs before
    }

    def doWithSpring = {
        def conf = SpringSecurityUtils.securityConfig

        if (!conf || !conf.active) {
            return
        }

        SpringSecurityUtils.loadSecondaryConfig 'DefaultAcsSecurityConfig'

        conf = SpringSecurityUtils.securityConfig


        boolean printStatusMessages = (conf.printStatusMessages instanceof Boolean) ? conf.printStatusMessages : true

        if (printStatusMessages) {
            println '\nConfiguring Spring Security ACS ...'
        }

        SpringSecurityUtils.registerProvider 'acsAuthenticationProvider'
        SpringSecurityUtils.registerFilter 'acsRequestFilter', SecurityFilterPosition.OPENID_FILTER.order - 1
        SpringSecurityUtils.registerFilter 'acsFilter', SecurityFilterPosition.OPENID_FILTER

        acsAuthenticationProvider(AcsAuthenticationProvider) {
            appUserClassName = conf.userLookup.userDomainClassName
            authorityClassName = conf.authority.className
            authorityJoinClassName = conf.userLookup.authorityJoinClassName
            grailsApplication = ref('grailsApplication')
            coreUserDetailsService = ref('userDetailsService')
            autoCreate = conf.acs.autoCreate
            defaultAuthorities = conf.acs.defaultAuthorities
            verifySignature = conf.acs.verifySignature
            pubKey = conf.acs.pubKey
            //userDetailsService = ref('userDetailsService')
        }

        acsRequestFilter(AcsRequestFilter){

        }

        acsFilter(AcsFilter) {
            //claimedIdentityFieldName = conf.openid.claimedIdentityFieldName // openid_identifier
            //consumer = ref('openIDConsumer')
            endPoint = conf.acs?.endPoint
            realm = conf.acs?.realm
            returnUrl = conf.acs?.returnUrl
            rememberMeServices = ref('rememberMeServices')
            authenticationManager = ref('authenticationManager')
            authenticationSuccessHandler = ref('authenticationSuccessHandler')
            authenticationFailureHandler = ref('authenticationFailureHandler')
            authenticationDetailsSource = ref('authenticationDetailsSource')
            sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
            filterProcessesUrl = conf.acs.authUrl
            //requiresAuthenticationRequestMatcher = new AnyRequestMatcher()
        }

        /*
        authenticationFailureHandler(AcsAuthenticationFailureHandler){
            redirectStrategy = ref('redirectStrategy')
            defaultFailureUrl = conf.failureHandler.defaultFailureUrl //'/login/authfail?login_error=1'
            useForward = conf.failureHandler.useForward // false
            ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
            exceptionMappings = conf.failureHandler.exceptionMappings // [:]
        }
        */

                /*
        authenticationFailureHandler(OpenIdAuthenticationFailureHandler) {
            redirectStrategy = ref('redirectStrategy')
            defaultFailureUrl = conf.failureHandler.defaultFailureUrl //'/login/authfail?login_error=1'
            useForward = conf.failureHandler.useForward // false
            ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
            exceptionMappings = conf.failureHandler.exceptionMappings // [:]
        }
        */

        // custom subclass that searches by username and openIds

        /*
        userDetailsService(AcsUserDetailsService) {
            grailsApplication = ref('grailsApplication')
        }
        */

        /*
        if (!conf.rememberMe.persistent) {
            // auth is external, so no password, so regular cookie isn't possible
            rememberMeServices(NullLogoutHandlerRememberMeServices)
        }
        */

        if (printStatusMessages) {
            println '... finished configuring Spring Security ACS\n'
        }
    }

    def doWithDynamicMethods = { ctx ->
        // TODO Implement registering dynamic methods to classes (optional)
    }

    def doWithApplicationContext = { ctx ->
        // TODO Implement post initialization spring config (optional)
    }

    def onChange = { event ->
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    def onConfigChange = { event ->
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    def onShutdown = { event ->
        // TODO Implement code that is executed when the application shuts down (optional)
    }
}
