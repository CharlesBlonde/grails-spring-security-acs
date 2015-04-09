package org.azure.acs

import com.google.common.base.Strings
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.StringUtils
import org.apache.log4j.Logger
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.jwt.Jwt
import org.springframework.security.jwt.JwtHelper
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
import org.springframework.security.web.util.RequestMatcher
import org.w3c.dom.Document
import org.xml.sax.SAXException

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.parsers.ParserConfigurationException

/**
 * User: charles
 * Date: 29/04/14
 * Time: 11:51
 * Author : cblonde@xebia.fr
 */
class AcsFilter extends AbstractAuthenticationProcessingFilter {

    private static def log = Logger.getLogger(this)

    String endPoint
    String realm
    String returnUrl

    public AcsFilter() {
        super("/j_spring_openid_security_check");
    }

    protected AcsFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    protected AcsFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        String wresult = httpServletRequest.getParameter("wresult");
        if (Strings.isNullOrEmpty(wresult)) {
            StringBuilder redirectURL = new StringBuilder(endPoint);
            redirectURL.append("?wa=wsignin1.0&wtrealm=");
            redirectURL.append(realm);
            redirectURL.append("&wctx=");
            redirectURL.append(this.getCompleteRequestURL(httpServletRequest));
            if (returnUrl) redirectURL.append("&wreply=$returnUrl");
            System.out.println("Redirecting to " + redirectURL.toString());

            httpServletResponse.sendRedirect(redirectURL.toString());
        } else {
            System.out.println(wresult);
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            try {
                DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
                Document doc = dBuilder.parse(new StringBufferInputStream(wresult));
                String base64Token = doc.getElementsByTagName("wsse:BinarySecurityToken").item(0).getTextContent();
                String token = StringUtils.newStringUtf8(Base64.decodeBase64(base64Token));
                Authentication securityToken = new AcsAuthenticationToken(token: token)
                Authentication auth = getAuthenticationManager().authenticate(securityToken)
                if (auth.authenticated) {
                    log.info "Successful authentication"
                    return auth
                } else {
                    new UsernameNotFoundException("Username not found")
                }
            } catch (ParserConfigurationException e) {
                e.printStackTrace();
                throw new RuntimeException("Unable to parse ACS Token");
            } catch (SAXException e) {
                e.printStackTrace();
                throw new RuntimeException("Unable to parse ACS Token");
            }

        }
        return null;
    }

    String getCompleteRequestURL(HttpServletRequest httpRequest) {
        StringBuffer completeRequestURL = httpRequest.getRequestURL();
        String queryString = httpRequest.getQueryString();
        if (queryString != null && !queryString.isEmpty()) {
            completeRequestURL.append('?').append(queryString);
        }

        String sslOffloadingProtocol = httpRequest.getHeader("X-FORWARDED-PROTO");

        if (sslOffloadingProtocol != null && sslOffloadingProtocol.equalsIgnoreCase("https")) {
            return completeRequestURL.toString().replace("http://", "https://");
        } else {
            return completeRequestURL.toString();
        }
    }
}
