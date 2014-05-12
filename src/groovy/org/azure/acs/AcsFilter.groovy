package org.azure.acs

import com.google.common.base.Strings
import org.apache.commons.codec.binary.Base64
import org.apache.commons.codec.binary.StringUtils
import org.apache.log4j.Logger
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
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
        System.out.println("constructor without argument");
    }

    protected AcsFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        System.out.println("constructor");
    }

    protected AcsFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
        System.out.println("constructor");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {
        System.out.println("Login:" + httpServletRequest.getParameterMap());
        String wresult = httpServletRequest.getParameter("wresult");
        if (Strings.isNullOrEmpty(wresult)) {
            //Must login
            // Using wctx parameter..

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
            DocumentBuilder dBuilder = null;
            try {
                dBuilder = dbFactory.newDocumentBuilder();
                Document doc = dBuilder.parse(new StringBufferInputStream(wresult));
                //System.out.println(doc.getChildNodes().item(0).ge);
                String base64Token = doc.getElementsByTagName("wsse:BinarySecurityToken").item(0).getTextContent();
                //TODO FIXME gros hack degeulasse !!!!
                //base64Token = "ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKU1V6STFOaUlzSW5nMWRDSTZJbkJUVTBZMlkwaG5YMkpPVTNBdFVEWjRUVEZWYTA1b00wVkpUU0o5LmV5SmhkV1FpT2lKb2RIUndPaTh2WVhwMWNtVnpaWEoyYVdObGN5OVVaVzVoYm5SVGFYUmxJaXdpYVhOeklqb2lhSFIwY0hNNkx5OWhlR0ZoWTNNdVlXTmpaWE56WTI5dWRISnZiQzUzYVc1a2IzZHpMbTVsZEM4aUxDSnVZbVlpT2pFek9UazJNVGt6T1RVc0ltVjRjQ0k2TVRNNU9UWTFOVE01TlN3aWFIUjBjRG92TDNOamFHVnRZWE11YldsamNtOXpiMlowTG1OdmJTOTNjeTh5TURBNEx6QTJMMmxrWlc1MGFYUjVMMk5zWVdsdGN5OWhkWFJvWlc1MGFXTmhkR2x2Ym1sdWMzUmhiblFpT2lJeU1ERTBMVEExTFRBNVZEQTNPakE1T2pVNUxqTXlNRm9pTENKb2RIUndPaTh2YzJOb1pXMWhjeTV0YVdOeWIzTnZablF1WTI5dEwzZHpMekl3TURndk1EWXZhV1JsYm5ScGRIa3ZZMnhoYVcxekwyRjFkR2hsYm5ScFkyRjBhVzl1YldWMGFHOWtJam9pYUhSMGNEb3ZMM05qYUdWdFlYTXViV2xqY205emIyWjBMbU52YlM5M2N5OHlNREE0THpBMkwybGtaVzUwYVhSNUwyRjFkR2hsYm5ScFkyRjBhVzl1YldWMGFHOWtMM2RwYm1SdmQzTWlMQ0pvZEhSd09pOHZjMk5vWlcxaGN5NTRiV3h6YjJGd0xtOXlaeTkzY3k4eU1EQTFMekExTDJsa1pXNTBhWFI1TDJOc1lXbHRjeTl1WVcxbElqb2lRVmhCTFVOTVQxVkVYRngzWVhCMWMyVnlJaXdpYUhSMGNEb3ZMM05qYUdWdFlYTXVlRzFzYzI5aGNDNXZjbWN2ZDNNdk1qQXdOUzh3TlM5cFpHVnVkR2wwZVM5amJHRnBiWE12ZFhCdUlqb2lkMkZ3ZFhObGNrQmhlR0V0WTJ4dmRXUXVZMjl0SWl3aWRYQnVJam9pUVZoQkxVTk1UMVZFWEZ4M1lYQjFjMlZ5SWl3aWFXUmxiblJwZEhsd2NtOTJhV1JsY2lJNkltaDBkSEE2THk5M1lYQmhaR1p6TG1GNFlTMWpiRzkxWkM1amIyMHZZV1JtY3k5elpYSjJhV05sY3k5MGNuVnpkQ0o5LmJid2pRRnZTV3dQMTJRbWloMVRVSDlETVRoWFV5aDEwNG9Bbk9zMzJ0amp5ZTZpUUVQbGFJTkJsTVNGLWJTVWdnYXcwSVNGaEN3MVBxcjlYWHhndkhieWY2UXdERmFrU3kzVVNXQ2dxWE94WjQwNEx6bVZlb3l2RkVqMDFPY21ncU9CM2s4V0FKMGwyWTdXeERabUhhcG5LSEwtZGVkU0dzUnhESUFvLUpSMS1yeDZTMU5RRDV6MnBfVC11YThZN2h0cWpTZjR0c3ROOF9EQk9GV0xuaGRIcnJkUTRCSmM5eGQzVXNtamVoUHU0R3BqSHoxRWdDSEczaVoyRGVNcVppamVjaENSMHY4Tmh1Nkdsal9KVUF5bDVTdElUNm5sQTM4ZGEzazNFWkgzUFBHVjFxOVRZRGl2b0pyQ1V4M3ZkWG1lVDhyb0dfUVo1elNaa2tId3R6dw=="
                String token = StringUtils.newStringUtf8(Base64.decodeBase64(base64Token));
                Jwt jwtToken = JwtHelper.decode(token);
                Authentication securityToken = new AcsAuthenticationToken(jwtToken: jwtToken)
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
        //System.out.println("attemptAuthentication");
        //System.out.println("attemptAuthentication2");
        return null;  //To change body of implemented methods use File | Settings | File Templates.
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
