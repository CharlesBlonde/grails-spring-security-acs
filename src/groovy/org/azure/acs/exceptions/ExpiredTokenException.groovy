package org.azure.acs.exceptions

import org.springframework.security.core.AuthenticationException

/**
 * User: charles
 * Date: 09/04/15
 * Time: 11:57
 * Author : charles.blonde@gmail.com
 */
class ExpiredTokenException extends AuthenticationException{
    ExpiredTokenException(String msg) {
        super(msg)
    }
}
