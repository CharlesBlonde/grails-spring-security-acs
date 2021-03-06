security {
    acs {
        endPoint = ""
        realm = ""
        returnUrl = ""
        authUrl = "/auth"
        autoCreate = true
        defaultAuthorities = []
        claim {
            usernames = ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
                    "upn",
                    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"]
            names = ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"]
            firstNames = ["givenname"]
            lastNames = ["surname"]
            emails = ["emailaddress"]
        }
        verifySignature = true
        pubKey = ""
    }
}