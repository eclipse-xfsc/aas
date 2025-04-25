package eu.xfsc.aas.model;

public interface SsiAuthErrorCodes {
    
    static String LOGIN_REJECTED = "login_rejected";
    static String LOGIN_TIMED_OUT = "login_timed_out";

    // also see org.springframework.security.oauth2.core.OAuth2ErrorCodes
}
