package org.episteme.activemq.auth.core;

import java.security.cert.X509Certificate;
import java.util.Optional;

public interface AuthRequestContext {
    String getRemoteAddress();
    Optional<X509Certificate[]> getClientCertificates();
    Optional<String> getJwtToken();
    String getUsername();
    Optional<String> getPassword();
    Optional<String> getHeader(String key);  // e.g., STOMP/WebSocket headers
    void setClientCertificates(X509Certificate[] clientCertificates);    
}