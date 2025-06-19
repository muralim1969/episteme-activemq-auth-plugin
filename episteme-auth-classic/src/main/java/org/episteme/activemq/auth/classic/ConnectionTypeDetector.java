package org.episteme.activemq.auth.classic;

import java.net.URI;
import java.util.Arrays;
import java.util.*;
import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.broker.TransportConnector;

public class ConnectionTypeDetector {

	
	static public ConnectionType getConnectionType(ConnectionContext context) {
        return Optional.ofNullable(context)
                .map(ConnectionContext::getConnector)
                .filter(TransportConnector.class::isInstance)
                .map(TransportConnector.class::cast)
                .map(TransportConnector::getUri)
                .map(ConnectionTypeDetector::determineConnectionTypeFromUri)
                .orElse(ConnectionType.UNKNOWN);
    }
	
	 /**
     * Determines connection type from URI.
     * 
     * @param uri the connection URI
     * @return the connection type based on scheme and parameters
     */
    static private ConnectionType determineConnectionTypeFromUri(URI uri) {
        if (uri == null) {
            return ConnectionType.UNKNOWN;
        }
        
        String scheme = uri.getScheme();
        if (scheme == null) {
            return ConnectionType.UNKNOWN;
        }
        
        String normalizedScheme = scheme.toLowerCase().trim();
        boolean needsClientAuth = hasClientAuthentication(uri);
        
        return switch (normalizedScheme) {
            case "ws" -> ConnectionType.WS;
            case "wss" -> needsClientAuth ? ConnectionType.WSS_CERTAUTH : ConnectionType.WSS;
            case "ssl" -> needsClientAuth ? ConnectionType.SSL_CERTAUTH : ConnectionType.SSL;
            case "tcp" -> ConnectionType.TCP;
            case "vm" -> ConnectionType.VM;
            case "nio" -> ConnectionType.NIO;
            case "http" -> ConnectionType.HTTP;
            case "https" -> needsClientAuth ? ConnectionType.HTTPS_CERTAUTH : ConnectionType.HTTPS;
            case "mqtt" -> ConnectionType.MQTT;
            case "mqtts" -> needsClientAuth ? ConnectionType.MQTTS_CERTAUTH : ConnectionType.MQTTS;
            default -> ConnectionType.UNKNOWN;
        };
    }
    static private boolean hasClientAuthentication(URI uri) {
        if (uri == null) {
            return false;
        }
        
        String query = uri.getQuery();
        if (query == null || query.trim().isEmpty()) {
            return false;
        }
        
        // Parse query parameters more robustly
        return Arrays.stream(query.split("&"))
                .map(String::trim)
                .anyMatch(param -> param.equals("needClientAuth=true"));
    }
}
