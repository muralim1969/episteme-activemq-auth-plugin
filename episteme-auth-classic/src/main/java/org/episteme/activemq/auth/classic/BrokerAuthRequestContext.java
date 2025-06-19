package org.episteme.activemq.auth.classic;

import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.command.ConnectionInfo;
import org.episteme.activemq.auth.core.AuthRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.*;

public class BrokerAuthRequestContext implements AuthRequestContext {

	private static final Logger log = LoggerFactory.getLogger(BrokerAuthRequestContext.class);
	
    private String remoteAddress;
    private Optional<X509Certificate[]> clientCertificates;
    private String username;
    private final Optional<String> password;
    private final Map<String, String> headers;

    public BrokerAuthRequestContext(ConnectionContext context, ConnectionInfo info) throws URISyntaxException {
      
        if (info.getTransportContext() instanceof X509Certificate[])
            this.clientCertificates = Optional.ofNullable((X509Certificate[]) info.getTransportContext());
        else
        	this.clientCertificates=null;

        this.username = info.getUserName().trim();     
        if (username.isEmpty()) {
            username = "service";
        }
        this.password = Optional.ofNullable(info.getPassword());

        this.headers = new HashMap<>(); // STOMP/WebSocket headers not available here by default
        setRemoteAddress(context.getConnection().getRemoteAddress());
    }

    private void setRemoteAddress(String remoteAddress) throws URISyntaxException
    {
    	URI uri = new URI(remoteAddress);
    	this.remoteAddress=AddressExtractor.getHost(uri);
    	log.info("Remoteaddress:"+remoteAddress);
    }

    @Override
    public String getRemoteAddress() {
        return remoteAddress;
    }

    @Override
    public Optional<X509Certificate[]> getClientCertificates() {
        return clientCertificates;
    }

    @Override
    public Optional<String> getJwtToken() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public Optional<String> getPassword() {
        return password;
    }

    @Override
    public Optional<String> getHeader(String key) {
        return Optional.ofNullable(headers.get(key));
    }


	@Override
	public void setClientCertificates(X509Certificate[] clientCertificates) {
		
		this.clientCertificates=Optional.ofNullable(clientCertificates);
	}
}