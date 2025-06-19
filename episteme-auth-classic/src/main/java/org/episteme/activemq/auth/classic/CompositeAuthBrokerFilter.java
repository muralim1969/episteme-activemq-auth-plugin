package org.episteme.activemq.auth.classic;

import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerFilter;
import org.apache.activemq.broker.ConnectionContext;
import org.apache.activemq.broker.TransportConnector;
import org.apache.activemq.command.ConnectionInfo;
import org.apache.activemq.security.SecurityContext;
import org.episteme.activemq.auth.core.AuthException;
import org.episteme.activemq.auth.core.AuthPipeline;
import org.episteme.activemq.auth.core.AuthRequestContext;
import org.episteme.activemq.auth.core.AuthenticatedUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public class CompositeAuthBrokerFilter extends BrokerFilter {

	private static final Logger log = LoggerFactory.getLogger(CompositeAuthBrokerFilter.class);
	private final Map<String, AuthPipeline> pipelines;
	
	public CompositeAuthBrokerFilter(Broker next, Map<String, AuthPipeline> pipelines) {
		super(next);
		this.pipelines = pipelines;
	}

	@Override
	public void addConnection(ConnectionContext context, ConnectionInfo connectionInfo) throws Exception {
		log.info("Adding connection from IP address " + context.getConnection().getRemoteAddress());

		SecurityContext securityContext = context.getSecurityContext();
		if (securityContext == null) {
			try {
				AuthenticatedUser user = processAuthentication(context, connectionInfo);
				if (user != null) {
					securityContext = new SecurityContext(connectionInfo.getUserName()) {
						@Override
						public Set<Principal> getPrincipals() {
							return Collections.emptySet();
						}
					};
					context.setSecurityContext(securityContext);
				}
				super.addConnection(context, connectionInfo);
				log.info(String.format("Added connection from IP address %s ",context.getConnection().getRemoteAddress()));
			} catch (Exception error) {
				context.setSecurityContext(null);
				log.error("Authenitcation failed: " + error);
				throw new SecurityException(error.getMessage());
			}
		} else
			super.addConnection(context, connectionInfo);
	}

	public static String getStackTrace(Exception e) {
		StringWriter sWriter = new StringWriter();
		PrintWriter pWriter = new PrintWriter(sWriter);
		e.printStackTrace(pWriter);
		return sWriter.toString();
	}

	private AuthenticatedUser processAuthentication(ConnectionContext context, ConnectionInfo connectionInfo)
			throws URISyntaxException, AuthException {
		ConnectionType connectionType = ConnectionTypeDetector.getConnectionType(context);

		if (connectionType == ConnectionType.VM) {
			AuthenticatedUser user = new AuthenticatedUser("internalvm");
			return user;
		}
		if (connectionType == ConnectionType.UNKNOWN) {
			// Throw an exception
			throw new AuthException(ConnectionType.UNKNOWN.getDescription());
		}
		TransportConnector connector = (TransportConnector) context.getConnector();
		String connectorName = connector.getName();
		AuthPipeline pipeline = pipelines.get(connectorName);

		if (pipeline == null) {
			throw new SecurityException("No authentication pipeline configured for connector: " + connectorName);
		}

		AuthRequestContext requestContext = new BrokerAuthRequestContext(context, connectionInfo);
		AuthenticatedUser user = pipeline.validate(requestContext);
		return user;
	}

}