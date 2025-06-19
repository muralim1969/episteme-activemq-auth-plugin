package org.episteme.activemq.auth.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

import org.episteme.activemq.auth.core.AuthConfigLoader.CertConfig;
import org.episteme.activemq.auth.core.AuthConfigLoader.IpAclConfig;
import org.episteme.activemq.auth.core.AuthConfigLoader.JwtConfig;
import org.episteme.activemq.auth.core.AuthConfigLoader.JwtIdpConfig;
import org.episteme.activemq.auth.core.AuthConfigLoader.PipelinesConfig;
import org.episteme.activemq.auth.core.AuthConfigLoader.RootConfig;
import org.episteme.activemq.auth.core.utils.IpAclEntry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class AuthConfigLoaderTest {

	private AuthConfigLoader configLoader;

	void setup(String testFile) throws IOException {

		configLoader = new AuthConfigLoader(testFile);
	}

	@Test
	@DisplayName("Should load valid complete configuration successfully")
	void shouldLoadValidCompleteConfiguration() throws IOException {
		// Given
		setup("src/test/resources/valid-complete-config.json");

		// Then
		RootConfig config = configLoader.getConfig();
		assertNotNull(config);

		// Verify IP ACL
		Optional<IpAclConfig> ipAcl = configLoader.getIpAclConfig();
		assertTrue(ipAcl.isPresent());
		assertEquals(3, ipAcl.get().allow.size());

		List<IpAclEntry> allowList = configLoader.getIpAclAllowList();
		assertEquals(3, allowList.size());

		// Verify Certificate config
		Optional<CertConfig> cert = configLoader.getCertConfig();
		assertTrue(cert.isPresent());
		assertEquals(4, cert.get().allowedThumbprints.size());

		List<String> thumbprints = configLoader.getAllowedThumbprints();
		assertEquals(4, thumbprints.size());

		// Verify JWT config
		Optional<JwtConfig> jwt = configLoader.getJwtConfig();
		assertTrue(jwt.isPresent());
		assertEquals(2, jwt.get().idps.size());

		JwtIdpConfig googleConfig = jwt.get().idps.get("https://accounts.google.com");
		assertNotNull(googleConfig);
		assertEquals("https://accounts.google.com", googleConfig.issuer);
		assertArrayEquals(new String[] { "my-app-client-id" }, googleConfig.audience);

		// Verify Pipelines config
		Optional<PipelinesConfig> pipelines = configLoader.getPipelinesConfig();
		assertTrue(pipelines.isPresent());
		assertEquals(3, pipelines.get().pipelines.size());

		List<String> ipCertJwtPipeline = pipelines.get().pipelines.get("connector-ip-cert-jwt");
		assertEquals(3, ipCertJwtPipeline.size());
		assertEquals("ip-acl-validator", ipCertJwtPipeline.get(0));
		assertEquals("client-cert-validator", ipCertJwtPipeline.get(1));
		assertEquals("jwt-validator", ipCertJwtPipeline.get(2));
	}

	@Test
	@DisplayName("Should handle empty configuration gracefully")
	void shouldHandleEmptyConfiguration() throws IOException {
		// Given
		setup("src/test/resources/empty-config.json");

		RootConfig config = configLoader.getConfig();
		assertNotNull(config);
		assertNull(config.ipAcl);
		assertNull(config.cert);
		assertNull(config.jwt);
		assertNull(config.pipelines);

		assertTrue(configLoader.getIpAclConfig().isEmpty());
		assertTrue(configLoader.getCertConfig().isEmpty());
		assertTrue(configLoader.getJwtConfig().isEmpty());
		assertTrue(configLoader.getPipelinesConfig().isEmpty());

		assertTrue(configLoader.getIpAclAllowList().isEmpty());
		assertTrue(configLoader.getAllowedThumbprints().isEmpty());
	}

	@Test
	@DisplayName("Should load minimal configuration with only one auth method")
	void shouldLoadMinimalConfiguration() throws IOException {
		// Given
		setup("src/test/resources/minimal-config.json");
		// Then
		assertTrue(configLoader.getIpAclConfig().isEmpty());
		assertTrue(configLoader.getCertConfig().isPresent());
		assertTrue(configLoader.getJwtConfig().isEmpty());
		assertTrue(configLoader.getPipelinesConfig().isEmpty());
		assertTrue(configLoader.getIpAclAllowList().isEmpty());
		assertEquals(1, configLoader.getAllowedThumbprints().size());
	}

	@Test
	@DisplayName("Should normalize certificate thumbprints correctly")
	void shouldNormalizeCertificateThumbprints() throws IOException {
		setup("src/test/resources/thumbprint-formats-config.json");
		List<String> thumbprints = configLoader.getAllowedThumbprints();
		assertEquals(3, thumbprints.size());
		// All should be normalized to uppercase without spaces
		assertTrue(thumbprints.contains("6FAD238812BBAC45E39066D275F792D5D9E3FA44"));
		// 6fad238812bbac45e39066d275f792d5d9e3fa44
		assertTrue(thumbprints.contains("AABBCCDDEEFF001122334455667788990AABBCCD"));
	}

	@Test
	@DisplayName("Should skip invalid IP ACL entries but keep valid ones")
	void shouldSkipInvalidIpAclEntries() throws IOException {
		// Given
		setup("src/test/resources/invalid-ip-config.json");
		// Then
		List<IpAclEntry> allowList = configLoader.getIpAclAllowList();
		assertEquals(2, allowList.size()); // Only valid entries should be kept

	}

	@Test
	@DisplayName("Should skip invalid certificate thumbprints")
	void shouldSkipInvalidCertificateThumbprints() throws IOException {
		// Given
		setup("src/test/resources/invalid-thumbprints-config.json");
		// Then
		List<String> thumbprints = configLoader.getAllowedThumbprints();
		assertEquals(2, thumbprints.size()); // Only valid thumbprints should be kept
	}

	@Test
	@DisplayName("Should skip invalid JWT IDP configurations")
	void shouldSkipInvalidJwtIdpConfigurations() throws IOException {
		// Given
		setup("src/test/resources/invalid-jwt-config.json");
		// Then
		Optional<JwtConfig> jwtConfig = configLoader.getJwtConfig();
		assertTrue(jwtConfig.isPresent());
		assertEquals(1, jwtConfig.get().idps.size()); // Only valid IDP should be kept
		assertTrue(jwtConfig.get().idps.containsKey("https://accounts.google.com"));
	}

	@Test
	@DisplayName("Should throw exception for non-existent config file")
	void shouldThrowExceptionForNonExistentFile() {

		@SuppressWarnings("resource")
		IOException exception = assertThrows(IOException.class, () -> {
			new AuthConfigLoader("src/test/resources/invalid-jwt-config.json1");
		});

		assertTrue(exception.getMessage().contains("Configuration file does not exist"));
	}

}
