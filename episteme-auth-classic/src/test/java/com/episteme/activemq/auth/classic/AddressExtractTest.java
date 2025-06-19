package com.episteme.activemq.auth.classic;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.URISyntaxException;

import org.episteme.activemq.auth.classic.AddressExtractor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class AddressExtractTest {

	@Test
	@DisplayName("Should extract IPv4 addresses correctly")
	void shouldExtractIPv4Addresses() throws URISyntaxException {
		// Given
		URI uri = new URI("tcp://192.168.1.1:61616");

		// When
		String host = AddressExtractor.getHost(uri);

		// Then
		assertEquals("192.168.1.1", host);
	}
	
	@Test
	@DisplayName("Should extract IPv6 special addresses correctly")
	void shouldExtractIPv6Addresses() throws URISyntaxException {
		// Given
		URI uri = new URI("tcp://0:0:0:0:0:0:0:1:64040");

		// When
		String host = AddressExtractor.getHost(uri);

		// Then
		assertEquals("[0:0:0:0:0:0:0:1]", host);
	}
	
	
	@ParameterizedTest
    @DisplayName("Should extract various IPv4 addresses")
    @CsvSource({
        "tcp://10.0.0.1:8080, 10.0.0.1",
        "tcp://[2001:db8::1]:61616, [2001:db8::1]",
        "http://127.0.0.1:80, 127.0.0.1",
        "mqtt://172.16.0.100:1883, 172.16.0.100",
        "ssl://255.255.255.255:443, 255.255.255.255",
        "tcp://0.0.0.0:61616, 0.0.0.0",
         "ws://[fd00:1234:abcd::1]:9000/socket,[fd00:1234:abcd::1]"
    })
    void shouldExtractVariousIPv4Addresses(String uriString, String expectedHost) throws URISyntaxException {
        // Given
        URI uri = new URI(uriString);
        
        // When
        String host = AddressExtractor.getHost(uri);
        
        // Then
        assertEquals(expectedHost, host);
    }	
	
}
