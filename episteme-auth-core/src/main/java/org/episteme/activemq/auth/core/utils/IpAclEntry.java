package org.episteme.activemq.auth.core.utils;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;

public class IpAclEntry {
    private final byte[] address;
    private final byte[] mask;

    private IpAclEntry(byte[] address, byte[] mask) {
        this.address = address;
        this.mask = mask;
    }

    public static IpAclEntry parse(String cidr) {
        String[] parts = cidr.split("/");
        
        try {
            InetAddress inetAddress = InetAddress.getByName(parts[0]);
            
            int prefixLength;
            if (parts.length == 1) {
                // No prefix specified - treat as single host
                prefixLength = inetAddress.getAddress().length * 8; // /32 for IPv4, /128 for IPv6
            } else if (parts.length == 2) {
                // CIDR notation
                prefixLength = Integer.parseInt(parts[1]);
            } else {
                throw new IllegalArgumentException("Invalid CIDR format: " + cidr);
            }
            
            byte[] rawAddress = inetAddress.getAddress();
            byte[] mask = new byte[rawAddress.length];
            
            for (int i = 0; i < prefixLength; i++) {
                mask[i / 8] |= 1 << (7 - (i % 8));
            }
            
            byte[] maskedAddress = new byte[rawAddress.length];
            for (int i = 0; i < rawAddress.length; i++) {
                maskedAddress[i] = (byte) (rawAddress[i] & mask[i]);
            }
            
            return new IpAclEntry(maskedAddress, mask);
        } catch (UnknownHostException | NumberFormatException e) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr, e);
        }
    }
    
    
    public boolean contains(String ip) {
        try {
            byte[] other = InetAddress.getByName(ip).getAddress();
            if (other.length != address.length) return false;

            for (int i = 0; i < address.length; i++) {
                if ((other[i] & mask[i]) != address[i]) {
                    return false;
                }
            }

            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof IpAclEntry)) return false;
        IpAclEntry other = (IpAclEntry) o;
        return Objects.deepEquals(this.address, other.address)
            && Objects.deepEquals(this.mask, other.mask);
    }

    @Override
    public int hashCode() {
        return Objects.hash(address, mask);
    }
}