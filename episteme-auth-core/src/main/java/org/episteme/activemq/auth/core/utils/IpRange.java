package org.episteme.activemq.auth.core.utils;

import java.net.InetAddress;

public class IpRange {
    private final byte[] base;
    private final int prefixLength;

    public static IpRange parse(String cidr) {
        try {
            String[] parts = cidr.split("/");
            InetAddress base = InetAddress.getByName(parts[0]);
            int prefix = parts.length > 1 ? Integer.parseInt(parts[1]) : (base.getAddress().length * 8);
            return new IpRange(base.getAddress(), prefix);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr, e);
        }
    }

    private IpRange(byte[] base, int prefixLength) {
        this.base = base;
        this.prefixLength = prefixLength;
    }

    public boolean contains(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length != base.length) return false;

        int fullBytes = prefixLength / 8;
        int remainderBits = prefixLength % 8;

        for (int i = 0; i < fullBytes; i++) {
            if (addr[i] != base[i]) return false;
        }

        if (remainderBits > 0) {
            int mask = ~((1 << (8 - remainderBits)) - 1);
            if ((addr[fullBytes] & mask) != (base[fullBytes] & mask)) return false;
        }

        return true;
    }
}