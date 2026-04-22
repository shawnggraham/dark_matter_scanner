package dark_matter_scanner;

// ========================================
// BLOCK 1 — DEVICE HEURISTICS
// ========================================
public class DeviceHeuristics {

    // ========================================
    // BLOCK 2 — INFRA ROLE CLASSIFIER
    // ========================================
    public static String classifyInfrastructureRole(String vendor, String mac, String ip, String responseType) {
        String v = vendor != null ? vendor.toLowerCase() : "";
        String m = mac != null ? mac.toUpperCase() : "";
        String rt = responseType != null ? responseType.toLowerCase() : "";
        String normalizedIp = ip != null ? ip.trim() : "";

        boolean gatewayLikeIp = isGatewayLikeIp(normalizedIp);
        boolean localAdminMac = isLocallyAdministeredMac(m);

        boolean routerVendor = containsAny(v,
                "cisco",
                "ubiquiti",
                "mikrotik",
                "juniper",
                "fortinet",
                "netgate",
                "pfsense",
                "opnsense",
                "vyos",
                "palo alto",
                "arista"
        );

        boolean switchVendor = containsAny(v,
                "hpe",
                "hewlett packard enterprise",
                "aruba",
                "extreme",
                "ruckus",
                "dell",
                "netgear",
                "tp-link",
                "d-link",
                "allied telesis"
        );

        if (routerVendor && gatewayLikeIp) return "Likely Router (high)";
        if (routerVendor) return "Likely Router";
        if (switchVendor && !gatewayLikeIp) return "Likely Managed Switch";
        if (localAdminMac && gatewayLikeIp) return "Likely Virtual Router/Firewall";
        if (containsAny(rt, "router", "gateway")) return "Likely Router";
        return "Unknown / Endpoint";
    }

    // ========================================
    // BLOCK 3 — DARK DEVICE BEHAVIOR CLASSIFIER
    // ========================================
    public static String[] classifyDarkDeviceBehavior(
            String sampleIp,
            String candidateMac,
            String vendor,
            int seenCount,
            String protocolList,
            String noteList,
            String nmapStatus,
            String serviceHint,
            String infraSignals
    ) {
        String mac = candidateMac != null ? candidateMac.trim().toUpperCase() : "";
        String notes = noteList != null ? noteList.toLowerCase() : "";
        String protocols = protocolList != null ? protocolList.toLowerCase() : "";
        String ip = sampleIp != null ? sampleIp.trim() : "";
        String hints = serviceHint != null ? serviceHint.toLowerCase() : "";
        String infra = infraSignals != null ? infraSignals.toLowerCase() : "";

        boolean hasIp = !ip.isBlank();
        boolean multicastMac = mac.startsWith("01:00:5E") || mac.startsWith("33:33");
        boolean broadcastMac = mac.startsWith("FF:FF:FF:FF:FF:FF");
        boolean controlNoise = notes.contains("ipv4-multicast")
                || notes.contains("ipv6-multicast")
                || notes.contains("broadcast")
                || protocols.contains("igmp");
        boolean arpClaim = notes.contains("who-has") || notes.contains("is-at");
        boolean localAdmin = isLocallyAdministeredMac(mac);
        boolean unknownVendor = vendor == null || vendor.isBlank() || "Unknown".equalsIgnoreCase(vendor);

        if (multicastMac || broadcastMac || (controlNoise && !hasIp)) {
            return new String[]{"Normal", "Multicast/broadcast control traffic"};
        }

        if (arpClaim && hasIp && seenCount >= 8 && unknownVendor) {
            return new String[]{"Suspicious", "Repeated ARP activity from unknown MAC with IP"};
        }

        if (hasIp && seenCount >= 6 && (hints.contains("vrrp")
                || hints.contains("hsrp")
                || hints.contains("ospf")
                || hints.contains("bgp")
                || hints.contains("snmp")
                || infra.contains("router-control"))) {
            return new String[]{"Suspicious", "Infrastructure-like control traffic from unaccounted host"};
        }

        if (!hasIp && seenCount >= 10) {
            return new String[]{"Review", "Repeatedly observed with no IP mapping"};
        }

        if (localAdmin && hasIp && seenCount >= 6) {
            return new String[]{"Review", "Locally administered MAC active on IP"};
        }

        if ("Unaccounted".equalsIgnoreCase(nmapStatus)) {
            return new String[]{"Review", "Unaccounted endpoint in capture"};
        }

        return new String[]{"Normal", "Low-volume unaccounted traffic"};
    }

    // ========================================
    // BLOCK 4 — SERVICE HINTS
    // ========================================
    public static String inferServiceHint(String rawLine, String protocolList, String noteList) {
        String line = rawLine != null ? rawLine.toLowerCase() : "";
        String protocols = protocolList != null ? protocolList.toLowerCase() : "";
        String notes = noteList != null ? noteList.toLowerCase() : "";

        if (line.contains("igmp")) return "IGMP group report";
        if (line.contains("vrrp")) return "VRRP";
        if (line.contains("hsrp")) return "HSRP";
        if (line.contains("ospf")) return "OSPF";
        if (line.contains(" bootpc ") || line.contains(" bootps ")) return "DHCP";
        if (line.contains(" mdns")) return "mDNS";
        if (line.contains(" ssdp")) return "SSDP";
        if (line.contains(" isakmp")) return "IPsec IKE";
        if (line.contains(" snmp")) return "SNMP";
        if (line.contains(" domain")) return "DNS";
        if (line.contains(" ntp")) return "NTP";

        if (line.contains(".53:")) return "DNS (port 53)";
        if (line.contains(".67:") || line.contains(".68:")) return "DHCP (67/68)";
        if (line.contains(".123:")) return "NTP (123)";
        if (line.contains(".161:") || line.contains(".162:")) return "SNMP (161/162)";
        if (line.contains(".179:")) return "BGP (179)";
        if (line.contains(".1900:")) return "SSDP (1900)";
        if (line.contains(".5353:")) return "mDNS (5353)";
        if (line.contains(".4789:")) return "VXLAN (4789)";

        if (notes.contains("ipv4-multicast") || notes.contains("ipv6-multicast")) return "Multicast data/control";
        if (notes.contains("broadcast")) return "Broadcast";
        if (protocols.contains("arp")) return "ARP";

        return "Unclassified";
    }

    // ========================================
    // BLOCK 5 — INFRA SIGNALS
    // ========================================
    public static String inferInfraSignals(String rawLine, String protocolList, String noteList) {
        String line = rawLine != null ? rawLine.toLowerCase() : "";
        String protocols = protocolList != null ? protocolList.toLowerCase() : "";
        String notes = noteList != null ? noteList.toLowerCase() : "";

        boolean multicast = notes.contains("ipv4-multicast") || notes.contains("ipv6-multicast");
        boolean arp = notes.contains("who-has") || notes.contains("is-at") || protocols.contains("arp");
        boolean routerControl = line.contains("vrrp")
                || line.contains("hsrp")
                || line.contains("ospf")
                || line.contains("igmp")
                || line.contains("pim")
                || line.contains("bgp");
        boolean mgmt = line.contains(" snmp")
                || line.contains(".161:")
                || line.contains(".162:")
                || line.contains(".22:")
                || line.contains(".443:");

        if (routerControl && mgmt) return "router-control+mgmt";
        if (routerControl) return "router-control";
        if (arp && multicast) return "arp+multicast";
        if (arp) return "arp";
        if (multicast) return "multicast";
        if (mgmt) return "mgmt-port";
        return "none";
    }

    // ========================================
    // BLOCK 6 — INTERNAL HELPERS
    // ========================================
    private static boolean containsAny(String text, String... tokens) {
        if (text == null || text.isBlank() || tokens == null) {
            return false;
        }
        for (String token : tokens) {
            if (token != null && !token.isBlank() && text.contains(token)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isGatewayLikeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        String normalized = ip;
        int slash = normalized.indexOf('/');
        if (slash > 0) {
            normalized = normalized.substring(0, slash);
        }
        int dot = normalized.lastIndexOf('.');
        if (dot < 0 || dot == normalized.length() - 1) {
            return false;
        }
        try {
            int lastOctet = Integer.parseInt(normalized.substring(dot + 1));
            return lastOctet == 1 || lastOctet == 254 || lastOctet == 253;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isLocallyAdministeredMac(String mac) {
        if (mac == null || mac.length() < 2) {
            return false;
        }
        try {
            int firstOctet = Integer.parseInt(mac.substring(0, 2), 16);
            return (firstOctet & 0x02) == 0x02;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }
}
