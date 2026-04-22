package dark_matter_scanner;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// ========================================
// BLOCK 1 — TCPDUMP PARSER SERVICE
// ========================================
public class TcpdumpParserService {

    // ========================================
    // BLOCK 2 — REGEX PATTERNS
    // ========================================
    private static final String IPV4 = "((?:\\d{1,3}\\.){3}\\d{1,3})";

    private static final Pattern MAC_PAIR_PATTERN = Pattern.compile(
            ".*?([0-9A-Fa-f:]{17})\\s*>\\s*([0-9A-Fa-f:]{17}).*"
    );

    private static final Pattern REQUEST_PATTERN = Pattern.compile(
            ".*?([0-9A-Fa-f:]{17})\\s*>\\s*([0-9A-Fa-f:]{17}).*?ARP.*?Request\\s+who-has\\s+"
                    + IPV4 + "\\s+tell\\s+" + IPV4 + ".*"
    );

    private static final Pattern REPLY_PATTERN = Pattern.compile(
            ".*?([0-9A-Fa-f:]{17})\\s*>\\s*([0-9A-Fa-f:]{17}).*?ARP.*?Reply\\s+"
                    + IPV4 + "\\s+is-at\\s+([0-9A-Fa-f:]{17}).*"
    );

    private static final Pattern IPV4_TRAFFIC_PATTERN = Pattern.compile(
            ".*?length\\s+\\d+:\\s+" + IPV4 + "(?:\\.\\d+)?\\s*>\\s+" + IPV4 + "(?:\\.\\d+)?[:\\s].*"
    );

    private static final Pattern ETHERTYPE_PATTERN = Pattern.compile(
            ".*?ethertype\\s+([^\\(,]+)\\s*\\(0x[0-9A-Fa-f]+\\).*"
    );

    // ========================================
    // BLOCK 3 — PARSE RAW TCPDUMP OUTPUT
    // ========================================
    public List<MacObservationRecord> parseArpObservations(int scanId, long captureId, String rawOutput) {

        List<MacObservationRecord> rows = new ArrayList<>();

        if (rawOutput == null || rawOutput.isBlank()) {
            return rows;
        }

        String[] lines = rawOutput.split("\\R");

        for (String line : lines) {
            String trimmed = line.trim();

            if (trimmed.isEmpty()) {
                continue;
            }

            if (shouldSkipLine(trimmed)) {
                continue;
            }

            Matcher requestMatcher = REQUEST_PATTERN.matcher(trimmed);
            if (requestMatcher.matches()) {
                String srcMac = requestMatcher.group(1).toUpperCase();
                String dstMac = requestMatcher.group(2).toUpperCase();
                String dstIp = requestMatcher.group(3);
                String srcIp = requestMatcher.group(4);

                rows.add(new MacObservationRecord(
                        scanId,
                        captureId,
                        srcMac,
                        srcIp,
                        dstMac,
                        dstIp,
                        "ARP",
                        "who-has",
                        trimmed
                ));
                continue;
            }

            Matcher replyMatcher = REPLY_PATTERN.matcher(trimmed);
            if (replyMatcher.matches()) {
                String ethernetSrcMac = replyMatcher.group(1).toUpperCase();
                String ethernetDstMac = replyMatcher.group(2).toUpperCase();
                String srcIp = replyMatcher.group(3);
                String arpClaimedMac = replyMatcher.group(4).toUpperCase();

                String srcMac = (arpClaimedMac != null && !arpClaimedMac.isBlank())
                        ? arpClaimedMac
                        : ethernetSrcMac;

                rows.add(new MacObservationRecord(
                        scanId,
                        captureId,
                        srcMac,
                        srcIp,
                        ethernetDstMac,
                        null,
                        "ARP",
                        "is-at",
                        trimmed
                ));
                continue;
            }

            String srcMac = null;
            String dstMac = null;

            Matcher macMatcher = MAC_PAIR_PATTERN.matcher(trimmed);
            if (macMatcher.matches()) {
                srcMac = macMatcher.group(1).toUpperCase();
                dstMac = macMatcher.group(2).toUpperCase();
            }

            String protocol = detectProtocol(trimmed);
            String note = detectNote(trimmed, dstMac, protocol);

            String srcIp = null;
            String dstIp = null;

            Matcher ipv4Matcher = IPV4_TRAFFIC_PATTERN.matcher(trimmed);
            if (ipv4Matcher.matches()) {
                srcIp = ipv4Matcher.group(1);
                dstIp = ipv4Matcher.group(2);
            }

            rows.add(new MacObservationRecord(
                    scanId,
                    captureId,
                    srcMac,
                    srcIp,
                    dstMac,
                    dstIp,
                    protocol,
                    note,
                    trimmed
            ));
        }

        return rows;
    }

    // ========================================
    // BLOCK 4 — SKIP NON-PACKET LINES
    // ========================================
    private boolean shouldSkipLine(String line) {
        String lower = line.toLowerCase();

        return lower.startsWith("tcpdump:")
                || lower.startsWith("listening on ")
                || lower.startsWith("dropped privs to ")
                || lower.startsWith("verbose output suppressed")
                || lower.startsWith("reading from file")
                || lower.startsWith("packets captured")
                || lower.startsWith("packets received by filter")
                || lower.startsWith("packets dropped by kernel");
    }

    // ========================================
    // BLOCK 5 — DETECT PROTOCOL
    // ========================================
    private String detectProtocol(String line) {

        if (line.contains(" ARP,") || line.contains(" ARP ")) {
            return "ARP";
        }

        Matcher ethertypeMatcher = ETHERTYPE_PATTERN.matcher(line);
        if (ethertypeMatcher.matches()) {
            String ethertype = ethertypeMatcher.group(1).trim();

            if (ethertype.equalsIgnoreCase("IPv4")) {
                return "IPv4";
            }

            if (ethertype.equalsIgnoreCase("IPv6")) {
                return "IPv6";
            }

            return ethertype.toUpperCase();
        }

        if (line.contains(" IP6 ")) {
            return "IPv6";
        }

        if (line.contains(" IP ")) {
            return "IPv4";
        }

        return "OTHER";
    }

    // ========================================
    // BLOCK 6 — DETECT NOTE / TRAFFIC CLASS
    // ========================================
    private String detectNote(String line, String dstMac, String protocol) {

        if (dstMac != null) {
            String normalizedDstMac = dstMac.toUpperCase();

            if ("FF:FF:FF:FF:FF:FF".equals(normalizedDstMac)) {
                return "broadcast";
            }

            if (normalizedDstMac.startsWith("01:00:5E")) {
                return "ipv4-multicast";
            }

            if (normalizedDstMac.startsWith("33:33")) {
                return "ipv6-multicast";
            }

            if (isMulticastMac(normalizedDstMac)) {
                return "multicast";
            }
        }

        if ("ARP".equals(protocol)) {
            return "arp-other";
        }

        return "unicast";
    }

    // ========================================
    // BLOCK 7 — MULTICAST MAC CHECK
    // ========================================
    private boolean isMulticastMac(String mac) {

        if (mac == null || mac.length() < 2) {
            return false;
        }

        try {
            int firstOctet = Integer.parseInt(mac.substring(0, 2), 16);
            return (firstOctet & 1) == 1;
        } catch (Exception e) {
            return false;
        }
    }

    // ========================================
    // BLOCK 8 — RECORD MODEL
    // ========================================
    public static class MacObservationRecord {
        private final int scanId;
        private final long captureId;
        private final String srcMac;
        private final String srcIp;
        private final String dstMac;
        private final String dstIp;
        private final String protocol;
        private final String note;
        private final String rawLine;

        public MacObservationRecord(
                int scanId,
                long captureId,
                String srcMac,
                String srcIp,
                String dstMac,
                String dstIp,
                String protocol,
                String note,
                String rawLine
        ) {
            this.scanId = scanId;
            this.captureId = captureId;
            this.srcMac = srcMac;
            this.srcIp = srcIp;
            this.dstMac = dstMac;
            this.dstIp = dstIp;
            this.protocol = protocol;
            this.note = note;
            this.rawLine = rawLine;
        }

        public int getScanId() {
            return scanId;
        }

        public long getCaptureId() {
            return captureId;
        }

        public String getSrcMac() {
            return srcMac;
        }

        public String getSrcIp() {
            return srcIp;
        }

        public String getDstMac() {
            return dstMac;
        }

        public String getDstIp() {
            return dstIp;
        }

        public String getProtocol() {
            return protocol;
        }

        public String getNote() {
            return note;
        }

        public String getRawLine() {
            return rawLine;
        }
    }
}