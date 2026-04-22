package dark_matter_scanner;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

// ========================================
// BLOCK 1 — FEATURE ANALYSIS SERVICE
// ========================================
public class FeatureAnalysisService {

    private final DatabaseService dbService;

    public FeatureAnalysisService(DatabaseService dbService) {
        this.dbService = dbService;
    }

    // ========================================
    // BLOCK 2 — LATEST CAPTURE LOOKUP
    // ========================================
    public Long findLatestCaptureId(int scanId) throws Exception {
        String captureSql = """
            SELECT id
            FROM tcpdump_captures
            WHERE scan_id = ?
            ORDER BY id DESC
            LIMIT 1
        """;

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(captureSql)
        ) {
            stmt.setInt(1, scanId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getLong("id");
                }
            }
        }

        return null;
    }

    // ========================================
    // BLOCK 3 — NETWORK NOISE SUMMARY TEXT
    // ========================================
    public String buildNetworkNoiseSummaryText(int scanId, long captureId) throws Exception {
        StringBuilder output = new StringBuilder();

        output.append("=== NETWORK NOISE SUMMARY ===\n");
        output.append("Scan ID: ").append(scanId).append("\n");
        output.append("Capture ID: ").append(captureId).append("\n\n");

        String summarySql = """
            SELECT traffic_class, row_count, pct_of_capture
            FROM vw_network_noise_summary
            WHERE scan_id = ?
              AND capture_id = ?
            ORDER BY row_count DESC, traffic_class
        """;

        int totalRows = 0;
        int noiseRows = 0;

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(summarySql)
        ) {
            stmt.setInt(1, scanId);
            stmt.setLong(2, captureId);

            try (ResultSet rs = stmt.executeQuery()) {
                output.append(String.format("%-22s | %-10s | %-10s%n", "CLASS", "COUNT", "PERCENT"));
                output.append("--------------------------------------------------------\n");

                while (rs.next()) {
                    String trafficClass = rs.getString("traffic_class");
                    int rowCount = rs.getInt("row_count");
                    double pct = rs.getDouble("pct_of_capture");

                    totalRows += rowCount;

                    if ("ARP".equals(trafficClass)
                            || "Broadcast".equals(trafficClass)
                            || "IPv4 Multicast".equals(trafficClass)
                            || "IPv6 Multicast".equals(trafficClass)) {
                        noiseRows += rowCount;
                    }

                    output.append(String.format(
                            "%-22s | %-10d | %-9.2f%%%n",
                            trafficClass,
                            rowCount,
                            pct
                    ));
                }
            }
        }

        output.append("\n=== TOP TALKERS ===\n\n");

        String talkerSql = """
            SELECT
                src_mac,
                src_vendor,
                COUNT(*) AS frame_count,
                COALESCE(MIN(src_ip)::text, '-') AS sample_src_ip,
                COUNT(DISTINCT src_ip) FILTER (WHERE src_ip IS NOT NULL) AS distinct_src_ip_count
            FROM vw_network_noise_detail
            WHERE scan_id = ?
              AND capture_id = ?
              AND src_mac IS NOT NULL
            GROUP BY src_mac, src_vendor
            ORDER BY frame_count DESC, src_mac
            LIMIT 10
        """;

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(talkerSql)
        ) {
            stmt.setInt(1, scanId);
            stmt.setLong(2, captureId);

            try (ResultSet rs = stmt.executeQuery()) {
                output.append(String.format(
                        "%-18s | %-20s | %-8s | %-15s | %-7s%n",
                        "SRC MAC",
                        "VENDOR",
                        "FRAMES",
                        "SAMPLE IP",
                        "IP CNT"
                ));
                output.append("--------------------------------------------------------------------------------\n");

                while (rs.next()) {
                    output.append(String.format(
                            "%-18s | %-20s | %-8d | %-15s | %-7d%n",
                            rs.getString("src_mac"),
                            rs.getString("src_vendor"),
                            rs.getInt("frame_count"),
                            rs.getString("sample_src_ip"),
                            rs.getInt("distinct_src_ip_count")
                    ));
                }
            }
        }

        output.append("\n=== CAPTURE SUMMARY ===\n\n");
        output.append("Total Observations: ").append(totalRows).append("\n");
        output.append("Broadcast/Multicast/ARP Rows: ").append(noiseRows).append("\n");

        if (totalRows > 0) {
            double noisePct = (noiseRows * 100.0) / totalRows;
            output.append(String.format("Noise Percentage: %.2f%%%n", noisePct));
        }

        return output.toString();
    }

    // ========================================
    // BLOCK 4 — DUPLICATE IP SUSPECTS
    // ========================================
    public List<Object[]> loadDuplicateIpSuspectRows(int scanId, long captureId) throws Exception {
        String suspectSql = """
            SELECT
                mo.src_ip AS suspected_ip,
                COUNT(DISTINCT mo.src_mac) AS distinct_mac_count,
                STRING_AGG(DISTINCT mo.src_mac, ', ' ORDER BY mo.src_mac) AS mac_list,
                STRING_AGG(
                    DISTINCT COALESCE(v.vendor_clean, v.vendor, 'Unknown'),
                    ', '
                    ORDER BY COALESCE(v.vendor_clean, v.vendor, 'Unknown')
                ) AS vendor_list,
                COUNT(*) AS arp_event_count,
                STRING_AGG(DISTINCT mo.note, ', ' ORDER BY mo.note) AS evidence_types
            FROM mac_observations mo
            LEFT JOIN mac_oui_lookup v
                ON LEFT(REGEXP_REPLACE(UPPER(mo.src_mac), '[^0-9A-F]', '', 'g'), 6)
                 = LEFT(REGEXP_REPLACE(UPPER(v.oui),      '[^0-9A-F]', '', 'g'), 6)
            WHERE mo.scan_id = ?
              AND mo.capture_id = ?
              AND mo.protocol = 'ARP'
              AND mo.src_ip IS NOT NULL
              AND mo.src_mac IS NOT NULL
              AND mo.note IN ('who-has', 'is-at')
            GROUP BY mo.src_ip
            HAVING COUNT(DISTINCT mo.src_mac) > 1
            ORDER BY distinct_mac_count DESC, arp_event_count DESC, mo.src_ip
        """;

        List<Object[]> rows = new ArrayList<>();

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(suspectSql)
        ) {
            stmt.setInt(1, scanId);
            stmt.setLong(2, captureId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    rows.add(new Object[]{
                            rs.getString("suspected_ip"),
                            rs.getInt("distinct_mac_count"),
                            rs.getString("mac_list"),
                            rs.getString("vendor_list"),
                            rs.getInt("arp_event_count"),
                            rs.getString("evidence_types")
                    });
                }
            }
        }

        return rows;
    }

    // ========================================
    // BLOCK 5 — DARK CANDIDATE ROWS
    // ========================================
    public List<DarkDeviceCandidate> loadDarkDeviceCandidates(int scanId, long captureId) throws Exception {
        String darkSql = """
            WITH scan_ctx AS (
                SELECT subnet::cidr AS subnet_cidr
                FROM scan_runs
                WHERE id = ?
            ),
            observed_candidates AS (
                SELECT
                    mo.src_mac AS candidate_mac,
                    mo.src_ip  AS candidate_ip,
                    mo.protocol,
                    mo.note,
                    mo.raw_line
                FROM mac_observations mo
                CROSS JOIN scan_ctx sc
                WHERE mo.scan_id = ?
                  AND mo.capture_id = ?
                  AND mo.src_mac IS NOT NULL
                  AND mo.src_ip IS NOT NULL
                  AND mo.src_ip <> '0.0.0.0'::inet
                  AND mo.src_ip << sc.subnet_cidr
                  AND UPPER(mo.src_mac) NOT IN ('FF:FF:FF:FF:FF:FF', '00:00:00:00:00:00')
                  AND UPPER(mo.src_mac) NOT LIKE '01:00:5E:%'
                  AND UPPER(mo.src_mac) NOT LIKE '33:33:%'
                  AND UPPER(mo.src_mac) NOT LIKE '01:80:C2:%'
                  AND UPPER(mo.src_mac) <> '01:00:0C:CC:CC:CC'
            ),
            filtered_candidates AS (
                SELECT *
                FROM observed_candidates
                WHERE candidate_mac IS NOT NULL
                  AND candidate_mac <> ''
                  AND candidate_ip IS NOT NULL
                  AND candidate_ip <> '0.0.0.0'::inet
            ),
            grouped_candidates AS (
                SELECT
                    fc.candidate_mac,
                    MIN(fc.candidate_ip) AS sample_ip,
                    COUNT(*) AS seen_count,
                    STRING_AGG(DISTINCT fc.protocol, ', ' ORDER BY fc.protocol) AS protocol_list,
                    STRING_AGG(DISTINCT COALESCE(fc.note, '?'), ', ' ORDER BY COALESCE(fc.note, '?')) AS note_list,
                    MIN(fc.raw_line) AS sample_line
                FROM filtered_candidates fc
                GROUP BY fc.candidate_mac
            )
            SELECT
                gc.sample_ip,
                gc.candidate_mac,
                COALESCE(v.vendor_clean, v.vendor, 'Unknown') AS vendor,
                gc.seen_count,
                gc.protocol_list,
                gc.note_list,
                CASE
                    WHEN ab_mac.mac_address IS NOT NULL THEN 'Known by Nmap MAC'
                    WHEN ab_ip.observed_ip IS NOT NULL THEN 'Known by Nmap IP'
                    ELSE 'Unaccounted'
                END AS nmap_status,
                gc.sample_line
            FROM grouped_candidates gc
            LEFT JOIN mac_oui_lookup v
                ON LEFT(REGEXP_REPLACE(UPPER(gc.candidate_mac), '[^0-9A-F]', '', 'g'), 6)
                 = LEFT(REGEXP_REPLACE(UPPER(v.oui),        '[^0-9A-F]', '', 'g'), 6)
            LEFT JOIN arp_bindings ab_mac
                ON ab_mac.scan_id = ?
               AND ab_mac.mac_address = gc.candidate_mac
            LEFT JOIN arp_bindings ab_ip
                ON ab_ip.scan_id = ?
               AND gc.sample_ip IS NOT NULL
               AND ab_ip.observed_ip = gc.sample_ip
            WHERE ab_mac.mac_address IS NULL
              AND ab_ip.observed_ip IS NULL
            ORDER BY gc.seen_count DESC, vendor, gc.candidate_mac
        """;

        List<DarkDeviceCandidate> rows = new ArrayList<>();

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(darkSql)
        ) {
            stmt.setInt(1, scanId);
            stmt.setInt(2, scanId);
            stmt.setLong(3, captureId);
            stmt.setInt(4, scanId);
            stmt.setInt(5, scanId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    rows.add(new DarkDeviceCandidate(
                            rs.getString("sample_ip"),
                            rs.getString("candidate_mac"),
                            rs.getString("vendor"),
                            rs.getInt("seen_count"),
                            rs.getString("protocol_list"),
                            rs.getString("note_list"),
                            rs.getString("nmap_status"),
                            rs.getString("sample_line")
                    ));
                }
            }
        }

        return rows;
    }

    // ========================================
    // BLOCK 6 — DARK DEVICE DTO
    // ========================================
    public static class DarkDeviceCandidate {
        public final String sampleIp;
        public final String candidateMac;
        public final String vendor;
        public final int seenCount;
        public final String protocolList;
        public final String noteList;
        public final String nmapStatus;
        public final String sampleLine;

        public DarkDeviceCandidate(
                String sampleIp,
                String candidateMac,
                String vendor,
                int seenCount,
                String protocolList,
                String noteList,
                String nmapStatus,
                String sampleLine
        ) {
            this.sampleIp = sampleIp;
            this.candidateMac = candidateMac;
            this.vendor = vendor;
            this.seenCount = seenCount;
            this.protocolList = protocolList;
            this.noteList = noteList;
            this.nmapStatus = nmapStatus;
            this.sampleLine = sampleLine;
        }
    }
}
