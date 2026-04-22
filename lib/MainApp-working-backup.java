package dark_matter_scanner;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
//import java.util.regex.Matcher;
//import java.util.regex.Pattern;

// ========================================
// BLOCK 1 — MAIN APP
// ========================================
public class MainApp {

    // ========================================
    // BLOCK 2 — SERVICES
    // ========================================
    private final ScanExecutor executor = new ScanExecutor();
    private final DatabaseService dbService = new DatabaseService();
    private final TcpdumpParserService tcpdumpParserService = new TcpdumpParserService();

    // ========================================
    // BLOCK 3 — UI COMPONENTS
    // ========================================
    private JFrame frame;
    private JTextField subnetField;
    private JTextArea outputArea;
    private JTable scanTable;
    private DefaultTableModel tableModel;
    private JComboBox<String> ifaceDropdown;

    private JCheckBox sshCheckbox;
    private JTextField sshUserField;
    private JPasswordField sshPassField;
    private JTextField targetHostField;

    private JButton tcpdumpBtn;
    private JSpinner captureMinutesSpinner;
    private JLabel captureStatusLabel;

    private ActionPanelManager actionPanelManager;

    // --- OUTPUT MODE COMPONENTS ---
    private CardLayout outputCardLayout;
    private JPanel outputCardPanel;
    private JTable detailTable;
    private DefaultTableModel detailTableModel;

    // ========================================
    // BLOCK 4 — STATE
    // ========================================
    private Integer activeScanId = null;
    private boolean captureRunning = false;
    private long captureStartMillis = 0L;
    private int captureDurationSeconds = 0;
    private javax.swing.Timer captureTimer = null;

    // ========================================
    // BLOCK 5 — MAIN ENTRY
    // ========================================
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainApp().initUI());
    }

    // ========================================
    // BLOCK 6 — UI SETUP
    // ========================================
    private void initUI() {

        frame = new JFrame("Dark Matter Scanner");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        frame.setSize(1450, 900);

        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sshCheckbox = new JCheckBox("Use SSH");
        sshCheckbox.setSelected(true);

        sshUserField = new JTextField("root", 8);
        sshPassField = new JPasswordField("doonoot", 10);
        targetHostField = new JTextField("192.168.1.1", 12);

        subnetField = new JTextField("192.168.1.0/24", 15);
        ifaceDropdown = new JComboBox<>();

        JButton ifaceBtn = new JButton("Load Interfaces");
        ifaceBtn.addActionListener(e -> loadInterfaces());

        JButton startBtn = new JButton("Start Scan");
        startBtn.addActionListener(e -> startScan());

        JButton deleteBtn = new JButton("Delete Selected");
        deleteBtn.addActionListener(e -> deleteSelectedScans());

        captureMinutesSpinner = new JSpinner(new SpinnerNumberModel(5, 1, 60, 1));

        tcpdumpBtn = new JButton("Start TCP Dump");
        tcpdumpBtn.addActionListener(e -> startTimedTcpdumpCapture());

        captureStatusLabel = new JLabel("TCP Dump Idle");

        top.add(sshCheckbox);
        top.add(new JLabel("User:"));
        top.add(sshUserField);
        top.add(new JLabel("Pass:"));
        top.add(sshPassField);
        top.add(new JLabel("Target:"));
        top.add(targetHostField);

        top.add(new JLabel("Subnet:"));
        top.add(subnetField);
        top.add(ifaceBtn);
        top.add(ifaceDropdown);
        top.add(startBtn);
        top.add(deleteBtn);

        top.add(Box.createHorizontalStrut(20));
        top.add(new JLabel("Capture Minutes:"));
        top.add(captureMinutesSpinner);
        top.add(tcpdumpBtn);
        top.add(captureStatusLabel);

        tableModel = new DefaultTableModel(
                new String[]{"ID", "Subnet", "Status", "Target", "SSH"},
                0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        scanTable = new JTable(tableModel);
        scanTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        scanTable.setAutoCreateRowSorter(true);

        outputArea = new JTextArea();
        outputArea.setEditable(false);
        outputArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        detailTableModel = new DefaultTableModel(
                new String[]{
                        "IP",
                        "MAC",
                        "Vendor",
                        "RTT ms",
                        "Response Type",
                        "Source",
                        "Seen Count",
                        "Last Seen"
                },
                0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        detailTable = new JTable(detailTableModel);
        detailTable.setAutoCreateRowSorter(true);
        detailTable.setFillsViewportHeight(true);

        outputCardLayout = new CardLayout();
        outputCardPanel = new JPanel(outputCardLayout);
        outputCardPanel.add(new JScrollPane(outputArea), "TEXT");
        outputCardPanel.add(new JScrollPane(detailTable), "TABLE");

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(scanTable),
                outputCardPanel
        );
        split.setDividerLocation(300);

        actionPanelManager = new ActionPanelManager(this);

        frame.add(top, BorderLayout.NORTH);
        frame.add(actionPanelManager.getPanel(), BorderLayout.WEST);
        frame.add(split, BorderLayout.CENTER);

        frame.setVisible(true);

        showTextOutput();
        loadHistory();
    }

    // ========================================
    // BLOCK 7 — LOAD INTERFACES
    // ========================================
    private void loadInterfaces() {

        new Thread(() -> {
            try {
                append("Loading interfaces...");

                String output;

                if (sshCheckbox.isSelected()) {
                    output = executor.runSSH(
                            targetHostField.getText().trim(),
                            sshUserField.getText().trim(),
                            new String(sshPassField.getPassword()),
                            "ifconfig"
                    );
                } else {
                    output = executor.runLocal(List.of("ifconfig"));
                }

                List<String> list = parseInterfaces(output);

                SwingUtilities.invokeLater(() -> {
                    ifaceDropdown.removeAllItems();
                    for (String s : list) {
                        ifaceDropdown.addItem(s);
                    }
                });

                append("Interfaces loaded: " + list.size());

            } catch (Exception e) {
                append("INTERFACE ERROR: " + e.getMessage());
            }
        }).start();
    }

    // ========================================
    // BLOCK 8 — PARSE INTERFACES
    // ========================================
    private List<String> parseInterfaces(String text) {

        List<String> list = new ArrayList<>();
        String iface = null;

        for (String line : text.split("\\R")) {

            if (!line.startsWith("\t") && line.contains(": flags")) {
                iface = line.split(":")[0];
            }

            if (line.trim().startsWith("inet ") && iface != null) {
                String ip = line.trim().split("\\s+")[1];
                if (!ip.startsWith("127.")) {
                    list.add(iface + " - " + ip);
                }
            }
        }

        return list;
    }

    // ========================================
    // BLOCK 9 — START SCAN
    // ========================================
    private void startScan() {

        try {
            String subnet = subnetField.getText().trim();

            if (subnet.isEmpty()) {
                append("Enter a subnet first.");
                return;
            }

            String ifaceValue = (String) ifaceDropdown.getSelectedItem();
            String ifaceName = "auto";

            if (ifaceValue != null && ifaceValue.contains(" - ")) {
                ifaceName = ifaceValue.split(" - ")[0];
            }

            boolean sshUsed = sshCheckbox.isSelected();
            String targetHost = sshUsed ? targetHostField.getText().trim() : "local";

            int scanId = dbService.createScanRun(subnet, ifaceName, targetHost, sshUsed);
            activeScanId = scanId;

            append("Scan started ID=" + scanId);

            SwingUtilities.invokeLater(this::loadHistory);

            final String fSubnet = subnet;
            final String fIface = ifaceName;
            final boolean fSsh = sshUsed;
            final String fTarget = targetHost;
            final int fScanId = scanId;

            new Thread(() -> runDiscoveryScan(fSubnet, fIface, fSsh, fTarget, fScanId)).start();

        } catch (Exception e) {
            append("ERROR: " + e.getMessage());
        }
    }

    // ========================================
    // BLOCK 10 — DISCOVERY SCAN
    // ========================================
    private void runDiscoveryScan(String subnet, String ifaceName, boolean sshUsed, String targetHost, int scanId) {

        try {
            String cmd = "nmap -sn -PR -n -oX - " + subnet;
            String output;

            if (sshUsed) {
                output = executor.runSSH(
                        targetHost,
                        sshUserField.getText().trim(),
                        new String(sshPassField.getPassword()),
                        cmd
                );
            } else {
                output = executor.runLocal(List.of(
                        "sudo", "nmap", "-sn", "-PR", "-n", "-oX", "-", subnet
                ));
            }

            parseAndStoreArp(output, scanId);
            dbService.completeScan(scanId, output);

            SwingUtilities.invokeLater(this::loadHistory);

            append("Scan complete.");

        } catch (Exception e) {
            append("SCAN ERROR: " + e.getMessage());
        }
    }

    // ========================================
    // BLOCK 11 — PARSE ARP
    // ========================================
    private void parseAndStoreArp(String xml, int scanId) {

        try {
            javax.xml.parsers.DocumentBuilderFactory factory =
                    javax.xml.parsers.DocumentBuilderFactory.newInstance();

            javax.xml.parsers.DocumentBuilder builder =
                    factory.newDocumentBuilder();

            org.w3c.dom.Document doc =
                    builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));

            org.w3c.dom.NodeList hosts = doc.getElementsByTagName("host");

            for (int i = 0; i < hosts.getLength(); i++) {

                org.w3c.dom.Element host = (org.w3c.dom.Element) hosts.item(i);

                String ip = null;
                String mac = null;
                Double rtt = null;
                String responseType = "unknown";

                org.w3c.dom.NodeList statusList = host.getElementsByTagName("status");
                if (statusList.getLength() > 0) {
                    org.w3c.dom.Element status = (org.w3c.dom.Element) statusList.item(0);
                    responseType = status.getAttribute("reason");
                }

                org.w3c.dom.NodeList addresses = host.getElementsByTagName("address");

                for (int j = 0; j < addresses.getLength(); j++) {
                    org.w3c.dom.Element addr = (org.w3c.dom.Element) addresses.item(j);

                    String type = addr.getAttribute("addrtype");
                    String value = addr.getAttribute("addr");

                    if ("ipv4".equals(type)) {
                        ip = value;
                    }
                    if ("mac".equals(type)) {
                        mac = value;
                    }
                }

                org.w3c.dom.NodeList timesList = host.getElementsByTagName("times");

                if (timesList.getLength() > 0) {
                    org.w3c.dom.Element times = (org.w3c.dom.Element) timesList.item(0);
                    String srtt = times.getAttribute("srtt");

                    if (!srtt.isEmpty()) {
                        rtt = Double.parseDouble(srtt) / 1000.0;
                    }
                }

                if (ip != null && mac != null) {
                    dbService.upsertArpBinding(scanId, ip, mac, "active_arp", rtt, responseType);
                }
            }

        } catch (Exception e) {
            append("PARSE ERROR: " + e.getMessage());
        }
    }

    // ========================================
    // BLOCK 12 — LOAD HISTORY
    // ========================================
    private void loadHistory() {

        tableModel.setRowCount(0);

        String sql = """
            SELECT id, subnet, status, target_host, ssh_used
            FROM scan_runs
            ORDER BY id DESC
            LIMIT 50
        """;

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql);
                ResultSet rs = stmt.executeQuery()
        ) {
            while (rs.next()) {
                tableModel.addRow(new Object[]{
                        rs.getInt("id"),
                        rs.getString("subnet"),
                        rs.getString("status"),
                        rs.getString("target_host"),
                        rs.getBoolean("ssh_used")
                });
            }
        } catch (Exception e) {
            append("LOAD ERROR: " + e.getMessage());
        }
    }

    // ========================================
    // BLOCK 13 — DELETE SCANS
    // ========================================
    private void deleteSelectedScans() {

        int[] rows = scanTable.getSelectedRows();

        if (rows.length == 0) {
            append("Select a scan first.");
            return;
        }

        new Thread(() -> {
            try {
                for (int row : rows) {
                    int modelRow = scanTable.convertRowIndexToModel(row);
                    int scanId = (int) tableModel.getValueAt(modelRow, 0);
                    dbService.deleteScanCompletely(scanId);
                }

                SwingUtilities.invokeLater(this::loadHistory);
                append("Selected scans deleted.");

            } catch (Exception e) {
                append("DELETE ERROR: " + e.getMessage());
            }
        }).start();
    }

    // ========================================
    // BLOCK 13B — GET SELECTED SCAN ID
    // ========================================
    public Integer getSelectedScanId() {

        int selectedRow = scanTable.getSelectedRow();

        if (selectedRow == -1) {
            return null;
        }

        int modelRow = scanTable.convertRowIndexToModel(selectedRow);
        return (int) tableModel.getValueAt(modelRow, 0);
    }

    // ========================================
    // BLOCK 14 — RTT CLUSTERS
    // ========================================
    public void showRttClusters() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            StringBuilder output = new StringBuilder();

            try (Connection conn = dbService.getConnection()) {

                String summarySql = """
                    SELECT
                        rtt_bucket,
                        node_count,
                        min_rtt,
                        max_rtt,
                        avg_rtt
                    FROM vw_rtt_cluster_summary
                    WHERE scan_id = ?
                    ORDER BY rtt_bucket
                """;

                String detailSql = """
                    SELECT
                        rtt_bucket,
                        observed_ip,
                        mac_address,
                        resolved_vendor,
                        rtt_ms
                    FROM vw_rtt_cluster_nodes
                    WHERE scan_id = ?
                    ORDER BY rtt_bucket, rtt_ms, observed_ip
                """;

                java.util.Map<Double, java.util.List<String>> clusterMap = new java.util.LinkedHashMap<>();
                java.util.Map<Double, String> summaryMap = new java.util.LinkedHashMap<>();

                try (PreparedStatement stmt = conn.prepareStatement(summarySql)) {
                    stmt.setInt(1, fScanId);

                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            double bucket = rs.getDouble("rtt_bucket");

                            summaryMap.put(
                                    bucket,
                                    String.format(
                                            "Nodes=%d | Min=%.3f | Max=%.3f | Avg=%.3f",
                                            rs.getInt("node_count"),
                                            rs.getDouble("min_rtt"),
                                            rs.getDouble("max_rtt"),
                                            rs.getDouble("avg_rtt")
                                    )
                            );
                        }
                    }
                }

                try (PreparedStatement stmt = conn.prepareStatement(detailSql)) {
                    stmt.setInt(1, fScanId);

                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            double bucket = rs.getDouble("rtt_bucket");

                            clusterMap.computeIfAbsent(bucket, k -> new java.util.ArrayList<>())
                                    .add(
                                            rs.getString("observed_ip")
                                                    + " | "
                                                    + rs.getString("mac_address")
                                                    + " | "
                                                    + rs.getString("resolved_vendor")
                                                    + " | RTT="
                                                    + rs.getDouble("rtt_ms")
                                    );
                        }
                    }
                }

                if (clusterMap.isEmpty()) {
                    output.append("No RTT cluster data found.\n");
                } else {
                    for (java.util.Map.Entry<Double, java.util.List<String>> entry : clusterMap.entrySet()) {
                        double bucket = entry.getKey();

                        output.append("\n=== CLUSTER (~ ")
                                .append(bucket)
                                .append(" ms) ===\n");

                        if (summaryMap.containsKey(bucket)) {
                            output.append(summaryMap.get(bucket)).append("\n");
                        }

                        for (String line : entry.getValue()) {
                            output.append(line).append("\n");
                        }
                    }
                }

                append(output.toString());

            } catch (Exception e) {
                append("CLUSTER ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 15 — OUTPUT
    // ========================================
    private void append(String msg) {
        SwingUtilities.invokeLater(() -> {
            showTextOutput();
            outputArea.append(msg + "\n");
        });
    }

    // ========================================
    // BLOCK 16 — DUPLICATE IP DETECTION
    // ========================================
    public void showDuplicateIPs() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            StringBuilder output = new StringBuilder();

            try (Connection conn = dbService.getConnection()) {

                String sql = """
                SELECT observed_ip,
                       COUNT(DISTINCT mac_address) AS mac_count,
                       STRING_AGG(DISTINCT mac_address, ', ') AS macs
                FROM arp_bindings
                WHERE scan_id = ?
                GROUP BY observed_ip
                HAVING COUNT(DISTINCT mac_address) > 1
            """;

                PreparedStatement stmt = conn.prepareStatement(sql);
                stmt.setInt(1, fScanId);

                ResultSet rs = stmt.executeQuery();

                while (rs.next()) {

                    output.append("DUPLICATE IP: ")
                            .append(rs.getString("observed_ip"))
                            .append("\n");

                    output.append("MACS: ")
                            .append(rs.getString("macs"))
                            .append("\n\n");
                }

                append(output.toString());

            } catch (Exception e) {
                append("DUP ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
// BLOCK 17 — START TIMED TCPDUMP CAPTURE
// ========================================
    private void startTimedTcpdumpCapture() {

        if (captureRunning) {
            append("A TCP dump capture is already running.");
            return;
        }

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            scanId = activeScanId;
        }

        if (scanId == null) {
            append("Select a scan first, or run a scan first.");
            return;
        }

        String ifaceValue = (String) ifaceDropdown.getSelectedItem();
        if (ifaceValue == null || !ifaceValue.contains(" - ")) {
            append("Load interfaces and select one first.");
            return;
        }

        String ifaceName = ifaceValue.split(" - ")[0].trim();
        boolean sshUsed = sshCheckbox.isSelected();
        String captureMethod = sshUsed ? "ssh" : "local";
        String captureHost = sshUsed ? targetHostField.getText().trim() : "local";

        int minutes = (Integer) captureMinutesSpinner.getValue();
        int durationSeconds = minutes * 60;

        captureRunning = true;
        captureDurationSeconds = durationSeconds;
        captureStartMillis = System.currentTimeMillis();

        tcpdumpBtn.setEnabled(false);
        startCaptureTimer();

        final int fScanId = scanId;
        final String fIfaceName = ifaceName;
        final boolean fSsh = sshUsed;
        final String fCaptureMethod = captureMethod;
        final String fCaptureHost = captureHost;
        final int fDurationSeconds = durationSeconds;

        new Thread(() -> {

            long captureId = -1L;

            try {
                append("Starting TCP dump capture on " + fIfaceName + " for " + minutes + " minute(s)...");

                captureId = dbService.createTcpdumpCapture(
                        fScanId,
                        fCaptureMethod,
                        fCaptureHost,
                        fIfaceName,
                        "all",
                        fDurationSeconds
                );

                String command;

                if (fSsh) {
                    command = "tcpdump -i " + fIfaceName + " -nn -e arp -c 20";
                } else {
                    command = "sudo tcpdump -i " + fIfaceName + " -nn -e arp 2>&1 & "
                            + "PID=$!; "
                            + "sleep " + fDurationSeconds + "; "
                            + "sudo kill -2 $PID >/dev/null 2>&1; "
                            + "sleep 1";
                }
                String output;

                long commandStart = System.currentTimeMillis();
                append("TCPDUMP COMMAND STARTED");

                if (fSsh) {
                    output = executor.runSSH(
                            targetHostField.getText().trim(),
                            sshUserField.getText().trim(),
                            new String(sshPassField.getPassword()),
                            command
                    );
                } else {
                    output = executor.runLocal(List.of("sh", "-c", command));
                }
                long commandEnd = System.currentTimeMillis();
                append("TCPDUMP COMMAND RETURNED after " + ((commandEnd - commandStart) / 1000.0) + " seconds");

                dbService.completeTcpdumpCapture(captureId, output);

                long parseStart = System.currentTimeMillis();
                append("TCPDUMP PARSE STARTED");

                int inserted = parseAndStoreTcpdumpArp(fScanId, captureId, output);

                long parseEnd = System.currentTimeMillis();
                append("TCPDUMP PARSE FINISHED after " + ((parseEnd - parseStart) / 1000.0) + " seconds");

                final long fCaptureId = captureId;
                SwingUtilities.invokeLater(() -> stopCaptureTimer("TCP Dump Complete"));

                append("TCP dump complete. Capture ID=" + fCaptureId + " | Parsed rows=" + inserted);

            } catch (Exception e) {
                try {
                    if (captureId > 0) {
                        dbService.failTcpdumpCapture(captureId, e.getMessage());
                    }
                } catch (Exception ignored) {
                }

                SwingUtilities.invokeLater(() -> stopCaptureTimer("TCP Dump Failed"));
                append("TCPDUMP ERROR: " + e.getMessage());

            } finally {
                SwingUtilities.invokeLater(() -> {
                    captureRunning = false;
                    tcpdumpBtn.setEnabled(true);
                });
            }

        }).start();
    }

    // ========================================
// BLOCK 18 — BUILD TIMED TCPDUMP COMMAND
// ========================================
    private String buildTimedTcpdumpCommand(String ifaceName, int durationSeconds) {

        return "sudo tcpdump -i " + ifaceName + " -nn -e arp 2>&1 & "
                + "PID=$!; "
                + "sleep " + durationSeconds + "; "
                + "sudo kill -2 $PID >/dev/null 2>&1; "
                + "sleep 1";
    }
    // ========================================
// BLOCK 19 — PARSE AND STORE TCPDUMP ARP
// ========================================
    private int parseAndStoreTcpdumpArp(int scanId, long captureId, String rawOutput) throws Exception {

        List<TcpdumpParserService.MacObservationRecord> rows =
                tcpdumpParserService.parseArpObservations(scanId, captureId, rawOutput);

        append("TCPDUMP PARSE MATCHES FOUND: " + rows.size());

        if (rows.isEmpty()) {
            return 0;
        }

        return dbService.insertMacObservationsBatch(rows);
    }
    // ========================================
    // BLOCK 20 — TOPOLOGY VIEW
    // ========================================
    public void showTopology() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            StringBuilder output = new StringBuilder();

            try (Connection conn = dbService.getConnection()) {

                String sql = """
                SELECT observed_ip, mac_address, rtt_ms
                FROM arp_bindings
                WHERE scan_id = ?
                ORDER BY rtt_ms
            """;

                PreparedStatement stmt = conn.prepareStatement(sql);
                stmt.setInt(1, fScanId);

                ResultSet rs = stmt.executeQuery();

                while (rs.next()) {

                    output.append(rs.getString("observed_ip"))
                            .append(" | ")
                            .append(rs.getString("mac_address"))
                            .append(" | RTT=")
                            .append(rs.getDouble("rtt_ms"))
                            .append("\n");
                }

                append(output.toString());

            } catch (Exception e) {
                append("TOPO ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 21 — CLEAR OUTPUT
    // ========================================
    public void clearOutput() {
        SwingUtilities.invokeLater(() -> {
            outputArea.setText("");
            detailTableModel.setRowCount(0);
            showTextOutput();
        });
    }

    // ========================================
    // BLOCK 22 — SHOW TEXT OUTPUT
    // ========================================
    private void showTextOutput() {
        outputCardLayout.show(outputCardPanel, "TEXT");
    }

    // ========================================
    // BLOCK 23 — SHOW TABLE OUTPUT
    // ========================================
    private void showTableOutput() {
        outputCardLayout.show(outputCardPanel, "TABLE");
    }

    // ========================================
    // BLOCK 24 — VIEW SCAN
    // ========================================
    public void viewRawScan() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            String sql = """
                SELECT
                    observed_ip,
                    mac_address,
                    resolved_vendor,
                    rtt_ms,
                    response_type,
                    source,
                    seen_count,
                    last_seen
                FROM vw_scan_nodes
                WHERE scan_id = ?
                ORDER BY observed_ip
            """;

            List<Object[]> rows = new ArrayList<>();

            try (
                    Connection conn = dbService.getConnection();
                    PreparedStatement stmt = conn.prepareStatement(sql)
            ) {
                stmt.setInt(1, fScanId);

                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        Object rttValue = rs.getObject("rtt_ms");

                        rows.add(new Object[]{
                                rs.getString("observed_ip"),
                                rs.getString("mac_address"),
                                rs.getString("resolved_vendor"),
                                (rttValue != null ? rs.getDouble("rtt_ms") : null),
                                rs.getString("response_type"),
                                rs.getString("source"),
                                rs.getInt("seen_count"),
                                rs.getTimestamp("last_seen")
                        });
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    detailTableModel.setRowCount(0);

                    for (Object[] row : rows) {
                        detailTableModel.addRow(row);
                    }

                    showTableOutput();
                });

            } catch (Exception e) {
                append("VIEW ERROR: " + e.getMessage());
            }

        }).start();
    }
    // ========================================
    // BLOCK 24B — VIEW TCPDUMP CAPTURE
    // ========================================
    public void viewTcpdumpCapture() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            String captureSql = """
                SELECT id
                FROM tcpdump_captures
                WHERE scan_id = ?
                ORDER BY id DESC
                LIMIT 1
            """;

            String rowsSql = """
                SELECT
                    mo.src_mac,
                    COALESCE(srcv.vendor_clean, srcv.vendor, 'Unknown') AS src_vendor,
                    mo.src_ip,
                    mo.dst_mac,
                    COALESCE(dstv.vendor_clean, dstv.vendor, 'Unknown') AS dst_vendor,
                    mo.dst_ip,
                    mo.protocol,
                    mo.note,
                    mo.raw_line
                FROM mac_observations mo
                LEFT JOIN mac_oui_lookup srcv
                    ON LEFT(REGEXP_REPLACE(UPPER(mo.src_mac), '[^0-9A-F]', '', 'g'), 6)
                     = LEFT(REGEXP_REPLACE(UPPER(srcv.oui),   '[^0-9A-F]', '', 'g'), 6)
                LEFT JOIN mac_oui_lookup dstv
                    ON LEFT(REGEXP_REPLACE(UPPER(mo.dst_mac), '[^0-9A-F]', '', 'g'), 6)
                     = LEFT(REGEXP_REPLACE(UPPER(dstv.oui),   '[^0-9A-F]', '', 'g'), 6)
                WHERE mo.scan_id = ?
                  AND mo.capture_id = ?
                ORDER BY mo.id
            """;

            List<Object[]> rows = new ArrayList<>();

            try (
                    Connection conn = dbService.getConnection();
                    PreparedStatement captureStmt = conn.prepareStatement(captureSql)
            ) {
                captureStmt.setInt(1, fScanId);

                Long captureId = null;

                try (ResultSet captureRs = captureStmt.executeQuery()) {
                    if (captureRs.next()) {
                        captureId = captureRs.getLong("id");
                    }
                }

                if (captureId == null) {
                    append("No TCP dump capture found for scan ID " + fScanId + ".");
                    return;
                }

                try (PreparedStatement rowStmt = conn.prepareStatement(rowsSql)) {
                    rowStmt.setInt(1, fScanId);
                    rowStmt.setLong(2, captureId);

                    try (ResultSet rs = rowStmt.executeQuery()) {
                        while (rs.next()) {
                            rows.add(new Object[]{
                                    rs.getString("src_mac"),
                                    rs.getString("src_vendor"),
                                    rs.getString("src_ip"),
                                    rs.getString("dst_mac"),
                                    rs.getString("dst_vendor"),
                                    rs.getString("dst_ip"),
                                    rs.getString("protocol"),
                                    rs.getString("note"),
                                    rs.getString("raw_line")
                            });
                        }
                    }
                }

                final Long fCaptureId = captureId;

                SwingUtilities.invokeLater(() -> {
                    detailTableModel.setRowCount(0);
                    detailTableModel.setColumnIdentifiers(new String[]{
                            "Src MAC",
                            "Src Vendor",
                            "Src IP",
                            "Dst MAC",
                            "Dst Vendor",
                            "Dst IP",
                            "Protocol",
                            "Note",
                            "Raw Line"
                    });

                    for (Object[] row : rows) {
                        detailTableModel.addRow(row);
                    }

                    showTableOutput();
                });

                //append("Loaded parsed TCP dump rows for capture ID " + fCaptureId + ": " + rows.size());

            } catch (Exception e) {
                append("TCPDUMP VIEW ERROR: " + e.getMessage());
            }

        }).start();
    }
    // ========================================
// BLOCK 24C — NETWORK NOISE SUMMARY
// ========================================
    public void showNetworkNoiseSummary() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            StringBuilder output = new StringBuilder();

            try (Connection conn = dbService.getConnection()) {

                Long captureId = null;

                String captureSql = """
                SELECT id
                FROM tcpdump_captures
                WHERE scan_id = ?
                ORDER BY id DESC
                LIMIT 1
            """;

                try (PreparedStatement stmt = conn.prepareStatement(captureSql)) {
                    stmt.setInt(1, fScanId);

                    try (ResultSet rs = stmt.executeQuery()) {
                        if (rs.next()) {
                            captureId = rs.getLong("id");
                        }
                    }
                }

                if (captureId == null) {
                    append("No TCP dump capture found for scan ID " + fScanId + ".");
                    return;
                }

                output.append("=== NETWORK NOISE SUMMARY ===\n");
                output.append("Scan ID: ").append(fScanId).append("\n");
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

                try (PreparedStatement stmt = conn.prepareStatement(summarySql)) {
                    stmt.setInt(1, fScanId);
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
                SELECT src_mac, src_vendor, frame_count
                FROM vw_network_top_talkers
                WHERE scan_id = ?
                  AND capture_id = ?
                ORDER BY frame_count DESC, src_mac
                LIMIT 10
            """;

                try (PreparedStatement stmt = conn.prepareStatement(talkerSql)) {
                    stmt.setInt(1, fScanId);
                    stmt.setLong(2, captureId);

                    try (ResultSet rs = stmt.executeQuery()) {
                        output.append(String.format("%-18s | %-25s | %-10s%n", "SRC MAC", "VENDOR", "FRAMES"));
                        output.append("-----------------------------------------------------------------\n");

                        while (rs.next()) {
                            output.append(String.format(
                                    "%-18s | %-25s | %-10d%n",
                                    rs.getString("src_mac"),
                                    rs.getString("src_vendor"),
                                    rs.getInt("frame_count")
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

                append(output.toString());

            } catch (Exception e) {
                append("NOISE SUMMARY ERROR: " + e.getMessage());
            }

        }).start();
    }
    // ========================================
    // BLOCK 24D — DUPLICATE IP SUSPECTS
    // ========================================
    public void showDuplicateIpSuspects() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            String captureSql = """
                SELECT id
                FROM tcpdump_captures
                WHERE scan_id = ?
                ORDER BY id DESC
                LIMIT 1
            """;

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
                    PreparedStatement captureStmt = conn.prepareStatement(captureSql)
            ) {
                captureStmt.setInt(1, fScanId);

                Long captureId = null;

                try (ResultSet rs = captureStmt.executeQuery()) {
                    if (rs.next()) {
                        captureId = rs.getLong("id");
                    }
                }

                if (captureId == null) {
                    append("No TCP dump capture found for scan ID " + fScanId + ".");
                    return;
                }

                try (PreparedStatement stmt = conn.prepareStatement(suspectSql)) {
                    stmt.setInt(1, fScanId);
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

                final Long fCaptureId = captureId;

                SwingUtilities.invokeLater(() -> {
                    detailTableModel.setRowCount(0);
                    detailTableModel.setColumnIdentifiers(new String[]{
                            "Suspected IP",
                            "Distinct MAC Count",
                            "MAC List",
                            "Vendor List",
                            "ARP Event Count",
                            "Evidence Types"
                    });

                    for (Object[] row : rows) {
                        detailTableModel.addRow(row);
                    }

                    showTableOutput();
                });

                if (rows.isEmpty()) {
                    append("No duplicate IP suspects found for capture ID " + fCaptureId + ".");
                }

            } catch (Exception e) {
                append("DUP SUSPECT ERROR: " + e.getMessage());
            }

        }).start();
    }
    // ========================================
    // BLOCK 25 — DARK DEVICE DETECTION
    // ========================================
    public void showDarkDevices() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        new Thread(() -> {

            StringBuilder output = new StringBuilder();

            try (Connection conn = dbService.getConnection()) {

                String sql = """
                    SELECT 
                        a.observed_ip,
                        a.mac_address,
                        COALESCE(v.vendor_clean, v.vendor, 'Unknown') AS vendor,
                        a.rtt_ms,
                        a.response_type
                    FROM arp_bindings a
                    LEFT JOIN mac_oui_lookup v
                        ON LEFT(REGEXP_REPLACE(UPPER(a.mac_address), '[^0-9A-F]', '', 'g'), 6)
                         = LEFT(REGEXP_REPLACE(UPPER(v.oui),        '[^0-9A-F]', '', 'g'), 6)
                    WHERE a.scan_id = ?
                    AND a.response_type = 'arp-response'
                    ORDER BY a.rtt_ms NULLS LAST
                """;

                PreparedStatement stmt = conn.prepareStatement(sql);
                stmt.setInt(1, scanId);

                ResultSet rs = stmt.executeQuery();

                boolean found = false;

                output.append("=== DARK DEVICES (ARP ONLY) ===\n\n");
                output.append(String.format(
                        "%-15s | %-17s | %-20s | %-8s%n",
                        "IP", "MAC", "VENDOR", "RTT"
                ));
                output.append("-------------------------------------------------------------\n");

                while (rs.next()) {
                    found = true;

                    Object rttObj = rs.getObject("rtt_ms");

                    output.append(String.format(
                            "%-15s | %-17s | %-20s | %-8s%n",
                            rs.getString("observed_ip"),
                            rs.getString("mac_address"),
                            rs.getString("vendor"),
                            (rttObj != null ? String.format("%.3f", rs.getDouble("rtt_ms")) : "N/A")
                    ));
                }

                if (!found) {
                    output.append("No dark devices found.\n");
                }

                append(output.toString());

            } catch (Exception e) {
                append("DARK DEVICE ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 26 — START CAPTURE TIMER
    // ========================================
    private void startCaptureTimer() {

        stopExistingTimer();

        captureStatusLabel.setText("TCP Dump Running...");

        captureTimer = new javax.swing.Timer(1000, e -> {
            long elapsedSeconds = (System.currentTimeMillis() - captureStartMillis) / 1000L;
            long remainingSeconds = Math.max(0, captureDurationSeconds - elapsedSeconds);

            String elapsedText = formatDuration(elapsedSeconds);
            String remainingText = formatDuration(remainingSeconds);

            if (remainingSeconds > 0) {
                captureStatusLabel.setText("TCP Dump Running | Elapsed " + elapsedText + " | Remaining " + remainingText);
            } else {
                captureStatusLabel.setText("TCP Dump Finishing...");
            }
        });

        captureTimer.start();
    }

    // ========================================
    // BLOCK 27 — STOP CAPTURE TIMER
    // ========================================
    private void stopCaptureTimer(String finalStatus) {
        stopExistingTimer();
        captureStatusLabel.setText(finalStatus);
    }

    // ========================================
    // BLOCK 28 — STOP EXISTING TIMER
    // ========================================
    private void stopExistingTimer() {
        if (captureTimer != null) {
            captureTimer.stop();
            captureTimer = null;
        }
    }

    // ========================================
    // BLOCK 29 — FORMAT DURATION
    // ========================================
    private String formatDuration(long totalSeconds) {
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        return String.format("%02d:%02d", minutes, seconds);
    }
}