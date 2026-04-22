package dark_matter_scanner;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

// ========================================
// BLOCK 1 — MAIN APP
// ========================================
public class MainApp {

    private static class TopologyNode {
        final String ip;
        final String mac;
        final String vendor;
        final String roleHint;
        final double rtt;
        final String responseType;
        final int seenCount;
        final Timestamp lastSeen;

        TopologyNode(
                String ip,
                String mac,
                String vendor,
                String roleHint,
                double rtt,
                String responseType,
                int seenCount,
                Timestamp lastSeen
        ) {
            this.ip = ip;
            this.mac = mac;
            this.vendor = vendor;
            this.roleHint = roleHint;
            this.rtt = rtt;
            this.responseType = responseType;
            this.seenCount = seenCount;
            this.lastSeen = lastSeen;
        }
    }

    private static class DarkObservedNode {
        final String ip;
        final String mac;
        final String vendor;
        final int seenCount;
        final Timestamp lastSeen;

        DarkObservedNode(String ip, String mac, String vendor, int seenCount, Timestamp lastSeen) {
            this.ip = ip;
            this.mac = mac;
            this.vendor = vendor;
            this.seenCount = seenCount;
            this.lastSeen = lastSeen;
        }
    }

    // ========================================
    // BLOCK 2 — SERVICES
    // ========================================
    private final ScanExecutor executor = new ScanExecutor();
    private final DatabaseService dbService = new DatabaseService();
    private final TcpdumpParserService tcpdumpParserService = new TcpdumpParserService();
    private final FeatureAnalysisService featureAnalysisService = new FeatureAnalysisService(dbService);

    // ========================================
    // BLOCK 3 — TOP UI COMPONENTS
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
    private JComboBox<String> scanDurationDropdown;
    private JLabel captureStatusLabel;

    private ActionPanelManager actionPanelManager;

    // ========================================
    // BLOCK 4 — BOTTOM OUTPUT COMPONENTS
    // ========================================
    private CardLayout outputCardLayout;
    private JPanel outputCardPanel;
    private JTable detailTable;
    private DefaultTableModel detailTableModel;
    private TopologyGraphPanel topologyGraphPanel;

    // ========================================
    // BLOCK 5 — MIDDLE CONTEXT PANEL COMPONENTS
    // ========================================
    private CardLayout middleCardLayout;
    private JPanel middleCardPanel;
    private JLabel middleHeaderLabel;
    private JLabel captureBrowserHeaderLabel;
    private JTextArea middleInfoArea;

    private JTable captureListTable;
    private DefaultTableModel captureListTableModel;
    private JButton refreshCaptureListBtn;
    private JButton loadSelectedCaptureBtn;
    private JButton useLatestCaptureBtn;
    private JButton deleteSelectedCaptureBtn;
    private JPanel topologyControlsPanel;
    private JLabel topologyControlsHeaderLabel;
    private JLabel topologyStatsLabel;
    private JSlider topoMinSeenSlider;
    private JLabel topoMinSeenValueLabel;
    private JSlider topoTimeWindowSlider;
    private JLabel topoTimeWindowValueLabel;
    private JSlider topoPercentSlider;
    private JLabel topoPercentValueLabel;
    private JButton topoPercentLowestBtn;
    private JButton topoPercentDefaultBtn;
    private JButton topoPercentHighestBtn;
    private JSlider topoAbsoluteSlider;
    private JLabel topoAbsoluteValueLabel;
    private JSlider topoMinGroupSlider;
    private JLabel topoMinGroupValueLabel;
    private JSlider topoOutlierSlider;
    private JLabel topoOutlierValueLabel;
    private JSlider topoBridgeSlider;
    private JLabel topoBridgeValueLabel;
    private JSlider topoZoomSlider;
    private JLabel topoZoomValueLabel;
    private JTextField topoRouterOverrideField;
    private JButton topologyRebuildBtn;

    // ========================================
    // BLOCK 6 — SPLIT PANES
    // ========================================
    private JSplitPane topMiddleSplit;
    private JSplitPane mainVerticalSplit;

    // ========================================
    // BLOCK 7 — STATE
    // ========================================
    private Integer activeScanId = null;
    private boolean captureRunning = false;
    private long captureStartMillis = 0L;
    private javax.swing.Timer captureTimer = null;

    private Long activeCaptureId = null;
    private Integer activeCaptureScanId = null;

    private Integer browserScanId = null;
    private Long browserSelectedCaptureId = null;

    private ScanExecutor.RunningCapture liveCapture = null;
    private ScanExecutor.RunningCapture darkMonitorCapture = null;
    private List<TopologyNode> topologyNodes = new ArrayList<>();
    private List<DarkObservedNode> topologyDarkObservedNodes = new ArrayList<>();
    private Integer topologyScanId = null;
    private String topologyScanTargetHost = null;
    private String topologyScanSubnet = null;
    private String topologyRouterHintIp = null;
    private Integer activeScanAutoStopSeconds = null;
    private boolean autoStopTriggered = false;
    private boolean darkMonitorRunning = false;
    private String darkMonitorIp = null;

    private static final int TOPO_PERCENT_DEFAULT = 15;
    private static final int TOPOLOGY_ZOOM_DEFAULT = 100;
    private static final String ENRICHMENT_TCP_PORTS = "80,443,515,548,631,9100,137,138,139,445,111,2049";
    private static final String ENRICHMENT_UDP_PORTS = "161";
    private static final int ENRICHMENT_CHUNK_SIZE = 32;

    // ========================================
    // BLOCK 8 — MAIN ENTRY
    // ========================================
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new MainApp().initUI());
    }

    // ========================================
    // BLOCK 9 — UI SETUP
    // ========================================
    private void initUI() {

        frame = new JFrame("Dark Matter Scanner");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());
        Rectangle usableBounds = GraphicsEnvironment
                .getLocalGraphicsEnvironment()
                .getMaximumWindowBounds();
        frame.setBounds(usableBounds);
        frame.setMinimumSize(new Dimension(
                Math.min(1100, usableBounds.width),
                Math.min(760, usableBounds.height)
        ));

        JPanel top = new JPanel(new BorderLayout());
        JPanel topRow1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel topRow2 = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sshCheckbox = new JCheckBox("Use SSH");
        sshCheckbox.setSelected(true);

        sshUserField = new JTextField("root", 8);
        sshPassField = new JPasswordField("Water3mark@", 10);
        targetHostField = new JTextField("10.8.3.253", 12);

        subnetField = new JTextField("192.168.10.0/24", 15);
        ifaceDropdown = new JComboBox<>();

        JButton ifaceBtn = new JButton("Load Interfaces");
        ifaceBtn.addActionListener(e -> loadInterfaces());

        JButton deleteBtn = new JButton("Delete Selected");
        deleteBtn.addActionListener(e -> deleteSelectedScans());

        tcpdumpBtn = new JButton("Start Scan");
        tcpdumpBtn.addActionListener(e -> toggleScanWorkflow());

        scanDurationDropdown = new JComboBox<>(new String[]{
                "1 min",
                "2 min",
                "3 min",
                "4 min",
                "5 min",
                "Continuous"
        });
        scanDurationDropdown.setSelectedItem("5 min");

        captureStatusLabel = new JLabel("Scan Capture Idle");

        topRow1.add(sshCheckbox);
        topRow1.add(new JLabel("User:"));
        topRow1.add(sshUserField);
        topRow1.add(new JLabel("Pass:"));
        topRow1.add(sshPassField);
        topRow1.add(new JLabel("Target:"));
        topRow1.add(targetHostField);

        topRow1.add(new JLabel("Subnet:"));
        topRow1.add(subnetField);

        topRow2.add(ifaceBtn);
        topRow2.add(ifaceDropdown);
        topRow2.add(deleteBtn);
        topRow2.add(tcpdumpBtn);
        topRow2.add(new JLabel("Duration:"));
        topRow2.add(scanDurationDropdown);
        topRow2.add(captureStatusLabel);

        top.add(topRow1, BorderLayout.NORTH);
        top.add(topRow2, BorderLayout.CENTER);

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

        topologyGraphPanel = new TopologyGraphPanel();

        outputCardLayout = new CardLayout();
        outputCardPanel = new JPanel(outputCardLayout);
        outputCardPanel.add(new JScrollPane(outputArea), "TEXT");
        outputCardPanel.add(new JScrollPane(detailTable), "TABLE");
        outputCardPanel.add(new JScrollPane(topologyGraphPanel), "GRAPH");

        buildMiddlePanel();

        topMiddleSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(scanTable),
                middleCardPanel
        );
        topMiddleSplit.setResizeWeight(0.50);
        topMiddleSplit.setDividerLocation(260);

        mainVerticalSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                topMiddleSplit,
                outputCardPanel
        );
        mainVerticalSplit.setResizeWeight(0.60);
        mainVerticalSplit.setDividerLocation(520);

        actionPanelManager = new ActionPanelManager(this);

        frame.add(top, BorderLayout.NORTH);
        frame.add(actionPanelManager.getPanel(), BorderLayout.WEST);
        frame.add(mainVerticalSplit, BorderLayout.CENTER);

        frame.setVisible(true);

        showTextOutput();
        showMiddlePlaceholder(
                "Context Panel",
                "This middle section is reserved for context-specific controls.\n\n" +
                        "Example use:\n" +
                        "- TCP dump list for selected scan\n" +
                        "- Topology sliders / thresholds\n" +
                        "- View-specific action buttons"
        );
        loadHistory();
    }

    // ========================================
    // BLOCK 10 — BUILD MIDDLE PANEL
    // ========================================
    private void buildMiddlePanel() {

        middleHeaderLabel = new JLabel("Context Panel");
        middleHeaderLabel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));
        captureBrowserHeaderLabel = new JLabel("Capture Browser");
        captureBrowserHeaderLabel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        middleInfoArea = new JTextArea();
        middleInfoArea.setEditable(false);
        middleInfoArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JPanel placeholderPanel = new JPanel(new BorderLayout());
        placeholderPanel.add(middleHeaderLabel, BorderLayout.NORTH);
        placeholderPanel.add(new JScrollPane(middleInfoArea), BorderLayout.CENTER);

        captureListTableModel = new DefaultTableModel(
                new String[]{"Capture ID", "Status", "Method", "Host", "Interface", "Started", "Ended"},
                0
        ) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        captureListTable = new JTable(captureListTableModel);
        captureListTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        captureListTable.setAutoCreateRowSorter(true);
        captureListTable.setFillsViewportHeight(true);

        captureListTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = captureListTable.getSelectedRow();
                if (selectedRow >= 0) {
                    int modelRow = captureListTable.convertRowIndexToModel(selectedRow);
                    Object value = captureListTableModel.getValueAt(modelRow, 0);
                    if (value instanceof Number) {
                        browserSelectedCaptureId = ((Number) value).longValue();
                    } else if (value != null) {
                        browserSelectedCaptureId = Long.parseLong(value.toString());
                    }
                }
            }
        });

        JPanel captureBrowserPanel = new JPanel(new BorderLayout());
        captureBrowserPanel.add(new JScrollPane(captureListTable), BorderLayout.CENTER);

        JPanel captureCardWrapper = new JPanel(new BorderLayout());
        captureCardWrapper.add(captureBrowserHeaderLabel, BorderLayout.NORTH);
        captureCardWrapper.add(captureBrowserPanel, BorderLayout.CENTER);

        topologyControlsPanel = buildTopologyControlsPanel();

        middleCardLayout = new CardLayout();
        middleCardPanel = new JPanel(middleCardLayout);
        middleCardPanel.add(placeholderPanel, "PLACEHOLDER");
        middleCardPanel.add(captureCardWrapper, "CAPTURE_BROWSER");
        middleCardPanel.add(topologyControlsPanel, "TOPOLOGY_CONTROLS");
    }

    // ========================================
    // BLOCK 11 — SHOW MIDDLE PLACEHOLDER
    // ========================================
    private void showMiddlePlaceholder(String header, String body) {
        SwingUtilities.invokeLater(() -> {
            middleHeaderLabel.setText(header);
            middleInfoArea.setText(body);
            middleCardLayout.show(middleCardPanel, "PLACEHOLDER");
        });
    }

    // ========================================
    // BLOCK 12 — SHOW MIDDLE CAPTURE BROWSER
    // ========================================
    private void showMiddleCaptureBrowser(String header) {
        SwingUtilities.invokeLater(() -> {
            captureBrowserHeaderLabel.setText(header);
            middleCardLayout.show(middleCardPanel, "CAPTURE_BROWSER");
        });
    }

    private void showMiddleTopologyControls(String header) {
        SwingUtilities.invokeLater(() -> {
            topologyControlsHeaderLabel.setText(header);
            middleCardLayout.show(middleCardPanel, "TOPOLOGY_CONTROLS");
        });
    }

    private JPanel buildTopologyControlsPanel() {

        topologyControlsHeaderLabel = new JLabel("Topology Controls");
        topologyControlsHeaderLabel.setBorder(BorderFactory.createEmptyBorder(6, 8, 6, 8));

        JPanel controlGrid = new JPanel(new GridLayout(0, 1, 0, 6));

        topoZoomSlider = new JSlider(25, 150, TOPOLOGY_ZOOM_DEFAULT);
        topoZoomValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Topology Zoom %", topoZoomSlider, topoZoomValueLabel));

        topoMinSeenSlider = new JSlider(1, 25, 1);
        topoMinSeenValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Edge Strength (min seen-count)", topoMinSeenSlider, topoMinSeenValueLabel));

        topoTimeWindowSlider = new JSlider(0, 240, 0);
        topoTimeWindowValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Recent Window (minutes, 0=all)", topoTimeWindowSlider, topoTimeWindowValueLabel));

        topoPercentSlider = new JSlider(1, 50, TOPO_PERCENT_DEFAULT);
        topoPercentValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Cluster Percent Threshold", topoPercentSlider, topoPercentValueLabel));
        controlGrid.add(buildTopologyPercentPresetRow());

        topoAbsoluteSlider = new JSlider(10, 500, 150);
        topoAbsoluteValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Cluster Absolute Threshold (ms)", topoAbsoluteSlider, topoAbsoluteValueLabel));

        topoMinGroupSlider = new JSlider(1, 8, 2);
        topoMinGroupValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Minimum Group Size", topoMinGroupSlider, topoMinGroupValueLabel));

        topoOutlierSlider = new JSlider(100, 600, 250);
        topoOutlierValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Outlier Multiplier (x base RTT)", topoOutlierSlider, topoOutlierValueLabel));

        topoBridgeSlider = new JSlider(5, 400, 80);
        topoBridgeValueLabel = new JLabel();
        controlGrid.add(buildSliderRow("Bridge Sensitivity (max gap ms)", topoBridgeSlider, topoBridgeValueLabel));

        topoRouterOverrideField = new JTextField(14);
        topoRouterOverrideField.setToolTipText("Optional: force router anchor IP (example: 192.168.10.1)");
        JPanel routerOverrideRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        routerOverrideRow.add(new JLabel("Router IP Override:"));
        routerOverrideRow.add(topoRouterOverrideField);
        controlGrid.add(routerOverrideRow);

        topologyRebuildBtn = new JButton("Rebuild Topology from DB");
        topologyRebuildBtn.addActionListener(e -> {
            Integer scanId = getSelectedScanId();
            if (scanId == null) {
                append("Select a scan first.");
                return;
            }
            topologyScanId = scanId;
            loadTopologyNodes(scanId);
        });

        topologyStatsLabel = new JLabel("Load topology data to begin.");
        topologyStatsLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JPanel footerButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        footerButtons.add(topologyRebuildBtn);

        JPanel content = new JPanel(new BorderLayout());
        content.add(controlGrid, BorderLayout.NORTH);
        content.add(topologyStatsLabel, BorderLayout.CENTER);
        content.add(footerButtons, BorderLayout.SOUTH);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.add(topologyControlsHeaderLabel, BorderLayout.NORTH);
        wrapper.add(new JScrollPane(content), BorderLayout.CENTER);

        javax.swing.event.ChangeListener listener = e -> {
            refreshTopologyControlLabels();
            rebuildTopologyGraphFromControls();
        };

        topoMinSeenSlider.addChangeListener(listener);
        topoTimeWindowSlider.addChangeListener(listener);
        topoPercentSlider.addChangeListener(listener);
        topoAbsoluteSlider.addChangeListener(listener);
        topoMinGroupSlider.addChangeListener(listener);
        topoOutlierSlider.addChangeListener(listener);
        topoBridgeSlider.addChangeListener(listener);
        topoZoomSlider.addChangeListener(listener);

        refreshTopologyControlLabels();
        return wrapper;
    }

    private JPanel buildSliderRow(String label, JSlider slider, JLabel valueLabel) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.add(new JLabel(label), BorderLayout.NORTH);
        row.add(slider, BorderLayout.CENTER);
        row.add(valueLabel, BorderLayout.EAST);
        return row;
    }

    private JPanel buildTopologyPercentPresetRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT));

        topoPercentLowestBtn = new JButton("Lowest");
        topoPercentLowestBtn.addActionListener(e -> topoPercentSlider.setValue(topoPercentSlider.getMinimum()));

        topoPercentDefaultBtn = new JButton("Default");
        topoPercentDefaultBtn.addActionListener(e -> topoPercentSlider.setValue(TOPO_PERCENT_DEFAULT));

        topoPercentHighestBtn = new JButton("Highest");
        topoPercentHighestBtn.addActionListener(e -> topoPercentSlider.setValue(topoPercentSlider.getMaximum()));

        row.add(new JLabel("Cluster % quick set:"));
        row.add(topoPercentLowestBtn);
        row.add(topoPercentDefaultBtn);
        row.add(topoPercentHighestBtn);

        return row;
    }

    private void refreshTopologyControlLabels() {
        topoMinSeenValueLabel.setText(String.valueOf(topoMinSeenSlider.getValue()));

        int minutes = topoTimeWindowSlider.getValue();
        topoTimeWindowValueLabel.setText(minutes == 0 ? "All" : (minutes + " min"));

        topoPercentValueLabel.setText(String.format("%.1f%%", topoPercentSlider.getValue() / 1.0));
        topoAbsoluteValueLabel.setText(String.format("%.3f", topoAbsoluteSlider.getValue() / 1000.0));
        topoMinGroupValueLabel.setText(String.valueOf(topoMinGroupSlider.getValue()));
        topoOutlierValueLabel.setText(String.format("%.2fx", topoOutlierSlider.getValue() / 100.0));
        topoBridgeValueLabel.setText(String.format("%.3f", topoBridgeSlider.getValue() / 1000.0));
        topoZoomValueLabel.setText(topoZoomSlider.getValue() + "%");
        topologyGraphPanel.setZoomFactor(topoZoomSlider.getValue() / 100.0);
    }

    // ========================================
    // BLOCK 13 — LOAD INTERFACES
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
    // BLOCK 14 — PARSE INTERFACES
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
    // BLOCK 15 — START SCAN
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
            final boolean fSsh = sshUsed;
            final String fTarget = targetHost;
            final int fScanId = scanId;

            new Thread(() -> runDiscoveryScan(fSubnet, fSsh, fTarget, fScanId)).start();

        } catch (Exception e) {
            append("ERROR: " + e.getMessage());
        }
    }

    private void startScanWithLiveCapture() {

        if (captureRunning) {
            append("A TCP dump capture is already running. Stop it before starting combined mode.");
            return;
        }

        try {
            String subnet = subnetField.getText().trim();

            if (subnet.isEmpty()) {
                append("Enter a subnet first.");
                return;
            }

            String ifaceValue = (String) ifaceDropdown.getSelectedItem();
            if (ifaceValue == null || !ifaceValue.contains(" - ")) {
                append("Load interfaces and select one first.");
                return;
            }

            String ifaceName = ifaceValue.split(" - ")[0].trim();

            boolean sshUsed = sshCheckbox.isSelected();
            String targetHost = sshUsed ? targetHostField.getText().trim() : "local";
            Integer autoStopSeconds = getSelectedScanDurationSeconds();

            int scanId = dbService.createScanRun(subnet, ifaceName, targetHost, sshUsed);
            activeScanId = scanId;
            activeScanAutoStopSeconds = autoStopSeconds;
            autoStopTriggered = false;

            String durationText = (autoStopSeconds == null)
                    ? "continuous"
                    : ((autoStopSeconds / 60) + " min");
            append("Scan started ID=" + scanId + " (capture " + durationText + ").");
            SwingUtilities.invokeLater(this::loadHistory);

            final String fSubnet = subnet;
            final String fIfaceName = ifaceName;
            final boolean fSsh = sshUsed;
            final String fTarget = targetHost;
            final int fScanId = scanId;

            new Thread(() -> runDiscoveryWithLiveCapture(fSubnet, fIfaceName, fSsh, fTarget, fScanId)).start();

        } catch (Exception e) {
            append("SCAN START ERROR: " + e.getMessage());
        }
    }

    private Integer getSelectedScanDurationSeconds() {
        if (scanDurationDropdown == null) {
            return null;
        }

        Object selected = scanDurationDropdown.getSelectedItem();
        if (selected == null) {
            return null;
        }

        String value = selected.toString().trim().toLowerCase();
        if (value.startsWith("continuous")) {
            return null;
        }

        if (value.endsWith("min")) {
            String minutesText = value.replace("min", "").trim();
            try {
                int minutes = Integer.parseInt(minutesText);
                if (minutes > 0) {
                    return minutes * 60;
                }
            } catch (NumberFormatException ignored) {
            }
        }

        return null;
    }

    private void runDiscoveryWithLiveCapture(String subnet, String ifaceName, boolean sshUsed, String targetHost, int scanId) {
        try {
            append("Starting TCP dump first (scan ID " + scanId + ")...");
            startTcpdumpCaptureForScan(scanId, ifaceName, sshUsed, targetHost);

            if (!waitForCaptureStart(scanId, 15000)) {
                append("Combined workflow aborted: TCP dump did not start in time.");
                return;
            }

            append("TCP dump is running. Starting Nmap scan...");
            runDiscoveryScan(subnet, sshUsed, targetHost, scanId, false);
            append("Nmap phase complete. Capture continues until Stop Scan.");

        } catch (Exception e) {
            append("SCAN WORKFLOW ERROR: " + e.getMessage());
        }
    }

    private boolean waitForCaptureStart(int scanId, long timeoutMillis) {
        long start = System.currentTimeMillis();

        while ((System.currentTimeMillis() - start) < timeoutMillis) {
            if (captureRunning
                    && activeCaptureScanId != null
                    && activeCaptureScanId == scanId
                    && liveCapture != null) {
                return true;
            }

            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }

        return false;
    }

    // ========================================
    // BLOCK 16 — DISCOVERY SCAN
    // ========================================
    private void runDiscoveryScan(String subnet, boolean sshUsed, String targetHost, int scanId) {
        runDiscoveryScan(subnet, sshUsed, targetHost, scanId, true);
    }

    private void runDiscoveryScan(String subnet, boolean sshUsed, String targetHost, int scanId, boolean logCompletion) {

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

            if (logCompletion) {
                append("Scan complete.");
            }

        } catch (Exception e) {
            append("SCAN ERROR: " + e.getMessage());
        }
    }

    // ========================================
    // BLOCK 17 — PARSE ARP
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

                if (ip != null && !ip.isBlank()) {
                    dbService.upsertArpBinding(scanId, ip, mac, "active_arp", rtt, responseType);
                }
            }

        } catch (Exception e) {
            append("PARSE ERROR: " + e.getMessage());
        }
    }

    // ========================================
    // BLOCK 18 — LOAD HISTORY
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
    // BLOCK 19 — DELETE SCANS
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
    // BLOCK 20 — GET SELECTED SCAN ID
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
    // BLOCK 21 — RTT CLUSTERS
    // ========================================
    public void showRttClusters() {

        clearOutput();
        showMiddlePlaceholder(
                "RTT Cluster Context",
                "This middle section is available for RTT controls.\n\n" +
                        "Suggested next step:\n" +
                        "- Add slider for percent threshold\n" +
                        "- Add slider for absolute threshold\n" +
                        "- Add re-cluster button"
        );

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
    // BLOCK 22 — APPEND OUTPUT
    // ========================================
    private void append(String msg) {
        SwingUtilities.invokeLater(() -> {
            showTextOutput();
            outputArea.append(msg + "\n");
        });
    }

    // ========================================
    // BLOCK 23 — DUPLICATE IP DETECTION
    // ========================================
    public void showDuplicateIPs() {

        clearOutput();
        showMiddlePlaceholder(
                "Duplicate IP Context",
                "This middle panel can later hold duplicate-IP filters,\n" +
                        "capture selectors, or compare buttons."
        );

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
    // BLOCK 24 — TOGGLE TCPDUMP CAPTURE
    // ========================================
    private void toggleScanWorkflow() {
        if (captureRunning) {
            stopTcpdumpCapture();
        } else {
            startScanWithLiveCapture();
        }
    }

    private void startTcpdumpCaptureForScan(
            Integer explicitScanId,
            String explicitIfaceName,
            Boolean explicitSshUsed,
            String explicitTargetHost
    ) {
        Integer selectedScanId = explicitScanId;
        if (selectedScanId == null) {
            selectedScanId = getSelectedScanId();
            if (selectedScanId == null) {
                selectedScanId = activeScanId;
            }
        }

        if (selectedScanId == null) {
            append("Select a scan first, or run a scan first.");
            return;
        }

        String ifaceName = explicitIfaceName;
        if (ifaceName == null || ifaceName.isBlank()) {
            String ifaceValue = (String) ifaceDropdown.getSelectedItem();
            if (ifaceValue == null || !ifaceValue.contains(" - ")) {
                append("Load interfaces and select one first.");
                return;
            }
            ifaceName = ifaceValue.split(" - ")[0].trim();
        }

        boolean sshUsed = explicitSshUsed != null ? explicitSshUsed : sshCheckbox.isSelected();
        String captureMethod = sshUsed ? "ssh" : "local";
        String captureHost = sshUsed
                ? ((explicitTargetHost != null && !explicitTargetHost.isBlank()) ? explicitTargetHost : targetHostField.getText().trim())
                : "local";

        final int fScanId = selectedScanId;
        final String fIfaceName = ifaceName;
        final boolean fSsh = sshUsed;
        final String fCaptureMethod = captureMethod;
        final String fCaptureHost = captureHost;

        SwingUtilities.invokeLater(() -> tcpdumpBtn.setEnabled(false));

        new Thread(() -> {

            long captureId = -1L;

            try {
                append("Starting TCP dump capture on " + fIfaceName + "...");

                captureId = dbService.createTcpdumpCapture(
                        fScanId,
                        fCaptureMethod,
                        fCaptureHost,
                        fIfaceName,
                        "no-filter",
                        0
                );

                if (fSsh) {
                    liveCapture = executor.startSSHStreaming(
                            fCaptureHost,
                            sshUserField.getText().trim(),
                            new String(sshPassField.getPassword()),
                            "exec tcpdump -l -i " + fIfaceName + " -nn -e",
                            this::append
                    );
                } else {
                    liveCapture = executor.startLocalStreaming(
                            List.of("sh", "-c", "exec sudo tcpdump -l -i " + fIfaceName + " -nn -e"),
                            this::append
                    );
                }

                activeCaptureId = captureId;
                activeCaptureScanId = fScanId;
                captureRunning = true;
                captureStartMillis = System.currentTimeMillis();

                SwingUtilities.invokeLater(() -> {
                    tcpdumpBtn.setText("Stop Scan");
                    tcpdumpBtn.setEnabled(true);
                    startCaptureTimer();
                });

                append("TCP dump started. Capture ID=" + captureId);

            } catch (Exception e) {
                final long fCaptureId = captureId;

                try {
                    if (fCaptureId > 0) {
                        dbService.failTcpdumpCapture(fCaptureId, e.getMessage());
                    }
                } catch (Exception ignored) {
                }

                liveCapture = null;
                activeCaptureId = null;
                activeCaptureScanId = null;
                captureRunning = false;
                activeScanAutoStopSeconds = null;
                autoStopTriggered = false;

                SwingUtilities.invokeLater(() -> {
                    stopCaptureTimer("Scan Failed");
                    tcpdumpBtn.setText("Start Scan");
                    tcpdumpBtn.setEnabled(true);
                });

                append("TCPDUMP START ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 26 — STOP TCPDUMP CAPTURE
    // ========================================
    private void stopTcpdumpCapture() {

        if (!captureRunning || activeCaptureId == null || activeCaptureScanId == null || liveCapture == null) {
            append("No active scan capture is currently running.");
            return;
        }

        final long fCaptureId = activeCaptureId;
        final int fScanId = activeCaptureScanId;
        final ScanExecutor.RunningCapture fLiveCapture = liveCapture;
        autoStopTriggered = true;

        SwingUtilities.invokeLater(() -> tcpdumpBtn.setEnabled(false));

        new Thread(() -> {
            try {
                append("Stopping TCP dump capture...");

                long commandStart = System.currentTimeMillis();
                append("TCPDUMP STOP COMMAND STARTED");

                fLiveCapture.stop();

                long waitStart = System.currentTimeMillis();
                while (fLiveCapture.isRunning() && (System.currentTimeMillis() - waitStart) < 5000) {
                    Thread.sleep(100);
                }

                String output = fLiveCapture.getOutput();

                long commandEnd = System.currentTimeMillis();
                append("TCPDUMP STOP COMMAND RETURNED after " + ((commandEnd - commandStart) / 1000.0) + " seconds");

                dbService.completeTcpdumpCapture(fCaptureId, output);

                long parseStart = System.currentTimeMillis();
                append("TCPDUMP PARSE STARTED");

                int inserted = parseAndStoreTcpdumpArp(fScanId, fCaptureId, output);

                long parseEnd = System.currentTimeMillis();
                append("TCPDUMP PARSE FINISHED after " + ((parseEnd - parseStart) / 1000.0) + " seconds");

                append("TCP dump complete. Capture ID=" + fCaptureId + " | Parsed rows=" + inserted);

                long enrichmentStart = System.currentTimeMillis();
                append("POST-CAPTURE ENRICHMENT STARTED");
                runPostCaptureEnrichment(fScanId);
                long enrichmentEnd = System.currentTimeMillis();
                append("POST-CAPTURE ENRICHMENT FINISHED after " + ((enrichmentEnd - enrichmentStart) / 1000.0) + " seconds");

                liveCapture = null;
                activeCaptureId = null;
                activeCaptureScanId = null;
                captureRunning = false;
                activeScanAutoStopSeconds = null;
                autoStopTriggered = false;

                SwingUtilities.invokeLater(() -> {
                    stopCaptureTimer("Scan Stopped");
                    tcpdumpBtn.setText("Start Scan");
                    tcpdumpBtn.setEnabled(true);
                });

                loadLatestTcpdumpCaptureForScan(fScanId);

            } catch (Exception e) {
                try {
                    dbService.failTcpdumpCapture(fCaptureId, e.getMessage());
                } catch (Exception ignored) {
                }

                liveCapture = null;
                activeCaptureId = null;
                activeCaptureScanId = null;
                captureRunning = false;
                activeScanAutoStopSeconds = null;
                autoStopTriggered = false;

                SwingUtilities.invokeLater(() -> {
                    stopCaptureTimer("Scan Failed");
                    tcpdumpBtn.setText("Start Scan");
                    tcpdumpBtn.setEnabled(true);
                });

                append("TCPDUMP STOP ERROR: " + e.getMessage());
            }
        }).start();
    }

    // ========================================
    // BLOCK 27 — PARSE AND STORE TCPDUMP ARP
    // ========================================
    private int parseAndStoreTcpdumpArp(int scanId, long captureId, String rawOutput) throws Exception {

        List<TcpdumpParserService.MacObservationRecord> rows =
                tcpdumpParserService.parseArpObservations(scanId, captureId, rawOutput);

        append("TCPDUMP PARSE MATCHES FOUND: " + rows.size());

        if (rows.isEmpty()) {
            return 0;
        }

        int insertedRows = dbService.insertMacObservationsBatch(rows);
        int promotedRows = dbService.upsertPassiveArpBindingsFromObservations(scanId, rows);
        int promotedIpv4Rows = dbService.upsertPassiveIpv4BindingsFromObservations(scanId, rows);
        append("TCPDUMP KNOWN-NODE PROMOTIONS: " + promotedRows);
        append("TCPDUMP IPV4 KNOWN-NODE PROMOTIONS: " + promotedIpv4Rows);
        return insertedRows;
    }

    private void runPostCaptureEnrichment(int scanId) {
        try {
            ScanRunContext context = loadScanRunContext(scanId);
            if (context == null) {
                append("ENRICHMENT SKIPPED: scan context not found.");
                return;
            }

            List<DatabaseService.NodeAddress> nodeAddresses = dbService.loadScanNodeAddresses(scanId);
            Map<String, String> ipToMac = new HashMap<>();
            Map<String, String> ipToVendor = new HashMap<>();
            List<String> targets = new ArrayList<>();

            for (DatabaseService.NodeAddress node : nodeAddresses) {
                if (node == null || !isDottedQuadIp(node.observedIp)) {
                    continue;
                }

                String ip = node.observedIp.trim();
                targets.add(ip);
                if (node.macAddress != null && !node.macAddress.isBlank()) {
                    ipToMac.put(ip, node.macAddress.trim().toUpperCase());
                }
                if (node.vendor != null && !node.vendor.isBlank()) {
                    ipToVendor.put(ip, node.vendor.trim());
                }
            }

            if (targets.isEmpty()) {
                append("ENRICHMENT SKIPPED: no discovered IP targets.");
                dbService.clearServiceObservationsForScan(scanId);
                dbService.clearNodeClassificationsForScan(scanId);
                return;
            }

            dbService.clearServiceObservationsForScan(scanId);
            dbService.clearNodeClassificationsForScan(scanId);

            List<DatabaseService.ServiceObservationRecord> serviceRows = new ArrayList<>();

            for (List<String> chunk : chunkList(targets, ENRICHMENT_CHUNK_SIZE)) {
                append("ENRICHMENT CHUNK: probing " + chunk.size() + " hosts");
                try {
                    appendProbeRowsForChunk(scanId, context, chunk, ipToMac, serviceRows);
                } catch (Exception e) {
                    append("ENRICHMENT CHUNK ERROR: " + e.getMessage());
                }
            }

            int insertedServiceRows = dbService.upsertServiceObservationsBatch(serviceRows);
            append("ENRICHMENT SERVICE ROWS: " + insertedServiceRows);

            List<DatabaseService.TrafficRoleHint> trafficRoleHints = dbService.loadTrafficRoleHintsForScan(scanId);
            List<DatabaseService.NodeClassificationRecord> classRows =
                    buildClassifications(scanId, targets, ipToMac, ipToVendor, serviceRows, trafficRoleHints);
            int insertedClassRows = dbService.upsertNodeClassificationsBatch(classRows);
            append("ENRICHMENT CLASSIFICATION ROWS: " + insertedClassRows);

        } catch (Exception e) {
            append("ENRICHMENT ERROR: " + e.getMessage());
        }
    }

    private ScanRunContext loadScanRunContext(int scanId) throws Exception {
        String sql = """
            SELECT subnet, target_host, ssh_used
            FROM scan_runs
            WHERE id = ?
        """;

        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)
        ) {
            stmt.setInt(1, scanId);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return new ScanRunContext(
                            rs.getString("subnet"),
                            rs.getString("target_host"),
                            rs.getBoolean("ssh_used")
                    );
                }
            }
        }

        return null;
    }

    private String runServiceProbeChunk(ScanRunContext context, List<String> ips) throws Exception {
        if (ips == null || ips.isEmpty()) {
            return "";
        }

        if (context.sshUsed) {
            String joinedIps = String.join(" ", ips);
            String cmd = "nmap -sT -Pn -n --open -sV --version-light -p "
                    + ENRICHMENT_TCP_PORTS
                    + " -oX - "
                    + joinedIps;

            return executor.runSSH(
                    context.targetHost,
                    sshUserField.getText().trim(),
                    new String(sshPassField.getPassword()),
                    cmd
            );
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("nmap");
        cmd.add("-sT");
        cmd.add("-Pn");
        cmd.add("-n");
        cmd.add("--open");
        cmd.add("-sV");
        cmd.add("--version-light");
        cmd.add("-p");
        cmd.add(ENRICHMENT_TCP_PORTS);
        cmd.add("-oX");
        cmd.add("-");
        cmd.addAll(ips);
        return executor.runLocal(cmd);
    }

    private String runUdpPrinterProbeChunk(ScanRunContext context, List<String> ips) throws Exception {
        if (ips == null || ips.isEmpty()) {
            return "";
        }

        if (context.sshUsed) {
            String joinedIps = String.join(" ", ips);
            String cmd = "nmap -sU -Pn -n --open --version-light -p "
                    + ENRICHMENT_UDP_PORTS
                    + " -oX - "
                    + joinedIps;

            return executor.runSSH(
                    context.targetHost,
                    sshUserField.getText().trim(),
                    new String(sshPassField.getPassword()),
                    cmd
            );
        }

        List<String> cmd = new ArrayList<>();
        cmd.add("nmap");
        cmd.add("-sU");
        cmd.add("-Pn");
        cmd.add("-n");
        cmd.add("--open");
        cmd.add("--version-light");
        cmd.add("-p");
        cmd.add(ENRICHMENT_UDP_PORTS);
        cmd.add("-oX");
        cmd.add("-");
        cmd.addAll(ips);
        return executor.runLocal(cmd);
    }

    private void appendProbeRowsForChunk(
            int scanId,
            ScanRunContext context,
            List<String> chunk,
            Map<String, String> ipToMac,
            List<DatabaseService.ServiceObservationRecord> outRows
    ) throws Exception {
        try {
            String tcpXml = runServiceProbeChunk(context, chunk);
            List<ServiceProbeResult> tcpRows = parseServiceProbeXml(tcpXml);
            append("ENRICHMENT TCP SERVICES FOUND: " + tcpRows.size());
            for (ServiceProbeResult result : tcpRows) {
                if (!isDottedQuadIp(result.observedIp)) {
                    continue;
                }
                String mac = ipToMac.get(result.observedIp);
                outRows.add(new DatabaseService.ServiceObservationRecord(
                        scanId,
                        result.observedIp,
                        mac,
                        result.transport,
                        result.port,
                        result.state,
                        result.serviceName,
                        result.product,
                        result.version,
                        result.extraInfo,
                        "nmap_sV"
                ));
            }
        } catch (Exception e) {
            append("ENRICHMENT TCP PROBE ERROR: " + e.getMessage());
        }

        try {
            String udpXml = runUdpPrinterProbeChunk(context, chunk);
            List<ServiceProbeResult> udpRows = parseServiceProbeXml(udpXml);
            append("ENRICHMENT UDP SERVICES FOUND: " + udpRows.size());
            for (ServiceProbeResult result : udpRows) {
                if (!isDottedQuadIp(result.observedIp)) {
                    continue;
                }
                String mac = ipToMac.get(result.observedIp);
                outRows.add(new DatabaseService.ServiceObservationRecord(
                        scanId,
                        result.observedIp,
                        mac,
                        result.transport,
                        result.port,
                        result.state,
                        result.serviceName,
                        result.product,
                        result.version,
                        result.extraInfo,
                        "nmap_sV"
                ));
            }
        } catch (Exception e) {
            append("ENRICHMENT UDP PROBE ERROR: " + e.getMessage());
        }
    }

    private List<ServiceProbeResult> parseServiceProbeXml(String xml) {
        List<ServiceProbeResult> rows = new ArrayList<>();

        if (xml == null || xml.isBlank()) {
            return rows;
        }

        try {
            javax.xml.parsers.DocumentBuilderFactory factory =
                    javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc =
                    builder.parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));

            org.w3c.dom.NodeList hosts = doc.getElementsByTagName("host");

            for (int i = 0; i < hosts.getLength(); i++) {
                org.w3c.dom.Element host = (org.w3c.dom.Element) hosts.item(i);
                String ip = extractHostIpv4(host);
                if (!isDottedQuadIp(ip)) {
                    continue;
                }

                org.w3c.dom.NodeList ports = host.getElementsByTagName("port");
                for (int j = 0; j < ports.getLength(); j++) {
                    org.w3c.dom.Element portElem = (org.w3c.dom.Element) ports.item(j);

                    String portIdText = portElem.getAttribute("portid");
                    int port;
                    try {
                        port = Integer.parseInt(portIdText);
                    } catch (NumberFormatException e) {
                        continue;
                    }

                    String transport = portElem.getAttribute("protocol");

                    String state = "unknown";
                    org.w3c.dom.NodeList stateNodes = portElem.getElementsByTagName("state");
                    if (stateNodes.getLength() > 0) {
                        org.w3c.dom.Element stateElem = (org.w3c.dom.Element) stateNodes.item(0);
                        state = stateElem.getAttribute("state");
                    }

                    if (!"open".equalsIgnoreCase(state)) {
                        continue;
                    }

                    String serviceName = null;
                    String product = null;
                    String version = null;
                    String extraInfo = null;

                    org.w3c.dom.NodeList serviceNodes = portElem.getElementsByTagName("service");
                    if (serviceNodes.getLength() > 0) {
                        org.w3c.dom.Element serviceElem = (org.w3c.dom.Element) serviceNodes.item(0);
                        serviceName = serviceElem.getAttribute("name");
                        product = serviceElem.getAttribute("product");
                        version = serviceElem.getAttribute("version");
                        extraInfo = serviceElem.getAttribute("extrainfo");
                    }

                    rows.add(new ServiceProbeResult(
                            ip,
                            transport,
                            port,
                            state,
                            nullIfBlank(serviceName),
                            nullIfBlank(product),
                            nullIfBlank(version),
                            nullIfBlank(extraInfo)
                    ));
                }
            }

        } catch (Exception e) {
            append("ENRICHMENT PARSE ERROR: " + e.getMessage());
        }

        return rows;
    }

    private String extractHostIpv4(org.w3c.dom.Element hostElem) {
        org.w3c.dom.NodeList addresses = hostElem.getElementsByTagName("address");
        for (int i = 0; i < addresses.getLength(); i++) {
            org.w3c.dom.Element addr = (org.w3c.dom.Element) addresses.item(i);
            if ("ipv4".equalsIgnoreCase(addr.getAttribute("addrtype"))) {
                return addr.getAttribute("addr");
            }
        }
        return null;
    }

    private List<DatabaseService.NodeClassificationRecord> buildClassifications(
            int scanId,
            List<String> allTargets,
            Map<String, String> ipToMac,
            Map<String, String> ipToVendor,
            List<DatabaseService.ServiceObservationRecord> services,
            List<DatabaseService.TrafficRoleHint> trafficRoleHints
    ) {
        Map<String, NodeServiceProfile> profileByIp = new HashMap<>();
        Map<String, DatabaseService.TrafficRoleHint> roleHintByIp = new HashMap<>();

        for (DatabaseService.ServiceObservationRecord row : services) {
            if (row == null || !isDottedQuadIp(row.observedIp)) {
                continue;
            }
            if (!"open".equalsIgnoreCase(row.state)) {
                continue;
            }

            NodeServiceProfile profile = profileByIp.computeIfAbsent(
                    row.observedIp,
                    k -> new NodeServiceProfile()
            );
            profile.openPorts.add(row.port);
            if (row.serviceName != null && !row.serviceName.isBlank()) {
                profile.serviceNames.add(row.serviceName.toLowerCase());
            }
        }

        if (trafficRoleHints != null) {
            for (DatabaseService.TrafficRoleHint hint : trafficRoleHints) {
                if (hint == null || !isDottedQuadIp(hint.observedIp)) {
                    continue;
                }
                roleHintByIp.put(hint.observedIp, hint);
            }
        }

        List<DatabaseService.NodeClassificationRecord> classRows = new ArrayList<>();

        for (String ip : allTargets) {
            NodeServiceProfile profile = profileByIp.getOrDefault(ip, new NodeServiceProfile());
            String mac = ipToMac.get(ip);
            String vendor = ipToVendor.getOrDefault(ip, "");
            String vendorLower = vendor.toLowerCase();
            boolean metadataCriticalInfra = isCriticalInfrastructureMac(mac);
            boolean vendorLooksPrinter = vendorLower.contains("hp")
                    || vendorLower.contains("hewlett")
                    || vendorLower.contains("brother")
                    || vendorLower.contains("epson")
                    || vendorLower.contains("canon")
                    || vendorLower.contains("lexmark")
                    || vendorLower.contains("xerox")
                    || vendorLower.contains("ricoh")
                    || vendorLower.contains("kyocera")
                    || vendorLower.contains("zebra")
                    || vendorLower.contains("konica");

            boolean has445 = profile.openPorts.contains(445);
            boolean has139 = profile.openPorts.contains(139);
            boolean has137 = profile.openPorts.contains(137);
            boolean has138 = profile.openPorts.contains(138);
            boolean hasDirectPrinterPort = profile.openPorts.contains(9100)
                    || profile.openPorts.contains(631)
                    || profile.openPorts.contains(515);
            boolean hasSnmp = profile.openPorts.contains(161);
            boolean hasNfs = profile.openPorts.contains(2049) || profile.openPorts.contains(111);
            boolean hasAfp = profile.openPorts.contains(548);
            boolean serviceLooksPrinter = containsAny(profile.serviceNames,
                    "ipp", "printer", "pdl-datastream", "jetdirect", "hplip");
            boolean serviceLooksFileServer = containsAny(profile.serviceNames,
                    "microsoft-ds", "netbios-ssn", "nfs", "mountd", "afpovertcp");
            boolean vendorLooksNas = containsAny(vendorLower,
                    "synology", "qnap", "netapp", "truenas", "freenas", "asustor", "buffalo");
            boolean vendorLooksInfra = containsAny(vendorLower,
                    "ubiquiti", "aruba", "cisco", "juniper", "mikrotik", "fortinet", "ruckus")
                    || metadataCriticalInfra;

            DatabaseService.TrafficRoleHint traffic = roleHintByIp.get(ip);
            String inferredTrafficRole = inferTrafficRole(traffic);

            if (metadataCriticalInfra) {
                classRows.add(new DatabaseService.NodeClassificationRecord(
                        scanId,
                        ip,
                        mac,
                        "infrastructure_device",
                        "high",
                        0.95,
                        buildEvidenceJson(profile, "oui-metadata-critical-infrastructure"),
                        "v1",
                        "rule_engine"
                ));
            }

            if (inferredTrafficRole != null) {
                String roleName;
                if (vendorLower.contains("ubiquiti")) {
                    roleName = "ubiquiti_" + inferredTrafficRole;
                } else {
                    roleName = "traffic_" + inferredTrafficRole;
                }
                String confidence = "mixed".equals(inferredTrafficRole) ? "medium" : "high";
                double score = "mixed".equals(inferredTrafficRole) ? 0.72 : 0.88;

                classRows.add(new DatabaseService.NodeClassificationRecord(
                        scanId,
                        ip,
                        mac,
                        roleName,
                        confidence,
                        score,
                        buildTrafficEvidenceJson(traffic, "flow-direction-" + inferredTrafficRole),
                        "v1",
                        "rule_engine"
                ));
            }

            if ((hasDirectPrinterPort || serviceLooksPrinter || (vendorLooksPrinter && hasSnmp))
                    && !vendorLooksInfra) {
                String confidence;
                double score;
                String reason;
                if (profile.openPorts.contains(9100) || profile.openPorts.contains(631) || serviceLooksPrinter) {
                    confidence = "high";
                    score = 0.92;
                    reason = "direct-printer-service-signals";
                } else if (profile.openPorts.contains(515) || (vendorLooksPrinter && hasSnmp)) {
                    confidence = "medium";
                    score = 0.70;
                    reason = "snmp-lpr-or-printer-vendor";
                } else {
                    confidence = "low";
                    score = 0.45;
                    reason = "weak-printer-signals";
                }

                classRows.add(new DatabaseService.NodeClassificationRecord(
                        scanId,
                        ip,
                        mac,
                        "printer",
                        confidence,
                        score,
                        buildEvidenceJson(profile, reason),
                        "v1",
                        "rule_engine"
                ));
            }

            if ((has445 && (has139 || has137 || has138))
                    || ((has445 || hasNfs || hasAfp) && vendorLooksNas)
                    || (hasNfs && hasAfp)
                    || (has445 && serviceLooksFileServer)) {
                String confidence = ((has445 && (has139 || has137 || has138)) || (vendorLooksNas && (has445 || hasNfs)))
                        ? "high"
                        : "medium";
                double score = "high".equals(confidence) ? 0.90 : 0.72;
                String reason = vendorLooksNas
                        ? "nas-vendor-and-file-service-signals"
                        : "file-service-port-signals";

                classRows.add(new DatabaseService.NodeClassificationRecord(
                        scanId,
                        ip,
                        mac,
                        "file_server",
                        confidence,
                        score,
                        buildEvidenceJson(profile, reason),
                        "v1",
                        "rule_engine"
                ));
            } else if (has445 || has139) {
                classRows.add(new DatabaseService.NodeClassificationRecord(
                        scanId,
                        ip,
                        mac,
                        "windows_host",
                        "medium",
                        0.65,
                        buildEvidenceJson(profile, "smb-or-netbios-signals"),
                        "v1",
                        "rule_engine"
                ));
            }
        }

        return classRows;
    }

    private String inferTrafficRole(DatabaseService.TrafficRoleHint hint) {
        if (hint == null) {
            return null;
        }

        int out = Math.max(0, hint.outboundFrames);
        int in = Math.max(0, hint.inboundFrames);
        int open = Math.max(0, hint.openServiceCount);
        int outPeers = Math.max(0, hint.distinctOutboundPeers);
        int inPeers = Math.max(0, hint.distinctInboundPeers);

        boolean hasServerSignals = open > 0 || (in >= 25 && inPeers >= 3);
        boolean hasClientSignals = (out >= 25 && outPeers >= 3);

        if (hasServerSignals && hasClientSignals) {
            return "mixed";
        }
        if (hasServerSignals && in >= out) {
            return "server";
        }
        if (hasClientSignals && out > in) {
            return "client";
        }
        return null;
    }

    private String buildTrafficEvidenceJson(DatabaseService.TrafficRoleHint hint, String reason) {
        if (hint == null) {
            return buildEvidenceJson(new NodeServiceProfile(), reason);
        }

        return "{"
                + "\"reason\":\"" + escapeJson(reason) + "\","
                + "\"outbound_frames\":" + hint.outboundFrames + ","
                + "\"inbound_frames\":" + hint.inboundFrames + ","
                + "\"distinct_outbound_peers\":" + hint.distinctOutboundPeers + ","
                + "\"distinct_inbound_peers\":" + hint.distinctInboundPeers + ","
                + "\"open_service_count\":" + hint.openServiceCount
                + "}";
    }

    private boolean containsAny(Set<String> values, String... needles) {
        if (values == null || values.isEmpty() || needles == null) {
            return false;
        }
        for (String value : values) {
            if (value == null) {
                continue;
            }
            String v = value.toLowerCase();
            for (String needle : needles) {
                if (needle != null && v.contains(needle.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean containsAny(String value, String... needles) {
        if (value == null || value.isBlank() || needles == null) {
            return false;
        }
        String lower = value.toLowerCase();
        for (String needle : needles) {
            if (needle != null && lower.contains(needle.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    private boolean isCriticalInfrastructureMac(String mac) {
        if (mac == null || mac.isBlank()) {
            return false;
        }
        try {
            return dbService.isMacMarkedCriticalInfrastructure(mac);
        } catch (Exception ignored) {
            return false;
        }
    }

    private String buildEvidenceJson(NodeServiceProfile profile, String reason) {
        String ports = profile.openPorts.stream()
                .sorted()
                .map(String::valueOf)
                .reduce((a, b) -> a + "," + b)
                .orElse("");

        String services = profile.serviceNames.stream()
                .sorted()
                .reduce((a, b) -> a + "," + b)
                .orElse("");

        return "{"
                + "\"reason\":\"" + escapeJson(reason) + "\","
                + "\"open_ports\":\"" + escapeJson(ports) + "\","
                + "\"services\":\"" + escapeJson(services) + "\""
                + "}";
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }

    private String nullIfBlank(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private List<List<String>> chunkList(List<String> items, int chunkSize) {
        List<List<String>> chunks = new ArrayList<>();
        if (items == null || items.isEmpty()) {
            return chunks;
        }

        int size = Math.max(1, chunkSize);
        for (int i = 0; i < items.size(); i += size) {
            int end = Math.min(items.size(), i + size);
            chunks.add(new ArrayList<>(items.subList(i, end)));
        }
        return chunks;
    }

    // ========================================
    // BLOCK 28 — TOPOLOGY VIEW
    // ========================================
    public void showTopology() {

        clearOutput();
        showMiddleTopologyControls("Topology Controls");

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        topologyScanId = scanId;
        loadTopologyNodes(scanId);
    }

    private void loadTopologyNodes(int scanId) {
        new Thread(() -> {
            String scanContextSql = """
                SELECT target_host, subnet
                FROM scan_runs
                WHERE id = ?
            """;

            String sql = """
                SELECT
                    a.observed_ip,
                    a.mac_address,
                    COALESCE(v.vendor_clean, v.vendor, 'Unknown') AS vendor,
                    a.rtt_ms,
                    a.response_type,
                    a.seen_count,
                    a.last_seen
                FROM arp_bindings a
                LEFT JOIN mac_oui_lookup v
                    ON LEFT(REGEXP_REPLACE(UPPER(a.mac_address), '[^0-9A-F]', '', 'g'), 6)
                     = LEFT(REGEXP_REPLACE(UPPER(v.oui),        '[^0-9A-F]', '', 'g'), 6)
                WHERE a.scan_id = ?
                  AND a.rtt_ms IS NOT NULL
                  AND a.observed_ip IS NOT NULL
                ORDER BY a.rtt_ms ASC, a.observed_ip ASC
            """;

            java.util.List<TopologyNode> nodes = new java.util.ArrayList<>();
            String targetHost = null;
            String subnet = null;

            try (Connection conn = dbService.getConnection()) {
                try (PreparedStatement contextStmt = conn.prepareStatement(scanContextSql)) {
                    contextStmt.setInt(1, scanId);
                    try (ResultSet rs = contextStmt.executeQuery()) {
                        if (rs.next()) {
                            targetHost = rs.getString("target_host");
                            subnet = rs.getString("subnet");
                        }
                    }
                }

                try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                    stmt.setInt(1, scanId);

                    try (ResultSet rs = stmt.executeQuery()) {
                        while (rs.next()) {
                            String ip = rs.getString("observed_ip");
                            if (!isDottedQuadIp(ip)) {
                                continue;
                            }
                            String mac = rs.getString("mac_address");
                            String vendor = rs.getString("vendor");
                            String responseType = rs.getString("response_type");
                            String roleHint = DeviceHeuristics.classifyInfrastructureRole(vendor, mac, ip, responseType);

                            nodes.add(new TopologyNode(
                                    ip,
                                    mac,
                                    vendor,
                                    roleHint,
                                    rs.getDouble("rtt_ms"),
                                    responseType,
                                    rs.getInt("seen_count"),
                                    rs.getTimestamp("last_seen")
                            ));
                        }
                    }
                }

                final String fTargetHost = targetHost;
                final String fSubnet = subnet;
                final String fRouterHint = inferRouterHintFromScan(conn, scanId, subnet);
                SwingUtilities.invokeLater(() -> {
                    topologyNodes = nodes;
                    topologyDarkObservedNodes = new ArrayList<>();
                    topologyScanTargetHost = fTargetHost;
                    topologyScanSubnet = fSubnet;
                    topologyRouterHintIp = fRouterHint;
                    rebuildTopologyGraphFromControls();
                });

            } catch (Exception e) {
                append("TOPO ERROR: " + e.getMessage());
            }

        }).start();
    }

    private String inferRouterHintFromScan(Connection conn, int scanId, String subnet) {
        if (conn == null || subnet == null || subnet.isBlank()) {
            return null;
        }

        String sql = """
            SELECT host(observed_ip) AS observed_ip
            FROM arp_bindings
            WHERE scan_id = ?
              AND observed_ip IS NOT NULL
              AND observed_ip << ?::cidr
            ORDER BY
                (CASE WHEN LOWER(COALESCE(response_type, '')) = 'localhost-response' THEN 1 ELSE 0 END) DESC,
                (CASE WHEN LOWER(COALESCE(source, '')) = 'active_arp' THEN 1 ELSE 0 END) DESC,
                (CASE
                    WHEN split_part(host(observed_ip), '.', 4) IN ('1', '254', '253')
                    THEN 1 ELSE 0
                 END) DESC,
                seen_count DESC,
                last_seen DESC NULLS LAST
            LIMIT 1
        """;

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, scanId);
            stmt.setString(2, subnet.trim());

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    String ip = rs.getString("observed_ip");
                    return isDottedQuadIp(ip) ? ip : null;
                }
            }
        } catch (Exception ignored) {
            return null;
        }

        return null;
    }

    private void rebuildTopologyGraphFromControls() {

        final int minSeenCount = topoMinSeenSlider.getValue();
        final int recentWindowMinutes = topoTimeWindowSlider.getValue();
        final double percentThreshold = topoPercentSlider.getValue() / 100.0;
        final double absoluteThreshold = topoAbsoluteSlider.getValue() / 1000.0;
        final int minGroupSize = topoMinGroupSlider.getValue();
        final double outlierMultiplier = topoOutlierSlider.getValue() / 100.0;
        final double bridgeThreshold = topoBridgeSlider.getValue() / 1000.0;

        Instant now = Instant.now();
        List<TopologyNode> filteredNodes = new ArrayList<>();

        for (TopologyNode node : topologyNodes) {
            if (node.seenCount < minSeenCount) {
                continue;
            }

            if (recentWindowMinutes > 0 && node.lastSeen != null) {
                long ageMinutes = Duration.between(node.lastSeen.toInstant(), now).toMinutes();
                if (ageMinutes > recentWindowMinutes) {
                    continue;
                }
            }

            filteredNodes.add(node);
        }

        if (filteredNodes.isEmpty()) {
            topologyStatsLabel.setText(String.format(
                    "Showing 0/%d RTT nodes (scan %s).",
                    topologyNodes.size(),
                    topologyScanId != null ? topologyScanId.toString() : "?"
            ));
            topologyGraphPanel.setGraphData("Router", 0.0, new ArrayList<>(), new ArrayList<>(), new ArrayList<>());
            showGraphOutput();
            return;
        }

        RouterAnchorSelection routerSelection = selectRouterAnchorNode(
                filteredNodes,
                topoRouterOverrideField != null ? topoRouterOverrideField.getText() : null,
                topologyRouterHintIp,
                topologyScanTargetHost,
                topologyScanSubnet
        );
        TopologyNode routerNodeForMath = routerSelection.node != null ? routerSelection.node : filteredNodes.get(0);
        String routerAnchorIp = routerSelection.anchorIp != null ? routerSelection.anchorIp : routerNodeForMath.ip;
        double routerAnchorRtt = routerSelection.node != null ? routerSelection.node.rtt : 0.0;

        java.util.List<java.util.List<TopologyNode>> rawClusters = new java.util.ArrayList<>();
        java.util.List<TopologyNode> currentCluster = new java.util.ArrayList<>();

        double clusterAnchorRtt = filteredNodes.get(0).rtt;
        currentCluster.add(filteredNodes.get(0));

        for (int i = 1; i < filteredNodes.size(); i++) {
            TopologyNode node = filteredNodes.get(i);

            double absoluteDiff = Math.abs(node.rtt - clusterAnchorRtt);
            double percentDiff = (clusterAnchorRtt <= 0.000001)
                    ? 0.0
                    : (absoluteDiff / clusterAnchorRtt);

            boolean sameCluster =
                    (absoluteDiff <= absoluteThreshold) ||
                            (percentDiff <= percentThreshold);

            if (sameCluster) {
                currentCluster.add(node);
            } else {
                rawClusters.add(currentCluster);
                currentCluster = new java.util.ArrayList<>();
                currentCluster.add(node);
                clusterAnchorRtt = node.rtt;
            }
        }

        if (!currentCluster.isEmpty()) {
            rawClusters.add(currentCluster);
        }

        java.util.List<TopologyGraphPanel.GraphCluster> graphClusters = new java.util.ArrayList<>();
        java.util.List<TopologyGraphPanel.GraphNode> outliers = new java.util.ArrayList<>();

        double baseRtt = routerNodeForMath.rtt;
        int clusterNumber = 1;
        int hiddenTinyNodes = 0;
        int possibleBridges = 0;
        int renderedBridges = 0;
        Double previousDisplayedMaxRtt = null;

        for (java.util.List<TopologyNode> cluster : rawClusters) {

            if (cluster.size() < minGroupSize) {
                hiddenTinyNodes += cluster.size();
                continue;
            }

            double minRtt = Double.MAX_VALUE;
            double maxRtt = Double.MIN_VALUE;
            double totalRtt = 0.0;

            java.util.List<TopologyGraphPanel.GraphNode> graphNodes = new java.util.ArrayList<>();

            for (TopologyNode n : cluster) {
                if (n.rtt < minRtt) minRtt = n.rtt;
                if (n.rtt > maxRtt) maxRtt = n.rtt;
                totalRtt += n.rtt;

                graphNodes.add(new TopologyGraphPanel.GraphNode(
                        n.ip,
                        n.mac,
                        n.vendor,
                        n.roleHint,
                        n.rtt,
                        n.responseType
                ));
            }

            double avgRtt = totalRtt / cluster.size();

            boolean isOutlierCluster =
                    (baseRtt > 0.000001) &&
                            (avgRtt >= (baseRtt * outlierMultiplier)) &&
                            (cluster.size() <= 2);

            if (isOutlierCluster) {
                outliers.addAll(graphNodes);
                continue;
            }

            boolean bridgeToPrevious = true;
            if (previousDisplayedMaxRtt != null) {
                possibleBridges++;
                double bridgeGap = Math.max(0.0, minRtt - previousDisplayedMaxRtt);
                bridgeToPrevious = bridgeGap <= bridgeThreshold;
                if (bridgeToPrevious) {
                    renderedBridges++;
                }
            }

            graphClusters.add(new TopologyGraphPanel.GraphCluster(
                    "Cluster " + clusterNumber,
                    minRtt,
                    maxRtt,
                    avgRtt,
                    bridgeToPrevious,
                    graphNodes
            ));
            previousDisplayedMaxRtt = maxRtt;
            clusterNumber++;
        }

        topologyStatsLabel.setText(String.format(
                "Showing %d/%d RTT nodes | %d groups | %d outliers | %d hidden tiny | bridges %d/%d | router %s (%s) | scan target=%s subnet=%s",
                filteredNodes.size() - hiddenTinyNodes - outliers.size(),
                topologyNodes.size(),
                graphClusters.size(),
                outliers.size(),
                hiddenTinyNodes,
                renderedBridges,
                possibleBridges,
                routerAnchorIp,
                routerSelection.reason,
                topologyScanTargetHost != null ? topologyScanTargetHost : "-",
                topologyScanSubnet != null ? topologyScanSubnet : "-"
        ));

        topologyGraphPanel.setGraphData(
                routerAnchorIp,
                routerAnchorRtt,
                graphClusters,
                outliers,
                new ArrayList<>()
        );
        showGraphOutput();
    }

    private RouterAnchorSelection selectRouterAnchorNode(
            List<TopologyNode> nodes,
            String routerOverride,
            String scanRouterHintIp,
            String targetHost,
            String subnet
    ) {
        if (nodes == null || nodes.isEmpty()) {
            return new RouterAnchorSelection(null, null, "none");
        }

        String normalizedOverride = normalizeIpToken(routerOverride);
        if (isDottedQuadIp(normalizedOverride)) {
            for (TopologyNode node : nodes) {
                if (isSameIp(node.ip, normalizedOverride)) {
                    return new RouterAnchorSelection(node, normalizedOverride, "manual override");
                }
            }
            return new RouterAnchorSelection(null, normalizedOverride, "manual override (not in Nmap RTT set)");
        }

        String normalizedScanRouterHint = normalizeIpToken(scanRouterHintIp);
        if (isDottedQuadIp(normalizedScanRouterHint)) {
            for (TopologyNode node : nodes) {
                if (isSameIp(node.ip, normalizedScanRouterHint)) {
                    return new RouterAnchorSelection(node, normalizedScanRouterHint, "scan router hint");
                }
            }
            return new RouterAnchorSelection(null, normalizedScanRouterHint, "scan router hint (not in Nmap RTT set)");
        }

        String subnetEntryRouterHint = extractRouterHintFromSubnetEntry(subnet);
        if (isDottedQuadIp(subnetEntryRouterHint)) {
            for (TopologyNode node : nodes) {
                if (isSameIp(node.ip, subnetEntryRouterHint)) {
                    return new RouterAnchorSelection(node, subnetEntryRouterHint, "subnet entry router hint");
                }
            }
            return new RouterAnchorSelection(null, subnetEntryRouterHint, "subnet entry router hint (not in Nmap RTT set)");
        }

        String normalizedTargetHost = normalizeIpToken(targetHost);
        if (!isDottedQuadIp(normalizedTargetHost)) {
            normalizedTargetHost = null;
        }
        if (normalizedTargetHost != null && isIpInSubnet(normalizedTargetHost, subnet)) {
            for (TopologyNode node : nodes) {
                if (isSameIp(node.ip, normalizedTargetHost)) {
                    return new RouterAnchorSelection(node, normalizedTargetHost, "scan target_host");
                }
            }
            return new RouterAnchorSelection(null, normalizedTargetHost, "scan target_host (not in Nmap RTT set)");
        }

        for (TopologyNode node : nodes) {
            String responseType = node.responseType != null ? node.responseType.trim().toLowerCase() : "";
            if ("localhost-response".equals(responseType) && isIpInSubnet(node.ip, subnet)) {
                return new RouterAnchorSelection(node, node.ip, "localhost-response");
            }
        }

        List<String> gatewayCandidates = deriveGatewayCandidatesFromSubnet(subnet);
        for (String candidate : gatewayCandidates) {
            for (TopologyNode node : nodes) {
                if (isSameIp(node.ip, candidate)) {
                    return new RouterAnchorSelection(node, candidate, "subnet gateway candidate " + candidate);
                }
            }
        }

        TopologyNode best = nodes.get(0);
        int bestScore = Integer.MIN_VALUE;

        for (TopologyNode node : nodes) {
            int score = scoreRouterCandidate(node, normalizedTargetHost);
            if (score > bestScore) {
                best = node;
                bestScore = score;
                continue;
            }

            if (score == bestScore) {
                if (node.seenCount > best.seenCount) {
                    best = node;
                } else if (node.seenCount == best.seenCount && node.rtt < best.rtt) {
                    best = node;
                }
            }
        }

        return new RouterAnchorSelection(best, best.ip, "scored heuristic");
    }

    private int scoreRouterCandidate(TopologyNode node, String normalizedTargetHost) {
        int score = 0;

        if (normalizedTargetHost != null && isSameIp(node.ip, normalizedTargetHost)) {
            score += 1000;
        }

        String roleHint = node.roleHint != null ? node.roleHint.toLowerCase() : "";
        String responseType = node.responseType != null ? node.responseType.toLowerCase() : "";
        String vendor = node.vendor != null ? node.vendor.toLowerCase() : "";

        if (roleHint.contains("router")) {
            score += 300;
        }
        if (roleHint.contains("gateway")) {
            score += 250;
        }
        if (responseType.contains("router") || responseType.contains("gateway")) {
            score += 120;
        }
        if (isGatewayLikeIp(node.ip)) {
            score += 180;
        }
        if (vendor.contains("cisco")
                || vendor.contains("ubiquiti")
                || vendor.contains("mikrotik")
                || vendor.contains("juniper")
                || vendor.contains("fortinet")
                || vendor.contains("netgate")
                || vendor.contains("palo alto")
                || vendor.contains("arista")) {
            score += 140;
        }

        score += Math.min(node.seenCount, 20) * 4;
        score += Math.max(0, (int) Math.round(40.0 - Math.min(node.rtt, 40.0)));

        return score;
    }

    private String normalizeIpToken(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || "local".equalsIgnoreCase(trimmed)) {
            return null;
        }
        int slash = trimmed.indexOf('/');
        if (slash > 0) {
            trimmed = trimmed.substring(0, slash);
        }
        return trimmed;
    }

    private boolean isSameIp(String ipA, String ipB) {
        String a = normalizeIpToken(ipA);
        String b = normalizeIpToken(ipB);
        if (!isDottedQuadIp(a) || !isDottedQuadIp(b)) {
            return false;
        }
        return a != null && b != null && a.equalsIgnoreCase(b);
    }

    private boolean isGatewayLikeIp(String ip) {
        String normalized = normalizeIpToken(ip);
        if (normalized == null) {
            return false;
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

    private List<String> deriveGatewayCandidatesFromSubnet(String subnet) {
        List<String> candidates = new ArrayList<>();
        String normalized = normalizeIpToken(subnet);
        if (!isDottedQuadIp(normalized)) {
            return candidates;
        }

        String[] parts = normalized.split("\\.");
        if (parts.length != 4) {
            return candidates;
        }

        String base = parts[0] + "." + parts[1] + "." + parts[2] + ".";
        candidates.add(base + "1");
        candidates.add(base + "254");
        candidates.add(base + "253");

        return candidates;
    }

    private String extractRouterHintFromSubnetEntry(String subnetCidr) {
        if (subnetCidr == null || subnetCidr.isBlank()) {
            return null;
        }

        String cidr = subnetCidr.trim();
        int slash = cidr.indexOf('/');
        if (slash <= 0 || slash >= cidr.length() - 1) {
            return null;
        }

        String ip = cidr.substring(0, slash).trim();
        if (!isDottedQuadIp(ip)) {
            return null;
        }

        if (isNetworkAddress(ip, cidr)) {
            return null;
        }

        return ip;
    }

    private boolean isNetworkAddress(String ip, String subnetCidr) {
        if (!isDottedQuadIp(ip) || subnetCidr == null || subnetCidr.isBlank()) {
            return false;
        }

        String cidr = subnetCidr.trim();
        int slash = cidr.indexOf('/');
        if (slash <= 0 || slash >= cidr.length() - 1) {
            return false;
        }

        String networkIp = cidr.substring(0, slash).trim();
        String prefixText = cidr.substring(slash + 1).trim();
        if (!isDottedQuadIp(networkIp)) {
            return false;
        }

        int prefix;
        try {
            prefix = Integer.parseInt(prefixText);
        } catch (NumberFormatException e) {
            return false;
        }
        if (prefix < 0 || prefix > 32) {
            return false;
        }

        long ipValue = ipv4ToLong(ip);
        long netValue = ipv4ToLong(networkIp);
        if (ipValue < 0 || netValue < 0) {
            return false;
        }

        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long networkBase = netValue & mask;
        return ipValue == networkBase;
    }

    private boolean isIpInSubnet(String ip, String subnetCidr) {
        if (!isDottedQuadIp(ip) || subnetCidr == null || subnetCidr.isBlank()) {
            return false;
        }

        String cidr = subnetCidr.trim();
        int slash = cidr.indexOf('/');
        if (slash <= 0 || slash >= cidr.length() - 1) {
            return false;
        }

        String networkIp = cidr.substring(0, slash).trim();
        String prefixText = cidr.substring(slash + 1).trim();

        if (!isDottedQuadIp(networkIp)) {
            return false;
        }

        int prefix;
        try {
            prefix = Integer.parseInt(prefixText);
        } catch (NumberFormatException e) {
            return false;
        }

        if (prefix < 0 || prefix > 32) {
            return false;
        }

        long ipValue = ipv4ToLong(ip);
        long netValue = ipv4ToLong(networkIp);
        if (ipValue < 0 || netValue < 0) {
            return false;
        }

        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (ipValue & mask) == (netValue & mask);
    }

    private long ipv4ToLong(String ip) {
        if (!isDottedQuadIp(ip)) {
            return -1L;
        }

        String[] parts = ip.split("\\.");
        long value = 0L;
        for (String part : parts) {
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return -1L;
            }
            value = (value << 8) | (octet & 0xFFL);
        }
        return value;
    }

    private boolean isDottedQuadIp(String value) {
        if (value == null) {
            return false;
        }

        String trimmed = value.trim();
        if (trimmed.isEmpty()) {
            return false;
        }

        String[] parts = trimmed.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            try {
                int octet = Integer.parseInt(part);
                if (octet < 0 || octet > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return true;
    }

    private static class RouterAnchorSelection {
        final TopologyNode node;
        final String anchorIp;
        final String reason;

        RouterAnchorSelection(TopologyNode node, String anchorIp, String reason) {
            this.node = node;
            this.anchorIp = anchorIp;
            this.reason = reason != null ? reason : "unknown";
        }
    }

    private static class ScanRunContext {
        final String subnet;
        final String targetHost;
        final boolean sshUsed;

        ScanRunContext(String subnet, String targetHost, boolean sshUsed) {
            this.subnet = subnet;
            this.targetHost = targetHost;
            this.sshUsed = sshUsed;
        }
    }

    private static class ServiceProbeResult {
        final String observedIp;
        final String transport;
        final int port;
        final String state;
        final String serviceName;
        final String product;
        final String version;
        final String extraInfo;

        ServiceProbeResult(
                String observedIp,
                String transport,
                int port,
                String state,
                String serviceName,
                String product,
                String version,
                String extraInfo
        ) {
            this.observedIp = observedIp;
            this.transport = transport;
            this.port = port;
            this.state = state;
            this.serviceName = serviceName;
            this.product = product;
            this.version = version;
            this.extraInfo = extraInfo;
        }
    }

    private static class NodeServiceProfile {
        final Set<Integer> openPorts = new HashSet<>();
        final Set<String> serviceNames = new HashSet<>();
    }

    // ========================================
    // BLOCK 29 — CLEAR OUTPUT
    // ========================================
    public void clearOutput() {
        SwingUtilities.invokeLater(() -> {
            outputArea.setText("");
            detailTableModel.setRowCount(0);
            showTextOutput();
        });
    }

    // ========================================
    // BLOCK 30 — SHOW TEXT OUTPUT
    // ========================================
    private void showTextOutput() {
        outputCardLayout.show(outputCardPanel, "TEXT");
    }

    // ========================================
    // BLOCK 31 — SHOW TABLE OUTPUT
    // ========================================
    private void showTableOutput() {
        outputCardLayout.show(outputCardPanel, "TABLE");
    }

    // ========================================
    // BLOCK 32 — SHOW GRAPH OUTPUT
    // ========================================
    private void showGraphOutput() {
        outputCardLayout.show(outputCardPanel, "GRAPH");
    }

    // ========================================
    // BLOCK 33 — CONFIGURE DETAIL TABLE
    // ========================================
    private void configureDetailTable(String[] headers, List<Object[]> rows) {
        SwingUtilities.invokeLater(() -> {
            detailTableModel.setColumnIdentifiers(headers);
            detailTableModel.setRowCount(0);

            for (Object[] row : rows) {
                detailTableModel.addRow(row);
            }

            showTableOutput();
        });
    }

    // ========================================
    // BLOCK 34 — VIEW SCAN
    // ========================================
    public void viewRawScan() {

        clearOutput();
        showMiddlePlaceholder(
                "Raw Scan Context",
                "This middle section is available for raw-scan actions.\n\n" +
                        "Possible later additions:\n" +
                        "- Filter by vendor\n" +
                        "- Filter by response type\n" +
                        "- Export selected rows"
        );

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {

            String sql = """
                WITH ranked_nodes AS (
                    SELECT
                        observed_ip,
                        mac_address,
                        resolved_vendor,
                        rtt_ms,
                        response_type,
                        source,
                        seen_count,
                        last_seen,
                        ROW_NUMBER() OVER (
                            PARTITION BY observed_ip
                            ORDER BY
                                (CASE WHEN rtt_ms IS NOT NULL THEN 1 ELSE 0 END) DESC,
                                seen_count DESC,
                                last_seen DESC NULLS LAST,
                                (CASE WHEN source = 'active_arp' THEN 1 ELSE 0 END) DESC,
                                (CASE WHEN mac_address IS NOT NULL THEN 1 ELSE 0 END) DESC,
                                rtt_ms ASC NULLS LAST
                        ) AS rn
                    FROM vw_scan_nodes
                    WHERE scan_id = ?
                )
                SELECT
                    observed_ip,
                    mac_address,
                    resolved_vendor,
                    rtt_ms,
                    response_type,
                    source,
                    seen_count,
                    last_seen
                FROM ranked_nodes
                WHERE rn = 1
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
                        String ip = rs.getString("observed_ip");
                        String mac = rs.getString("mac_address");
                        String vendor = rs.getString("resolved_vendor");
                        String responseType = rs.getString("response_type");
                        String roleHint = DeviceHeuristics.classifyInfrastructureRole(vendor, mac, ip, responseType);

                        rows.add(new Object[]{
                                ip,
                                mac,
                                vendor,
                                roleHint,
                                (rttValue != null ? rs.getDouble("rtt_ms") : null),
                                responseType,
                                rs.getString("source"),
                                rs.getInt("seen_count"),
                                rs.getTimestamp("last_seen")
                        });
                    }
                }

                configureDetailTable(
                        new String[]{
                                "IP",
                                "MAC",
                                "Vendor",
                                "Role Hint",
                                "RTT ms",
                                "Response Type",
                                "Source",
                                "Seen Count",
                                "Last Seen"
                        },
                        rows
                );

            } catch (Exception e) {
                append("VIEW ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 35 — VIEW TCPDUMP CAPTURE
    // ========================================
    public void viewTcpdumpCapture() {

        clearOutput();

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        showMiddlePlaceholder(
                "TCP Dump Context",
                "Loading latest TCP dump for scan ID " + scanId + "..."
        );

        loadLatestTcpdumpCaptureForScan(scanId);
    }

    private void loadLatestTcpdumpCaptureForScan(int scanId) {
        final int fScanId = scanId;

        new Thread(() -> {
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
                stmt.setInt(1, fScanId);

                Long latestCaptureId = null;
                try (ResultSet rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        latestCaptureId = rs.getLong("id");
                    }
                }

                if (latestCaptureId == null) {
                    append("No TCP dump captures found for scan ID " + fScanId + ".");
                    showMiddlePlaceholder(
                            "TCP Dump Context",
                            "No TCP dump captures found for scan ID " + fScanId + "."
                    );
                    return;
                }

                loadTcpdumpCaptureById(fScanId, latestCaptureId);

            } catch (Exception e) {
                append("LATEST CAPTURE LOAD ERROR: " + e.getMessage());
                showMiddlePlaceholder(
                        "TCP Dump Context",
                        "Failed to load latest TCP dump capture.\n\n" + e.getMessage()
                );
            }
        }).start();
    }

    private void deleteSelectedTcpdumpCapture() {

        if (browserScanId == null) {
            append("No scan is currently loaded into the capture browser.");
            return;
        }

        int selectedRow = captureListTable.getSelectedRow();
        if (selectedRow < 0) {
            append("Select a capture from the middle panel first.");
            return;
        }

        int modelRow = captureListTable.convertRowIndexToModel(selectedRow);
        Object idValue = captureListTableModel.getValueAt(modelRow, 0);
        if (idValue == null) {
            append("Selected capture row does not contain a valid capture ID.");
            return;
        }

        long captureId;
        if (idValue instanceof Number) {
            captureId = ((Number) idValue).longValue();
        } else {
            captureId = Long.parseLong(idValue.toString());
        }

        if (captureRunning && activeCaptureId != null && activeCaptureId == captureId) {
            append("Cannot delete a capture while it is currently running.");
            return;
        }

        int confirm = JOptionPane.showConfirmDialog(
                frame,
                "Delete capture ID " + captureId + " and its parsed observations?",
                "Delete TCP Dump Capture",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE
        );

        if (confirm != JOptionPane.YES_OPTION) {
            return;
        }

        final int fScanId = browserScanId;
        final long fCaptureId = captureId;

        new Thread(() -> {
            try {
                dbService.deleteTcpdumpCapture(fScanId, fCaptureId);
                append("Deleted TCP dump capture ID " + fCaptureId + ".");

                SwingUtilities.invokeLater(() -> {
                    if (browserSelectedCaptureId != null && browserSelectedCaptureId == fCaptureId) {
                        browserSelectedCaptureId = null;
                    }
                });

                loadCaptureBrowserForScan(fScanId, true);

            } catch (Exception e) {
                append("DELETE CAPTURE ERROR: " + e.getMessage());
            }
        }).start();
    }

    // ========================================
    // BLOCK 36 — LOAD CAPTURE BROWSER FOR SCAN
    // ========================================
    private void loadCaptureBrowserForScan(int scanId, boolean autoLoadLatest) {

        final int fScanId = scanId;
        final boolean fAutoLoadLatest = autoLoadLatest;

        new Thread(() -> {

            String captureSql = """
                SELECT
                    id,
                    status,
                    capture_method,
                    capture_host,
                    interface_name,
                    started_at,
                    ended_at
                FROM tcpdump_captures
                WHERE scan_id = ?
                ORDER BY id DESC
            """;

            List<Object[]> rows = new ArrayList<>();
            Long latestCaptureId = null;

            try (
                    Connection conn = dbService.getConnection();
                    PreparedStatement stmt = conn.prepareStatement(captureSql)
            ) {
                stmt.setInt(1, fScanId);

                try (ResultSet rs = stmt.executeQuery()) {
                    while (rs.next()) {
                        long captureId = rs.getLong("id");

                        if (latestCaptureId == null) {
                            latestCaptureId = captureId;
                        }

                        rows.add(new Object[]{
                                captureId,
                                rs.getString("status"),
                                rs.getString("capture_method"),
                                rs.getString("capture_host"),
                                rs.getString("interface_name"),
                                rs.getTimestamp("started_at"),
                                rs.getTimestamp("ended_at")
                        });
                    }
                }

                final Long fLatestCaptureId = latestCaptureId;

                SwingUtilities.invokeLater(() -> {
                    browserScanId = fScanId;
                    browserSelectedCaptureId = fLatestCaptureId;

                    captureListTableModel.setColumnIdentifiers(new String[]{
                            "Capture ID", "Status", "Method", "Host", "Interface", "Started", "Ended"
                    });
                    captureListTableModel.setRowCount(0);

                    for (Object[] row : rows) {
                        captureListTableModel.addRow(row);
                    }

                    showMiddleCaptureBrowser("TCP Dump Captures for Scan ID " + fScanId);

                    if (!rows.isEmpty()) {
                        captureListTable.setRowSelectionInterval(0, 0);
                    }
                });

                if (rows.isEmpty()) {
                    showMiddlePlaceholder(
                            "TCP Dump Capture Browser",
                            "No TCP dump captures found for scan ID " + fScanId + "."
                    );
                    append("No TCP dump captures found for scan ID " + fScanId + ".");
                    return;
                }

                if (fAutoLoadLatest && fLatestCaptureId != null) {
                    loadTcpdumpCaptureById(fScanId, fLatestCaptureId);
                }

            } catch (Exception e) {
                append("CAPTURE LIST ERROR: " + e.getMessage());
                showMiddlePlaceholder(
                        "TCP Dump Capture Browser",
                        "Failed to load capture list.\n\n" + e.getMessage()
                );
            }

        }).start();
    }

    // ========================================
    // BLOCK 37 — LOAD TCPDUMP CAPTURE BY ID
    // ========================================
    private void loadTcpdumpCaptureById(int scanId, long captureId) {

        final int fScanId = scanId;
        final long fCaptureId = captureId;

        new Thread(() -> {

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
                    PreparedStatement stmt = conn.prepareStatement(rowsSql)
            ) {
                stmt.setInt(1, fScanId);
                stmt.setLong(2, fCaptureId);

                try (ResultSet rs = stmt.executeQuery()) {
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

                configureDetailTable(
                        new String[]{
                                "Src MAC",
                                "Src Vendor",
                                "Src IP",
                                "Dst MAC",
                                "Dst Vendor",
                                "Dst IP",
                                "Protocol",
                                "Note",
                                "Raw Line"
                        },
                        rows
                );

                if (rows.isEmpty()) {
                    append("Capture ID " + fCaptureId + " has no parsed mac_observations rows.");
                }

            } catch (Exception e) {
                append("TCPDUMP VIEW ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 38 — NETWORK NOISE SUMMARY
    // ========================================
    public void showNetworkNoiseSummary() {

        clearOutput();
        showMiddlePlaceholder(
                "Noise Summary Context",
                "This middle panel can later host capture selectors,\n" +
                        "filters, and top-talker drill-down controls."
        );

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {
            try {
                Long captureId = featureAnalysisService.findLatestCaptureId(fScanId);
                if (captureId == null) {
                    append("No TCP dump capture found for scan ID " + fScanId + ".");
                    return;
                }
                append(featureAnalysisService.buildNetworkNoiseSummaryText(fScanId, captureId));
            } catch (Exception e) {
                append("NOISE SUMMARY ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 38B — POSSIBLE SERVICES INVENTORY
    // ========================================
    public void showPossibleServices() {

        clearOutput();
        showMiddlePlaceholder(
                "Possible Services Context",
                "One row per node with discovered services and likely roles.\n" +
                        "Click any column header to sort."
        );

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {
            try {
                dbService.ensureOuiMetadataSchema();
                List<Object[]> rows = queryPossibleServicesRows(fScanId);

                boolean hasServiceSignals = false;
                boolean hasTrafficRoleSignals = false;
                for (Object[] row : rows) {
                    String openPorts = row[3] != null ? row[3].toString().trim() : "";
                    String likelyRoles = row[5] != null ? row[5].toString().trim() : "";
                    String assessment = row[6] != null ? row[6].toString().trim().toLowerCase() : "";
                    if (!openPorts.isEmpty() || !likelyRoles.isEmpty() || !assessment.contains("weak/no smb signal")) {
                        hasServiceSignals = true;
                    }
                    String lr = likelyRoles.toLowerCase();
                    if (lr.contains("traffic_client")
                            || lr.contains("traffic_server")
                            || lr.contains("traffic_mixed")
                            || lr.contains("ubiquiti_client")
                            || lr.contains("ubiquiti_server")
                            || lr.contains("ubiquiti_mixed")) {
                        hasTrafficRoleSignals = true;
                    }
                }

                if (!rows.isEmpty() && !hasServiceSignals) {
                    append("No enrichment signals found for this scan yet. Running enrichment now...");
                    runPostCaptureEnrichment(fScanId);
                    rows = queryPossibleServicesRows(fScanId);
                } else if (!rows.isEmpty() && !hasTrafficRoleSignals) {
                    append("No traffic role labels found yet. Refreshing enrichment for this scan...");
                    runPostCaptureEnrichment(fScanId);
                    rows = queryPossibleServicesRows(fScanId);
                }

                configureDetailTable(
                        new String[]{
                                "IP",
                                "MAC",
                                "Vendor",
                                "Open Ports",
                                "Services",
                                "Likely Roles",
                                "Assessment",
                                "Critical Infra"
                        },
                        rows
                );

                if (rows.isEmpty()) {
                    append("No service inventory rows found for scan ID " + fScanId + ".");
                }

            } catch (Exception e) {
                append("POSSIBLE SERVICES VIEW ERROR: " + e.getMessage());
            }
        }).start();
    }

    private List<Object[]> queryPossibleServicesRows(int scanId) throws Exception {
        String sql = """
            WITH base AS (
                SELECT
                    host(a.observed_ip) AS observed_ip,
                    a.mac_address,
                    COALESCE(v.vendor_clean, v.vendor, 'Unknown') AS vendor
                FROM (
                    SELECT
                        scan_id,
                        observed_ip,
                        mac_address,
                        ROW_NUMBER() OVER (
                            PARTITION BY observed_ip
                            ORDER BY
                                (CASE WHEN rtt_ms IS NOT NULL THEN 1 ELSE 0 END) DESC,
                                seen_count DESC,
                                last_seen DESC NULLS LAST,
                                (CASE WHEN mac_address IS NOT NULL THEN 1 ELSE 0 END) DESC
                        ) AS rn
                    FROM arp_bindings
                    WHERE scan_id = ?
                ) a
                LEFT JOIN mac_oui_lookup v
                  ON LEFT(REGEXP_REPLACE(UPPER(a.mac_address), '[^0-9A-F]', '', 'g'), 6)
                   = LEFT(REGEXP_REPLACE(UPPER(v.oui),        '[^0-9A-F]', '', 'g'), 6)
                WHERE a.rn = 1
            ),
            svc AS (
                SELECT
                    host(so.observed_ip) AS observed_ip,
                    STRING_AGG(
                        DISTINCT (so.port::text || '/' || COALESCE(so.transport, 'tcp')),
                        ', '
                        ORDER BY (so.port::text || '/' || COALESCE(so.transport, 'tcp'))
                    ) AS open_ports,
                    STRING_AGG(
                        DISTINCT COALESCE(so.service_name, '?'),
                        ', '
                        ORDER BY COALESCE(so.service_name, '?')
                    ) AS services
                FROM service_observations so
                WHERE so.scan_id = ?
                  AND so.state = 'open'
                GROUP BY so.observed_ip
            ),
            cls AS (
                SELECT
                    host(nc.observed_ip) AS observed_ip,
                    STRING_AGG(
                        DISTINCT (nc.node_role || ' (' || nc.confidence || ')'),
                        ', '
                        ORDER BY (nc.node_role || ' (' || nc.confidence || ')')
                    ) AS likely_roles
                FROM node_classifications nc
                WHERE nc.scan_id = ?
                GROUP BY nc.observed_ip
            ),
            fs_raw AS (
                SELECT
                    host(observed_ip) AS observed_ip,
                    file_share_assessment
                FROM vw_likely_file_sharing_nodes
                WHERE scan_id = ?
            ),
            fs AS (
                SELECT
                    observed_ip,
                    CASE
                        WHEN MAX(CASE WHEN file_share_assessment LIKE 'Likely Windows/File Server%' THEN 3
                                      WHEN file_share_assessment LIKE 'Likely SMB File Sharing%' THEN 2
                                      WHEN file_share_assessment LIKE 'Likely NetBIOS/Legacy File Sharing%' THEN 1
                                      ELSE 0 END) = 3
                            THEN 'Likely Windows/File Server (high)'
                        WHEN MAX(CASE WHEN file_share_assessment LIKE 'Likely Windows/File Server%' THEN 3
                                      WHEN file_share_assessment LIKE 'Likely SMB File Sharing%' THEN 2
                                      WHEN file_share_assessment LIKE 'Likely NetBIOS/Legacy File Sharing%' THEN 1
                                      ELSE 0 END) = 2
                            THEN 'Likely SMB File Sharing (medium)'
                        WHEN MAX(CASE WHEN file_share_assessment LIKE 'Likely Windows/File Server%' THEN 3
                                      WHEN file_share_assessment LIKE 'Likely SMB File Sharing%' THEN 2
                                      WHEN file_share_assessment LIKE 'Likely NetBIOS/Legacy File Sharing%' THEN 1
                                      ELSE 0 END) = 1
                            THEN 'Likely NetBIOS/Legacy File Sharing (medium)'
                        ELSE 'Weak/No SMB Signal'
                    END AS file_share_assessment
                FROM fs_raw
                GROUP BY observed_ip
            )
            SELECT
                b.observed_ip,
                b.mac_address,
                b.vendor,
                COALESCE(s.open_ports, '') AS open_ports,
                COALESCE(s.services, '') AS services,
                COALESCE(c.likely_roles, '') AS likely_roles,
                COALESCE(f.file_share_assessment, 'No SMB Signal') AS assessment,
                COALESCE(om.critical_infrastructure, false) AS critical_infrastructure
            FROM base b
            LEFT JOIN svc s ON s.observed_ip = b.observed_ip
            LEFT JOIN cls c ON c.observed_ip = b.observed_ip
            LEFT JOIN fs f ON f.observed_ip = b.observed_ip
            LEFT JOIN mac_oui_metadata om
              ON LEFT(REGEXP_REPLACE(UPPER(b.mac_address), '[^0-9A-F]', '', 'g'), 6)
               = LEFT(REGEXP_REPLACE(UPPER(om.oui),        '[^0-9A-F]', '', 'g'), 6)
            ORDER BY b.observed_ip
        """;

        List<Object[]> rows = new ArrayList<>();
        try (
                Connection conn = dbService.getConnection();
                PreparedStatement stmt = conn.prepareStatement(sql)
        ) {
            stmt.setInt(1, scanId);
            stmt.setInt(2, scanId);
            stmt.setInt(3, scanId);
            stmt.setInt(4, scanId);

            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    rows.add(new Object[]{
                            rs.getString("observed_ip"),
                            rs.getString("mac_address"),
                            rs.getString("vendor"),
                            rs.getString("open_ports"),
                            rs.getString("services"),
                            rs.getString("likely_roles"),
                            rs.getString("assessment"),
                            rs.getBoolean("critical_infrastructure")
                    });
                }
            }
        }
        return rows;
    }

    public void showSelectedOuiMetadata() {
        String mac = getSelectedMacFromDetailTable();
        if (mac == null) {
            append("Select a row with a MAC address first.");
            return;
        }

        String oui = normalizeOuiFromMac(mac);
        if (oui == null) {
            append("Unable to derive OUI from MAC: " + mac);
            return;
        }

        new Thread(() -> {
            try {
                DatabaseService.OuiMetadataRecord record = dbService.getOuiMetadata(oui);
                if (record == null) {
                    append("OUI " + oui + " has no metadata override yet.");
                    return;
                }

                append("OUI " + record.oui
                        + " | Vendor=" + record.vendor
                        + " | CriticalInfra=" + record.criticalInfrastructure
                        + " | Type=" + (record.equipmentType != null ? record.equipmentType : "-")
                        + " | RoleHint=" + (record.roleHint != null ? record.roleHint : "-")
                        + " | Notes=" + (record.notes != null ? record.notes : "-"));
            } catch (Exception e) {
                append("OUI METADATA ERROR: " + e.getMessage());
            }
        }).start();
    }

    public void setSelectedOuiCriticalInfrastructure(boolean critical) {
        String mac = getSelectedMacFromDetailTable();
        if (mac == null) {
            append("Select a row with a MAC address first.");
            return;
        }

        String oui = normalizeOuiFromMac(mac);
        if (oui == null) {
            append("Unable to derive OUI from MAC: " + mac);
            return;
        }

        new Thread(() -> {
            try {
                dbService.upsertOuiMetadata(
                        oui,
                        critical,
                        null,
                        critical ? "critical_infrastructure" : null,
                        "Set from UI using selected MAC " + mac
                );
                append("OUI " + oui + " critical infrastructure set to " + critical + ".");
            } catch (Exception e) {
                append("SET OUI METADATA ERROR: " + e.getMessage());
            }
        }).start();
    }

    public void runSnmpWalkForSelectedNode() {
        String ip = getSelectedIpFromDetailTable();
        if (!isDottedQuadIp(ip)) {
            append("Select a row with a valid IPv4 first.");
            return;
        }

        String community = JOptionPane.showInputDialog(
                frame,
                "SNMP community string (v2c):",
                "public"
        );
        if (community == null) {
            append("SNMP walk cancelled.");
            return;
        }
        community = community.trim();
        if (community.isEmpty()) {
            append("SNMP community string is required.");
            return;
        }

        String oidRoot = JOptionPane.showInputDialog(
                frame,
                "OID root:",
                "1.3.6.1.2.1"
        );
        if (oidRoot == null) {
            append("SNMP walk cancelled.");
            return;
        }
        oidRoot = oidRoot.trim();
        if (oidRoot.isEmpty()) {
            oidRoot = "1.3.6.1.2.1";
        }

        Integer scanId = getSelectedScanId();
        final String fIp = ip;
        final String fCommunity = community;
        final String fOidRoot = oidRoot;
        final Integer fScanId = scanId;

        showMiddlePlaceholder(
                "SNMP Walk: " + fIp,
                "Running snmpwalk...\n"
        );

        new Thread(() -> {
            long runId = -1L;
            String output = "";
            try {
                dbService.ensureSnmpWalkSchema();
                runId = dbService.createSnmpWalkRun(fScanId, fIp, "v2c", fOidRoot);
                append("SNMP walk started. Run ID=" + runId + " | IP=" + fIp + " | OID=" + fOidRoot);

                if (sshCheckbox.isSelected()) {
                    String cmd = "snmpwalk -v2c -c " + shellQuote(fCommunity)
                            + " -On " + shellQuote(fIp) + " " + shellQuote(fOidRoot);
                    output = executor.runSSH(
                            targetHostField.getText().trim(),
                            sshUserField.getText().trim(),
                            new String(sshPassField.getPassword()),
                            cmd
                    );
                } else {
                    output = executor.runLocal(List.of(
                            "snmpwalk",
                            "-v2c",
                            "-c",
                            fCommunity,
                            "-On",
                            fIp,
                            fOidRoot
                    ));
                }

                dbService.completeSnmpWalkRun(runId, output);
                append("SNMP walk complete. Run ID=" + runId);
                final String fOutput = output;
                SwingUtilities.invokeLater(() -> {
                    showMiddlePlaceholder(
                            "SNMP Walk: " + fIp,
                            fOutput != null && !fOutput.isBlank() ? fOutput : "(no output)"
                    );
                });

            } catch (Exception e) {
                try {
                    if (runId > 0) {
                        dbService.failSnmpWalkRun(runId, e.getMessage(), output);
                    }
                } catch (Exception ignored) {
                }
                append("SNMP WALK ERROR: " + e.getMessage());
                final String errText = e.getMessage();
                SwingUtilities.invokeLater(() -> showMiddlePlaceholder(
                        "SNMP Walk: " + fIp,
                        "SNMP walk failed.\n\n" + (errText != null ? errText : "unknown error")
                ));
            }
        }).start();
    }

    private String getSelectedIpFromDetailTable() {
        int selectedRow = detailTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }

        int modelRow = detailTable.convertRowIndexToModel(selectedRow);
        int colCount = detailTableModel.getColumnCount();

        for (int c = 0; c < colCount; c++) {
            String colName = detailTableModel.getColumnName(c);
            if (colName == null) {
                continue;
            }
            if (!colName.toLowerCase().contains("ip")) {
                continue;
            }

            Object value = detailTableModel.getValueAt(modelRow, c);
            if (value == null) {
                continue;
            }

            String ip = normalizeIpToken(value.toString());
            if (isDottedQuadIp(ip)) {
                return ip;
            }
        }

        return null;
    }

    private String shellQuote(String value) {
        if (value == null) {
            return "''";
        }
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    private String getSelectedMacFromDetailTable() {
        int selectedRow = detailTable.getSelectedRow();
        if (selectedRow < 0) {
            return null;
        }

        int modelRow = detailTable.convertRowIndexToModel(selectedRow);
        int colCount = detailTableModel.getColumnCount();

        for (int c = 0; c < colCount; c++) {
            String colName = detailTableModel.getColumnName(c);
            if (colName == null) {
                continue;
            }
            String normalized = colName.trim().toLowerCase();
            if (!normalized.contains("mac")) {
                continue;
            }

            Object value = detailTableModel.getValueAt(modelRow, c);
            if (value == null) {
                continue;
            }
            String mac = value.toString().trim();
            if (mac.matches("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")) {
                return mac.toUpperCase();
            }
        }

        return null;
    }

    private String normalizeOuiFromMac(String mac) {
        if (mac == null) {
            return null;
        }
        String hex = mac.toUpperCase().replaceAll("[^0-9A-F]", "");
        if (hex.length() < 6) {
            return null;
        }
        hex = hex.substring(0, 6);
        return hex.substring(0, 2) + ":" + hex.substring(2, 4) + ":" + hex.substring(4, 6);
    }

    // ========================================
    // BLOCK 39 — DUPLICATE IP SUSPECTS
    // ========================================
    public void showDuplicateIpSuspects() {

        clearOutput();
        showMiddlePlaceholder(
                "Duplicate IP Suspects Context",
                "This middle panel can later hold compare buttons,\n" +
                        "capture selection, or MAC drill-down actions."
        );

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {
            try {
                Long captureId = featureAnalysisService.findLatestCaptureId(fScanId);
                if (captureId == null) {
                    append("No TCP dump capture found for scan ID " + fScanId + ".");
                    return;
                }

                List<Object[]> rows = featureAnalysisService.loadDuplicateIpSuspectRows(fScanId, captureId);

                configureDetailTable(
                        new String[]{
                                "Suspected IP",
                                "Distinct MAC Count",
                                "MAC List",
                                "Vendor List",
                                "ARP Event Count",
                                "Evidence Types"
                        },
                        rows
                );

                if (rows.isEmpty()) {
                    append("No duplicate IP suspects found for capture ID " + captureId + ".");
                }

            } catch (Exception e) {
                append("DUP SUSPECT ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 40 — DARK DEVICE DETECTION
    // ========================================
    public void showDarkDevices() {

        clearOutput();
        showMiddlePlaceholder(
                "Dark Device Context",
                "How to read common notes/protocol patterns:\n\n" +
                        "Behavior flags in this view:\n" +
                        "- Normal: expected multicast/broadcast control behavior.\n" +
                        "- Review: unaccounted device that needs validation.\n" +
                        "- Suspicious: repeated ARP/IP behavior worth investigation.\n\n" +
                        "Additional signals:\n" +
                        "- Service Hint: likely protocol/service inferred from packet line.\n" +
                        "- Infra Signals: weak/strong hints of infrastructure behavior.\n\n" +
                        "- ipv4-multicast:\n" +
                        "  One-to-many traffic to 224.0.0.0/4 (MAC 01:00:5E:*).\n" +
                        "  Usually discovery/control chatter, not a single endpoint.\n\n" +
                        "- ipv6-multicast:\n" +
                        "  One-to-many traffic to ff00::/8 (MAC 33:33:*).\n\n" +
                        "- broadcast:\n" +
                        "  Sent to everyone on the local segment (ff:ff:ff:ff:ff:ff).\n\n" +
                        "- who-has:\n" +
                        "  ARP request asking \"who owns this IP?\".\n\n" +
                        "- is-at:\n" +
                        "  ARP reply stating \"this IP maps to this MAC\".\n\n" +
                        "- unaccounted:\n" +
                        "  Seen in capture but not currently matched to scan inventory.\n\n" +
                        "Multicast/Broadcast entries are useful for baseline behavior and\n" +
                        "noise analysis, even when they are not dark endpoints."
        );

        Integer scanId = getSelectedScanId();
        if (scanId == null) {
            append("Select a scan first.");
            return;
        }

        final int fScanId = scanId;

        new Thread(() -> {
            java.util.List<Object[]> rows = new java.util.ArrayList<>();

            try {
                Long captureId = featureAnalysisService.findLatestCaptureId(fScanId);
                if (captureId == null) {
                    append("No TCP dump capture found for scan ID " + fScanId + ".");
                    return;
                }

                List<FeatureAnalysisService.DarkDeviceCandidate> candidates =
                        featureAnalysisService.loadDarkDeviceCandidates(fScanId, captureId);

                for (FeatureAnalysisService.DarkDeviceCandidate candidate : candidates) {
                    String serviceHint = DeviceHeuristics.inferServiceHint(
                            candidate.sampleLine,
                            candidate.protocolList,
                            candidate.noteList
                    );
                    String infraSignals = DeviceHeuristics.inferInfraSignals(
                            candidate.sampleLine,
                            candidate.protocolList,
                            candidate.noteList
                    );

                    String[] behavior = DeviceHeuristics.classifyDarkDeviceBehavior(
                            candidate.sampleIp,
                            candidate.candidateMac,
                            candidate.vendor,
                            candidate.seenCount,
                            candidate.protocolList,
                            candidate.noteList,
                            candidate.nmapStatus,
                            serviceHint,
                            infraSignals
                    );

                    rows.add(new Object[]{
                            candidate.sampleIp,
                            candidate.candidateMac,
                            candidate.vendor,
                            candidate.seenCount,
                            behavior[0],
                            behavior[1],
                            serviceHint,
                            infraSignals,
                            candidate.protocolList,
                            candidate.noteList,
                            candidate.nmapStatus,
                            candidate.sampleLine
                    });
                }

                SwingUtilities.invokeLater(() -> {
                    detailTableModel.setColumnIdentifiers(new String[]{
                            "Sample IP",
                            "Candidate MAC",
                            "Vendor",
                            "Seen Count",
                            "Behavior Flag",
                            "Why Flagged",
                            "Service Hint",
                            "Infra Signals",
                            "Protocols",
                            "Notes",
                            "Nmap Status",
                            "Sample Line"
                    });

                    detailTableModel.setRowCount(0);

                    for (Object[] row : rows) {
                        detailTableModel.addRow(row);
                    }

                    showTableOutput();

                    if (rows.isEmpty()) {
                        outputArea.setText("No dark devices found. Everything seen in the latest TCP dump appears to be accounted for by Nmap IP/MAC inventory.");
                        showTextOutput();
                    }
                });

            } catch (Exception e) {
                append("DARK DEVICE ERROR: " + e.getMessage());
            }

        }).start();
    }

    // ========================================
    // BLOCK 40B — DARK DEVICE MONITOR
    // ========================================
    public void monitorSelectedDarkDevice() {
        int selectedRow = detailTable.getSelectedRow();
        if (selectedRow < 0) {
            append("Select a dark-device row first.");
            return;
        }

        int modelRow = detailTable.convertRowIndexToModel(selectedRow);
        Object ipValue = detailTableModel.getValueAt(modelRow, 0);
        if (ipValue == null) {
            append("Selected row has no sample IP.");
            return;
        }

        String ip = ipValue.toString().trim();
        if (!isDottedQuadIp(ip)) {
            append("Selected row IP is not a monitorable IPv4 host: " + ip);
            return;
        }

        String ifaceValue = (String) ifaceDropdown.getSelectedItem();
        if (ifaceValue == null || !ifaceValue.contains(" - ")) {
            append("Load interfaces and select one first.");
            return;
        }

        String ifaceName = ifaceValue.split(" - ")[0].trim();
        boolean sshUsed = sshCheckbox.isSelected();
        String captureHost = sshUsed ? targetHostField.getText().trim() : "local";

        if (darkMonitorRunning) {
            stopDarkDeviceMonitor();
        }

        showMiddlePlaceholder(
                "Node Monitor: " + ip,
                "Starting monitor on " + ifaceName + "...\n\n"
        );

        new Thread(() -> {
            try {
                String tcpdumpCmd = "exec tcpdump -l -i " + ifaceName + " -nn -e host " + ip;

                if (sshUsed) {
                    darkMonitorCapture = executor.startSSHStreaming(
                            captureHost,
                            sshUserField.getText().trim(),
                            new String(sshPassField.getPassword()),
                            tcpdumpCmd,
                            this::appendMonitorLine
                    );
                } else {
                    darkMonitorCapture = executor.startLocalStreaming(
                            List.of("sh", "-c", "exec sudo tcpdump -l -i " + ifaceName + " -nn -e host " + ip),
                            this::appendMonitorLine
                    );
                }

                darkMonitorRunning = true;
                darkMonitorIp = ip;
                append("Dark-device monitor started for " + ip + " on " + ifaceName + ".");

            } catch (Exception e) {
                darkMonitorCapture = null;
                darkMonitorRunning = false;
                darkMonitorIp = null;
                append("DARK MONITOR ERROR: " + e.getMessage());
            }
        }).start();
    }

    public void stopDarkDeviceMonitor() {
        if (!darkMonitorRunning || darkMonitorCapture == null) {
            append("No dark-device monitor is running.");
            return;
        }

        new Thread(() -> {
            try {
                darkMonitorCapture.stop();
            } catch (Exception ignored) {
            } finally {
                darkMonitorCapture = null;
                String stoppedIp = darkMonitorIp;
                darkMonitorIp = null;
                darkMonitorRunning = false;
                append("Dark-device monitor stopped" + (stoppedIp != null ? " for " + stoppedIp : "") + ".");
            }
        }).start();
    }

    private void appendMonitorLine(String line) {
        if (line == null) {
            return;
        }
        SwingUtilities.invokeLater(() -> {
            middleInfoArea.append(line + "\n");
            middleInfoArea.setCaretPosition(middleInfoArea.getDocument().getLength());
        });
    }

    // ========================================
    // BLOCK 41 — START CAPTURE TIMER
    // ========================================
    private void startCaptureTimer() {

        stopExistingTimer();

        captureStatusLabel.setText("Scan Capture Running...");

        captureTimer = new javax.swing.Timer(1000, e -> {
            long elapsedSeconds = (System.currentTimeMillis() - captureStartMillis) / 1000L;
            String elapsedText = formatDuration(elapsedSeconds);

            if (activeScanAutoStopSeconds != null) {
                long remaining = Math.max(0L, activeScanAutoStopSeconds - elapsedSeconds);
                String remainingText = formatDuration(remaining);
                captureStatusLabel.setText("Scan Capture Running | Elapsed " + elapsedText + " | Remaining " + remainingText);

                if (!autoStopTriggered && elapsedSeconds >= activeScanAutoStopSeconds && captureRunning) {
                    autoStopTriggered = true;
                    append("Auto-stop duration reached. Stopping scan capture...");
                    stopTcpdumpCapture();
                }
            } else {
                captureStatusLabel.setText("Scan Capture Running | Elapsed " + elapsedText);
            }
        });

        captureTimer.start();
    }

    // ========================================
    // BLOCK 42 — STOP CAPTURE TIMER
    // ========================================
    private void stopCaptureTimer(String finalStatus) {
        stopExistingTimer();
        captureStatusLabel.setText(finalStatus);
    }

    // ========================================
    // BLOCK 43 — STOP EXISTING TIMER
    // ========================================
    private void stopExistingTimer() {
        if (captureTimer != null) {
            captureTimer.stop();
            captureTimer = null;
        }
    }

    // ========================================
    // BLOCK 44 — FORMAT DURATION
    // ========================================
    private String formatDuration(long totalSeconds) {
        long minutes = totalSeconds / 60;
        long seconds = totalSeconds % 60;
        return String.format("%02d:%02d", minutes, seconds);
    }
}
