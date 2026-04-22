package dark_matter_scanner;

import javax.swing.*;
import java.awt.*;

// ========================================
// BLOCK 1 — ACTION PANEL MANAGER
// ========================================
public class ActionPanelManager {

    // ========================================
    // BLOCK 2 — FIELDS
    // ========================================
    private final JPanel container;
    private final JComboBox<String> modeDropdown;
    private final MainApp app;

    // ========================================
    // BLOCK 3 — CONSTRUCTOR
    // ========================================
    public ActionPanelManager(MainApp app) {

        this.app = app;

        container = new JPanel(new BorderLayout());

        modeDropdown = new JComboBox<>(new String[]{
                "View Scan",
                "View TCP Dump",
                "Possible Services",
                "Duplicate IP Suspects",
                "RTT Clusters",
                "Topology Map",
                "Dark Devices",
                "Network Noise Summary",
                "OUI Metadata",
                "SNMP Walk"
        });

        modeDropdown.addActionListener(e -> refreshPanel());

        container.add(modeDropdown, BorderLayout.NORTH);

        refreshPanel();
    }

    // ========================================
    // BLOCK 4 — GET PANEL
    // ========================================
    public JPanel getPanel() {
        return container;
    }

    // ========================================
    // BLOCK 5 — REFRESH PANEL
    // ========================================
    private void refreshPanel() {

        String selected = (String) modeDropdown.getSelectedItem();

        if (container.getComponentCount() > 1) {
            container.remove(1);
        }

        JPanel dynamic = new JPanel(new FlowLayout(FlowLayout.LEFT));

        switch (selected) {

            case "View Scan":
                JButton viewBtn = new JButton("Show Scan");
                viewBtn.addActionListener(e -> app.viewRawScan());
                dynamic.add(viewBtn);
                break;

            case "View TCP Dump":
                JButton tcpdumpViewBtn = new JButton("Show TCP Dump");
                tcpdumpViewBtn.addActionListener(e -> app.viewTcpdumpCapture());
                dynamic.add(tcpdumpViewBtn);
                break;

            case "Possible Services":
                JButton fsBtn = new JButton("Show Possible Services");
                fsBtn.addActionListener(e -> app.showPossibleServices());
                dynamic.add(fsBtn);
                break;

            case "Duplicate IP Suspects":
                JButton dupSusBtn = new JButton("Show Duplicate IP Suspects");
                dupSusBtn.addActionListener(e -> app.showDuplicateIpSuspects());
                dynamic.add(dupSusBtn);
                break;

            case "RTT Clusters":
                JButton clusterBtn = new JButton("Run Clustering");
                clusterBtn.addActionListener(e -> app.showRttClusters());
                dynamic.add(clusterBtn);
                break;

            case "Topology Map":
                JButton topoBtn = new JButton("Build Topology");
                topoBtn.addActionListener(e -> app.showTopology());
                dynamic.add(topoBtn);
                break;

            case "Dark Devices":
                JPanel darkStack = new JPanel();
                darkStack.setLayout(new BoxLayout(darkStack, BoxLayout.Y_AXIS));

                JButton darkBtn = new JButton("Find Dark Devices");
                darkBtn.addActionListener(e -> app.showDarkDevices());
                darkStack.add(darkBtn);

                JButton monitorDarkBtn = new JButton("Monitor Selected Node");
                monitorDarkBtn.addActionListener(e -> app.monitorSelectedDarkDevice());
                darkStack.add(monitorDarkBtn);

                JButton stopMonitorBtn = new JButton("Stop Monitor");
                stopMonitorBtn.addActionListener(e -> app.stopDarkDeviceMonitor());
                darkStack.add(stopMonitorBtn);

                dynamic.add(darkStack);
                break;

            case "Network Noise Summary":
                JButton noiseBtn = new JButton("Show Noise Summary");
                noiseBtn.addActionListener(e -> app.showNetworkNoiseSummary());
                dynamic.add(noiseBtn);
                break;

            case "OUI Metadata":
                JPanel ouiStack = new JPanel();
                ouiStack.setLayout(new BoxLayout(ouiStack, BoxLayout.Y_AXIS));

                JButton ouiShowBtn = new JButton("Show Selected OUI");
                ouiShowBtn.addActionListener(e -> app.showSelectedOuiMetadata());
                ouiStack.add(ouiShowBtn);

                JButton ouiMarkCriticalBtn = new JButton("Mark Critical Infra");
                ouiMarkCriticalBtn.addActionListener(e -> app.setSelectedOuiCriticalInfrastructure(true));
                ouiStack.add(ouiMarkCriticalBtn);

                JButton ouiUnmarkCriticalBtn = new JButton("Unmark Critical Infra");
                ouiUnmarkCriticalBtn.addActionListener(e -> app.setSelectedOuiCriticalInfrastructure(false));
                ouiStack.add(ouiUnmarkCriticalBtn);

                dynamic.add(ouiStack);
                break;

            case "SNMP Walk":
                JPanel snmpStack = new JPanel();
                snmpStack.setLayout(new BoxLayout(snmpStack, BoxLayout.Y_AXIS));

                JButton snmpRunBtn = new JButton("Walk Selected Node");
                snmpRunBtn.addActionListener(e -> app.runSnmpWalkForSelectedNode());
                snmpStack.add(snmpRunBtn);

                dynamic.add(snmpStack);
                break;
        }

        container.add(dynamic, BorderLayout.CENTER);
        container.revalidate();
        container.repaint();
    }
}
