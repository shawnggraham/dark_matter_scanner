package dark_matter_scanner;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

// ========================================
// BLOCK 1 — TOPOLOGY GRAPH PANEL
// ========================================
public class TopologyGraphPanel extends JPanel {

    // ========================================
    // BLOCK 2 — GRAPH MODEL CLASSES
    // ========================================
    public static class GraphNode {
        public final String ip;
        public final String mac;
        public final String vendor;
        public final String roleHint;
        public final double rtt;
        public final String responseType;
        public final int seenCount;
        public final boolean darkObserved;

        public GraphNode(String ip, String mac, String vendor, double rtt, String responseType) {
            this(ip, mac, vendor, "", rtt, responseType, 0, false);
        }

        public GraphNode(String ip, String mac, String vendor, String roleHint, double rtt, String responseType) {
            this(ip, mac, vendor, roleHint, rtt, responseType, 0, false);
        }

        public GraphNode(
                String ip,
                String mac,
                String vendor,
                String roleHint,
                double rtt,
                String responseType,
                int seenCount,
                boolean darkObserved
        ) {
            this.ip = ip;
            this.mac = mac;
            this.vendor = vendor;
            this.roleHint = roleHint;
            this.rtt = rtt;
            this.responseType = responseType;
            this.seenCount = seenCount;
            this.darkObserved = darkObserved;
        }
    }

    public static class GraphCluster {
        public final String name;
        public final double minRtt;
        public final double maxRtt;
        public final double avgRtt;
        public final boolean bridgeToPrevious;
        public final List<GraphNode> nodes;

        public GraphCluster(String name, double minRtt, double maxRtt, double avgRtt, boolean bridgeToPrevious, List<GraphNode> nodes) {
            this.name = name;
            this.minRtt = minRtt;
            this.maxRtt = maxRtt;
            this.avgRtt = avgRtt;
            this.bridgeToPrevious = bridgeToPrevious;
            this.nodes = nodes;
        }
    }

    // ========================================
    // BLOCK 3 — FIELDS
    // ========================================
    private String routerIp = "Router";
    private double routerRtt = 0.0;
    private List<GraphCluster> clusters = new ArrayList<>();
    private List<GraphNode> outliers = new ArrayList<>();
    private List<GraphNode> darkObservedNodes = new ArrayList<>();
    private double zoomFactor = 1.0;
    private int baseGraphWidth = 1400;
    private int baseGraphHeight = 900;

    private static final int LEFT_MARGIN = 80;
    private static final int TOP_MARGIN = 80;
    private static final int COLUMN_WIDTH = 260;
    private static final int NODE_HEIGHT = 82;
    private static final int NODE_WIDTH = 200;
    private static final int NODE_GAP = 20;
    private static final int CLUSTER_HEADER_HEIGHT = 55;
    private static final int ROUTER_X = 80;

    // ========================================
    // BLOCK 4 — CONSTRUCTOR
    // ========================================
    public TopologyGraphPanel() {
        setBackground(Color.WHITE);
        setOpaque(true);
        setPreferredSize(new Dimension(1400, 900));
        ToolTipManager.sharedInstance().registerComponent(this);
    }

    // ========================================
    // BLOCK 5 — SET GRAPH DATA
    // ========================================
    public void setGraphData(String routerIp,
                             double routerRtt,
                             List<GraphCluster> clusters,
                             List<GraphNode> outliers,
                             List<GraphNode> darkObservedNodes) {

        this.routerIp = (routerIp != null && !routerIp.isBlank()) ? routerIp : "Router";
        this.routerRtt = routerRtt;
        this.clusters = (clusters != null) ? clusters : new ArrayList<>();
        this.outliers = (outliers != null) ? outliers : new ArrayList<>();
        this.darkObservedNodes = (darkObservedNodes != null) ? darkObservedNodes : new ArrayList<>();

        int maxNodesInColumn = 1;

        for (GraphCluster cluster : this.clusters) {
            if (cluster.nodes.size() > maxNodesInColumn) {
                maxNodesInColumn = cluster.nodes.size();
            }
        }

        if (this.outliers.size() > maxNodesInColumn) {
            maxNodesInColumn = this.outliers.size();
        }
        if (this.darkObservedNodes.size() > maxNodesInColumn) {
            maxNodesInColumn = this.darkObservedNodes.size();
        }

        int rightPaneWidth = (this.darkObservedNodes != null && !this.darkObservedNodes.isEmpty()) ? 620 : 400;
        baseGraphWidth = Math.max(LEFT_MARGIN + 250 + (this.clusters.size() * COLUMN_WIDTH) + rightPaneWidth, 1400);
        baseGraphHeight = Math.max(TOP_MARGIN + 150 + (maxNodesInColumn * (NODE_HEIGHT + NODE_GAP)) + 300, 900);

        applyScaledPreferredSize();
    }

    public void setZoomFactor(double zoomFactor) {
        double clamped = Math.max(0.25, Math.min(1.50, zoomFactor));
        this.zoomFactor = clamped;
        applyScaledPreferredSize();
    }

    private void applyScaledPreferredSize() {
        int scaledWidth = (int) Math.round(baseGraphWidth * zoomFactor);
        int scaledHeight = (int) Math.round(baseGraphHeight * zoomFactor);
        setPreferredSize(new Dimension(Math.max(350, scaledWidth), Math.max(250, scaledHeight)));
        revalidate();
        repaint();
    }

    // ========================================
    // BLOCK 6 — PAINT COMPONENT
    // ========================================
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);

        Graphics2D g2 = (Graphics2D) g.create();

        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.scale(zoomFactor, zoomFactor);

            drawTitle(g2);
            drawRouter(g2);
            drawClusters(g2);
            drawOutliers(g2);
            drawDarkObserved(g2);

        } finally {
            g2.dispose();
        }
    }

    // ========================================
    // BLOCK 7 — DRAW TITLE
    // ========================================
    private void drawTitle(Graphics2D g2) {
        g2.setColor(Color.BLACK);
        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 18));
        g2.drawString("Topology Map / RTT Proximity Graph", LEFT_MARGIN, 35);

        g2.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
        g2.drawString("Heuristic view only — clusters are based on RTT similarity, not proven physical topology.", LEFT_MARGIN, 55);
    }

    // ========================================
    // BLOCK 8 — DRAW ROUTER
    // ========================================
    private void drawRouter(Graphics2D g2) {

        int x = ROUTER_X;
        int y = TOP_MARGIN + 180;
        int w = 170;
        int h = 80;

        g2.setColor(new Color(230, 230, 250));
        g2.fillRoundRect(x, y, w, h, 18, 18);

        g2.setColor(Color.BLACK);
        g2.setStroke(new BasicStroke(2f));
        g2.drawRoundRect(x, y, w, h, 18, 18);

        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
        g2.drawString("Router / Anchor", x + 18, y + 24);

        g2.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        g2.drawString(routerIp, x + 18, y + 44);
        g2.drawString(String.format("RTT %.3f ms", routerRtt), x + 18, y + 62);
    }

    // ========================================
    // BLOCK 9 — DRAW CLUSTERS
    // ========================================
    private void drawClusters(Graphics2D g2) {

        int routerCenterX = ROUTER_X + 170;
        int routerCenterY = TOP_MARGIN + 220;

        int clusterIndex = 0;

        for (GraphCluster cluster : clusters) {

            int columnX = LEFT_MARGIN + 240 + (clusterIndex * COLUMN_WIDTH);
            int headerY = TOP_MARGIN;

            // --- Header ---
            g2.setColor(new Color(220, 245, 220));
            g2.fillRoundRect(columnX, headerY, 210, CLUSTER_HEADER_HEIGHT, 16, 16);

            g2.setColor(Color.BLACK);
            g2.setStroke(new BasicStroke(2f));
            g2.drawRoundRect(columnX, headerY, 210, CLUSTER_HEADER_HEIGHT, 16, 16);

            g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
            g2.drawString(cluster.name, columnX + 12, headerY + 20);

            g2.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
            g2.drawString(String.format("Avg %.3f ms", cluster.avgRtt), columnX + 12, headerY + 36);
            g2.drawString(String.format("%d nodes", cluster.nodes.size()), columnX + 110, headerY + 36);

            // --- Main line ---
            int clusterLineX = columnX + 100;
            int clusterLineTop = headerY + CLUSTER_HEADER_HEIGHT;
            int clusterLineBottom = clusterLineTop + Math.max(50, cluster.nodes.size() * (NODE_HEIGHT + NODE_GAP) - NODE_GAP);

            g2.setColor(Color.GRAY);
            g2.setStroke(new BasicStroke(2f));
            g2.drawLine(clusterLineX, clusterLineTop, clusterLineX, clusterLineBottom);

            // --- Link from previous layer / router ---
            int targetY = headerY + 28;

            if (clusterIndex == 0) {
                g2.drawLine(routerCenterX, routerCenterY, columnX, targetY);
            } else if (cluster.bridgeToPrevious) {
                int prevColumnX = LEFT_MARGIN + 240 + ((clusterIndex - 1) * COLUMN_WIDTH);
                int prevCenterX = prevColumnX + 210;
                int prevCenterY = TOP_MARGIN + 28;
                g2.drawLine(prevCenterX, prevCenterY, columnX, targetY);
            }

            // --- Nodes ---
            int startY = TOP_MARGIN + 90;

            for (int i = 0; i < cluster.nodes.size(); i++) {
                GraphNode node = cluster.nodes.get(i);

                int nodeX = columnX + 5;
                int nodeY = startY + (i * (NODE_HEIGHT + NODE_GAP));

                drawNodeBox(g2, nodeX, nodeY, NODE_WIDTH, NODE_HEIGHT, node);

                g2.setColor(Color.GRAY);
                g2.setStroke(new BasicStroke(1.5f));
                g2.drawLine(clusterLineX, nodeY + (NODE_HEIGHT / 2), nodeX, nodeY + (NODE_HEIGHT / 2));
            }

            clusterIndex++;
        }
    }

    // ========================================
    // BLOCK 10 — DRAW OUTLIERS
    // ========================================
    private void drawOutliers(Graphics2D g2) {

        if (outliers == null || outliers.isEmpty()) {
            return;
        }

        int startX = 20;
        int startY = TOP_MARGIN + 320;

        g2.setColor(new Color(255, 245, 220));
        g2.fillRoundRect(startX, startY - 40, 220, 35, 14, 14);

        g2.setColor(Color.BLACK);
        g2.drawRoundRect(startX, startY - 40, 220, 35, 14, 14);

        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        g2.drawString("Outliers / Far Nodes", startX + 12, startY - 18);

        for (int i = 0; i < outliers.size(); i++) {
            GraphNode node = outliers.get(i);
            int nodeY = startY + (i * (NODE_HEIGHT + 10));
            drawNodeBox(g2, startX, nodeY, NODE_WIDTH, NODE_HEIGHT, node);
        }
    }

    private void drawDarkObserved(Graphics2D g2) {

        if (darkObservedNodes == null || darkObservedNodes.isEmpty()) {
            return;
        }

        int startX = LEFT_MARGIN + 240 + (clusters.size() * COLUMN_WIDTH) + 40;
        int startY = TOP_MARGIN + 90;

        g2.setColor(new Color(255, 238, 238));
        g2.fillRoundRect(startX, TOP_MARGIN, 260, 55, 14, 14);

        g2.setColor(Color.BLACK);
        g2.drawRoundRect(startX, TOP_MARGIN, 260, 55, 14, 14);

        g2.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 13));
        g2.drawString("Dark Observed Devices", startX + 12, TOP_MARGIN + 22);

        g2.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        g2.drawString(String.format("%d nodes (no RTT cluster)", darkObservedNodes.size()), startX + 12, TOP_MARGIN + 40);

        for (int i = 0; i < darkObservedNodes.size(); i++) {
            GraphNode node = darkObservedNodes.get(i);
            int nodeY = startY + (i * (NODE_HEIGHT + 10));
            drawNodeBox(g2, startX, nodeY, NODE_WIDTH, NODE_HEIGHT, node);
        }
    }

    // ========================================
    // BLOCK 11 — DRAW NODE BOX
    // ========================================
    private void drawNodeBox(Graphics2D g2, int x, int y, int w, int h, GraphNode node) {

        if (node.darkObserved) {
            g2.setColor(new Color(255, 242, 242));
        } else {
            g2.setColor(new Color(235, 245, 255));
        }
        g2.fillRoundRect(x, y, w, h, 16, 16);

        g2.setColor(Color.BLACK);
        g2.setStroke(new BasicStroke(1.5f));
        g2.drawRoundRect(x, y, w, h, 16, 16);

        g2.setFont(new Font(Font.MONOSPACED, Font.BOLD, 11));
        g2.drawString(trim(node.ip, 16), x + 10, y + 18);

        g2.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 10));
        g2.drawString(trim(node.mac, 20), x + 10, y + 34);
        g2.drawString(trim(node.vendor, 22), x + 10, y + 49);

        if (node.darkObserved) {
            g2.drawString(String.format("Seen %d", node.seenCount), x + 10, y + 63);
        } else {
            g2.drawString(String.format("RTT %.3f", node.rtt), x + 10, y + 63);
        }

        if (node.roleHint != null && !node.roleHint.isBlank()) {
            g2.setFont(new Font(Font.MONOSPACED, Font.BOLD, 9));
            g2.drawString(trim(node.roleHint, 22), x + 10, y + 75);
        }
    }

    // ========================================
    // BLOCK 12 — TRIM
    // ========================================
    private String trim(String value, int max) {
        if (value == null) {
            return "";
        }
        if (value.length() <= max) {
            return value;
        }
        return value.substring(0, Math.max(0, max - 3)) + "...";
    }
}
