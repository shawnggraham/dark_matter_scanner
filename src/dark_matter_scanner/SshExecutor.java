// ========================================
// BLOCK 0 — PACKAGE + IMPORTS
// ========================================
package dark_matter_scanner;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

// ========================================
// BLOCK 1 — SSH EXECUTOR
// ========================================
public class SshExecutor {

    // ========================================
    // BLOCK 2 — TEST CONNECTION
    // ========================================
    public String testConnection(String host, String user, String pass) throws Exception {

        Session session = null;

        try {
            session = createSession(host, user, pass);
            session.connect(10000);

            return "SSH connection successful to " + host;

        } finally {
            disconnectSession(session);
        }
    }

    // ========================================
    // BLOCK 3 — RUN COMMAND
    // ========================================
    public String runCommand(String host, String user, String pass, String command) throws Exception {

        Session session = null;
        ChannelExec channel = null;

        try {
            session = createSession(host, user, pass);
            session.connect(10000);

            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            channel.setInputStream(null);

            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();

            channel.setOutputStream(stdout);
            channel.setErrStream(stderr);

            channel.connect(10000);

            while (!channel.isClosed()) {
                Thread.sleep(200);
            }

            String outText = stdout.toString(StandardCharsets.UTF_8);
            String errText = stderr.toString(StandardCharsets.UTF_8);
            int exitCode = channel.getExitStatus();

            StringBuilder result = new StringBuilder();

            result.append("COMMAND: ").append(command).append("\n");
            result.append("EXIT CODE: ").append(exitCode).append("\n");

            if (!outText.isBlank()) {
                result.append("\n--- STDOUT ---\n");
                result.append(outText);
            }

            if (!errText.isBlank()) {
                result.append("\n--- STDERR ---\n");
                result.append(errText);
            }

            return result.toString();

        } finally {
            disconnectChannel(channel);
            disconnectSession(session);
        }
    }

    // ========================================
    // BLOCK 4 — CREATE SESSION
    // ========================================
    private Session createSession(String host, String user, String pass) throws Exception {

        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("Host is required.");
        }

        if (user == null || user.isBlank()) {
            throw new IllegalArgumentException("User is required.");
        }

        JSch jsch = new JSch();
        Session session = jsch.getSession(user.trim(), host.trim(), 22);
        session.setPassword(pass);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        config.put("PreferredAuthentications", "password,keyboard-interactive");
        session.setConfig(config);

        return session;
    }

    // ========================================
    // BLOCK 5 — DISCONNECT CHANNEL
    // ========================================
    private void disconnectChannel(ChannelExec channel) {

        try {
            if (channel != null && channel.isConnected()) {
                channel.disconnect();
            }
        } catch (Exception ignored) {
        }
    }

    // ========================================
    // BLOCK 6 — DISCONNECT SESSION
    // ========================================
    private void disconnectSession(Session session) {

        try {
            if (session != null && session.isConnected()) {
                session.disconnect();
            }
        } catch (Exception ignored) {
        }
    }
}