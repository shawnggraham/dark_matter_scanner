package dark_matter_scanner;

import com.jcraft.jsch.*;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

// ========================================
// BLOCK 1 — SCAN EXECUTOR
// ========================================
public class ScanExecutor {

    // ========================================
    // BLOCK 2 — RUN LOCAL
    // ========================================
    public String runLocal(List<String> command) throws Exception {

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process p = pb.start();

        StringBuilder out = new StringBuilder();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8)
        )) {
            String line;
            while ((line = reader.readLine()) != null) {
                out.append(line).append("\n");
            }
        }

        p.waitFor();

        return out.toString();
    }

    // ========================================
    // BLOCK 3 — RUN SSH
    // ========================================
    public String runSSH(String host, String user, String pass, String cmd) throws Exception {

        Session session = new JSch().getSession(user, host, 22);
        session.setPassword(pass);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        session.setConfig(config);

        session.connect();

        ChannelExec channel = (ChannelExec) session.openChannel("exec");
        channel.setCommand(cmd);

        java.io.ByteArrayOutputStream outputStream = new java.io.ByteArrayOutputStream();
        channel.setOutputStream(outputStream);
        channel.setErrStream(outputStream);

        channel.connect();

        while (!channel.isClosed()) {
            Thread.sleep(200);
        }

        String output = outputStream.toString();

        channel.disconnect();
        session.disconnect();

        return output;
    }

    // ========================================
    // BLOCK 4 — START LOCAL STREAMING
    // ========================================
    public RunningCapture startLocalStreaming(List<String> command, Consumer<String> onLine) throws Exception {

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);

        Process process = pb.start();

        RunningCapture capture = new RunningCapture();
        capture.process = process;

        Thread readerThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)
            )) {
                String line;
                while ((line = reader.readLine()) != null) {
                    capture.output.append(line).append("\n");

                    if (onLine != null) {
                        onLine.accept(line);
                    }
                }
            } catch (Exception e) {
                capture.readerError = e;
            } finally {
                try {
                    capture.exitCode = process.waitFor();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                capture.running.set(false);
            }
        }, "dms-local-capture-reader");

        capture.readerThread = readerThread;
        readerThread.setDaemon(true);
        readerThread.start();

        return capture;
    }

    // ========================================
    // BLOCK 5 — START SSH STREAMING
    // ========================================
    public RunningCapture startSSHStreaming(String host, String user, String pass, String shellCommand, Consumer<String> onLine) throws Exception {

        Session session = new JSch().getSession(user, host, 22);
        session.setPassword(pass);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        config.put("PreferredAuthentications", "password,keyboard-interactive");
        session.setConfig(config);

        session.connect();

        ChannelExec channel = (ChannelExec) session.openChannel("exec");

        String wrappedCommand = "sh -c " + shellQuote(shellCommand + " 2>&1");
        channel.setCommand(wrappedCommand);
        channel.setInputStream(null);

        InputStream inputStream = channel.getInputStream();
        channel.connect();

        RunningCapture capture = new RunningCapture();
        capture.session = session;
        capture.channel = channel;

        Thread readerThread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(inputStream, StandardCharsets.UTF_8)
            )) {
                String line;
                while ((line = reader.readLine()) != null) {
                    capture.output.append(line).append("\n");

                    if (onLine != null) {
                        onLine.accept(line);
                    }
                }
            } catch (Exception e) {
                capture.readerError = e;
            } finally {
                try {
                    for (int i = 0; i < 20; i++) {
                        if (channel.isClosed()) {
                            break;
                        }
                        Thread.sleep(100);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }

                capture.exitCode = channel.getExitStatus();

                try {
                    if (channel.isConnected()) {
                        channel.disconnect();
                    }
                } catch (Exception ignored) {
                }

                try {
                    if (session.isConnected()) {
                        session.disconnect();
                    }
                } catch (Exception ignored) {
                }

                capture.running.set(false);
            }
        }, "dms-ssh-capture-reader");

        capture.readerThread = readerThread;
        readerThread.setDaemon(true);
        readerThread.start();

        return capture;
    }

    // ========================================
    // BLOCK 6 — SHELL QUOTE
    // ========================================
    private String shellQuote(String value) {
        return "'" + value.replace("'", "'\"'\"'") + "'";
    }

    // ========================================
    // BLOCK 7 — RUNNING CAPTURE
    // ========================================
    public static class RunningCapture {
        private Process process;
        private Session session;
        private ChannelExec channel;
        private Thread readerThread;

        private final StringBuffer output = new StringBuffer();
        private final AtomicBoolean running = new AtomicBoolean(true);

        private volatile Integer exitCode = null;
        private volatile Exception readerError = null;

        public boolean isRunning() {
            return running.get();
        }

        public String getOutput() {
            return output.toString();
        }

        public Integer getExitCode() {
            return exitCode;
        }

        public Exception getReaderError() {
            return readerError;
        }

        public void stop() {
            try {
                if (process != null) {
                    process.destroy();
                }
            } catch (Exception ignored) {
            }

            try {
                if (channel != null && channel.isConnected()) {
                    channel.disconnect();
                }
            } catch (Exception ignored) {
            }

            try {
                if (session != null && session.isConnected()) {
                    session.disconnect();
                }
            } catch (Exception ignored) {
            }

            running.set(false);
        }
    }
}