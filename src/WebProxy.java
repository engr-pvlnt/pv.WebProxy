import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

public class WebProxy {
    private static final int PROXY_PORT = 8888;
    private static final Set<String> BLOCKED_WEBSITES = new ConcurrentSkipListSet<>();
    private static final Set<String> BLOCKED_WORDS = new ConcurrentSkipListSet<>();
    private static final String BLOCKLIST_FILE = "blocklist.txt";
    private static final String WORDLIST_FILE = "wordlist.txt";
    private static final String LOG_FILE = "proxy.log";
    private static final int MAX_THREADS = 20;
    private static final ExecutorService executor = Executors.newFixedThreadPool(MAX_THREADS);
    private static final DateTimeFormatter LOG_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    public static final String PROXY_VERSION = "pv.WebProxy v1.0";
    private static ServerSocket serverSocket;
    private static boolean enableLogging = true; // Added logging control flag

    public static void main(String[] args) {
        System.out.println(PROXY_VERSION + " starting on port " + PROXY_PORT);
        System.out.println("Coded by: p.velante@gmail.com");
        log("Proxy server starting on port " + PROXY_PORT);

        loadBlockedWebsites(BLOCKLIST_FILE);
        loadBlockedWords(WORDLIST_FILE);

        new Thread(() -> listenForConsoleCommands()).start();

        try {
            serverSocket = new ServerSocket(PROXY_PORT);
            System.out.println("Proxy server started. Listening for connections...");
            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    executor.submit(new ProxyHandler(clientSocket));
                } catch (IOException e) {
                    log("Error accepting client connection: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Error starting the proxy server: " + e.getMessage());
            log("Error starting the proxy server: " + e.getMessage());
        } finally {
            shutdownExecutor();
        }
    }

    private static void listenForConsoleCommands() {
        try (Scanner scanner = new Scanner(System.in)) {
            while (true) {
                System.out.println("Enter command (reload, exit, log on, log off):");
                String command = scanner.nextLine().trim().toLowerCase();

                switch (command) {
                    case "reload":
                        reloadLists();
                        break;
                    case "exit":
                        System.out.println("Exiting proxy server...");
                        log("Proxy server exiting due to console command.");
                        shutdown();
                        return;
                    case "log on": //Added command
                        enableLogging = true;
                        System.out.println("Logging enabled.");
                        log("Logging enabled via console command.");
                        break;
                    case "log off": //Added command
                        enableLogging = false;
                        System.out.println("Logging disabled.");
                        log("Logging disabled via console command.");
                        break;
                    default:
                        System.out.println("Unknown command.");
                }
            }
        }
    }

    public static void reloadLists() {
        System.out.println("Reloading blocklists...");
        log("Reloading blocklists due to console command.");
        BLOCKED_WEBSITES.clear();
        BLOCKED_WORDS.clear();
        loadBlockedWebsites(BLOCKLIST_FILE);
        loadBlockedWords(WORDLIST_FILE);
        System.out.println("Blocklists reloaded.");
        log("Blocklists reloaded successfully.");
    }

    public static void shutdown() {
        System.out.println("Shutting down the proxy server...");
        log("Proxy server shutting down...");

        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            System.err.println("Error closing server socket: " + e.getMessage());
            log("Error closing server socket during shutdown: " + e.getMessage());
        }

        shutdownExecutor();

        System.exit(0);
    }

    private static void shutdownExecutor() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                System.err.println("Executor did not terminate in the specified time.");
                log("Executor did not terminate in the specified time.");
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    public static void loadBlockedWebsites(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmedLine = line.trim();
                if (!trimmedLine.isEmpty()) {
                    BLOCKED_WEBSITES.add(trimmedLine);
                }
            }
            System.out.println("Blocked websites loaded: " + BLOCKED_WEBSITES);
            log("Blocked websites loaded from " + filePath + ": " + BLOCKED_WEBSITES);
        } catch (IOException e) {
            System.err.println("Error loading blocklist from file " + filePath + ": " + e.getMessage());
            log("Error loading blocklist from file " + filePath + ": " + e.getMessage());
        }
    }

    public static void loadBlockedWords(String filePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmedLine = line.trim().toLowerCase();
                if (!trimmedLine.isEmpty()) {
                    BLOCKED_WORDS.add(trimmedLine);
                }
            }
            System.out.println("Blocked words loaded: " + BLOCKED_WORDS);
            log("Blocked words loaded from " + filePath + ": " + BLOCKED_WORDS);
        } catch (IOException e) {
            System.err.println("Error loading wordlist from file " + filePath + ": " + e.getMessage());
            log("Error loading wordlist from file " + filePath + ": " + e.getMessage());
        }
    }

    public static boolean isBlocked(String host) {
        for (String blocked : BLOCKED_WEBSITES) {
            if (blocked.startsWith("*.")) {
                String domain = blocked.substring(2);
                if (host.endsWith(domain)) {
                    System.out.println("Website blocked: " + host + " (matches " + blocked + ")");
                    log("Website blocked due to wildcard match: " + host + " matches " + blocked);
                    return true;
                }
            } else if (host.equals(blocked)) {
                System.out.println("Website blocked: " + host);
                log("Website blocked: " + host + " matches " + blocked);
                return true;
            }
        }
        return false;
    }

    // Modified to check only URL and Meta Description
    public static boolean containsBlockedWord(String url, String metaDescription) {
        log("containsBlockedWord: Checking URL: " + url);
        log("containsBlockedWord: Checking Meta Description: " + metaDescription);

        String normalizedUrl = url != null ? url.toLowerCase() : "";
        String normalizedMetaDescription = metaDescription != null ? metaDescription.toLowerCase() : "";

        for (String word : BLOCKED_WORDS) {
            //Use contains instead of regex for checking if a word exists as a substring
            if (normalizedUrl.contains(word) || normalizedMetaDescription.contains(word)) {
                log("Blocked word found: " + word + " in URL or Meta Description.");
                return true;
            } else {
                log("No match for word: " + word + " in URL or Meta Description.");
            }
        }
        return false;
    }

    public static void log(String message) {
        if (enableLogging) {  // Check if logging is enabled
            try (FileWriter fw = new FileWriter(LOG_FILE, true);
                 BufferedWriter bw = new BufferedWriter(fw);
                 PrintWriter out = new PrintWriter(bw)) {
                out.println(LOG_FORMATTER.format(LocalDateTime.now()) + " - " + message);
            } catch (IOException e) {
                System.err.println("Error writing to log file: " + e.getMessage());
            }
        }
    }
}

class ProxyHandler implements Runnable {
    private final Socket clientSocket;

    public ProxyHandler(Socket clientSocket) {
        this.clientSocket = clientSocket;
    }

    @Override
    public void run() {
        try (
                InputStream clientInput = clientSocket.getInputStream();
                OutputStream clientOutput = clientSocket.getOutputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(clientInput))
        ) {
            String clientIP = clientSocket.getInetAddress().getHostAddress();
            String clientHostName = getClientHostName(clientSocket.getInetAddress());

            String requestLine = reader.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                WebProxy.log("Empty request received, closing connection.");
                return;
            }

            String[] parts = requestLine.split(" ");
            if (parts.length < 3) {
                sendErrorResponse(clientOutput, "Bad Request: Invalid request format.");
                WebProxy.log("Invalid request format: " + requestLine);
                return;
            }

            String method = parts[0];
            String target = parts[1];

            // Log the accessed website with client info
            WebProxy.log(String.format("Client IP: %s, Hostname: %s accessed: %s", clientIP, clientHostName, target));
            System.out.println(String.format("Client IP: %s, Hostname: %s accessed: %s", clientIP, clientHostName, target));
            System.out.println("Proxy server started. Listening for connections...");

            if (method.equalsIgnoreCase("CONNECT")) {
                handleConnectMethod(target, clientInput, clientOutput, clientIP, clientHostName);
                return;
            }

            String host = null;
            String resource = target;
            String line;
            Map<String, String> headers = new HashMap<>();
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                WebProxy.log("Header: " + line);
                if (line.toLowerCase().startsWith("host: ")) {
                    host = line.substring(line.indexOf(":") + 1).trim();
                }
                int colonIndex = line.indexOf(":");
                if (colonIndex > 0) {
                    String headerName = line.substring(0, colonIndex).trim();
                    String headerValue = line.substring(colonIndex + 1).trim();
                    headers.put(headerName, headerValue);
                }
            }

            if (host == null) {
                sendErrorResponse(clientOutput, "Bad Request: Missing Host header.");
                WebProxy.log("Missing Host header in request.");
                return;
            }

            String urlString = (target.startsWith("http") || target.startsWith("https")) ? target : "http://" + host + resource;

            URL url;
            try {
                url = new URL(urlString);
            } catch (MalformedURLException e) {
                sendErrorResponse(clientOutput, "Bad Request: Invalid URL.");
                WebProxy.log("Invalid URL: " + urlString);
                return;
            }

            if (WebProxy.isBlocked(url.getHost())) {
                sendBlockedResponse(clientOutput, url.toString());
                return;
            }

            // Fetch the meta description of the page
            String pageDescription = fetchPageContent(url, headers);

            // Check if the URL or Meta Description contains blocked words
            if (WebProxy.containsBlockedWord(url.toString(), pageDescription)) {
                sendBlockedResponse(clientOutput, url.toString());
                return;
            }

            forwardHttpRequest(url, method, clientOutput, headers);

        } catch (IOException e) {
            System.err.println("Proxy handler exception: " + e.getMessage());
            WebProxy.log("Proxy handler exception: " + e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                System.err.println("Error closing client socket: " + e.getMessage());
                WebProxy.log("Error closing client socket: " + e.getMessage());
            }
        }
    }

    // Helper method to get the hostname from InetAddress
    private String getClientHostName(InetAddress inetAddress) {
        try {
            return inetAddress.getHostName();
        } catch (Exception e) {
            WebProxy.log("Error getting hostname: " + e.getMessage());
            return "Unknown";
        }
    }

    private void handleConnectMethod(String target, InputStream clientInput, OutputStream clientOutput, String clientIP, String clientHostName) {
        String[] hostPort = target.split(":");
        if (hostPort.length != 2) {
            sendErrorResponse(clientOutput, "Bad Request: Invalid CONNECT target.");
            WebProxy.log("Invalid CONNECT target: " + target);
            return;
        }

        String host = hostPort[0];
        int port;
        try {
            port = Integer.parseInt(hostPort[1]);
        } catch (NumberFormatException e) {
            sendErrorResponse(clientOutput, "Bad Request: Invalid port.");
            WebProxy.log("Invalid port in CONNECT target: " + target);
            return;
        }

        if (WebProxy.isBlocked(host)) {
            sendBlockedResponse(clientOutput, host);
            return;
        }

        try (Socket serverSocket = new Socket(host, port)) {
            clientOutput.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes());
            clientOutput.flush();

            WebProxy.log("CONNECT Tunnel established to " + host + ":" + port);
            // Log the accessed website with client info for CONNECT method
            WebProxy.log(String.format("Client IP: %s, Hostname: %s established CONNECT tunnel to: %s:%d", clientIP, clientHostName, host, port));
            System.out.println(String.format("Client IP: %s, Hostname: %s established CONNECT tunnel to: %s:%d", clientIP, clientHostName, host, port));


            ExecutorService tunnelExecutor = Executors.newFixedThreadPool(2);
            tunnelExecutor.submit(() -> forwardData(serverSocket, clientSocket));
            tunnelExecutor.submit(() -> forwardData(clientSocket, serverSocket));

            tunnelExecutor.shutdown();
            try {
                tunnelExecutor.awaitTermination(60, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                WebProxy.log("Tunnel forwarding threads interrupted: " + e.getMessage());
                tunnelExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }

        } catch (IOException e) {
            sendErrorResponse(clientOutput, "Bad Gateway: " + e.getMessage());
            WebProxy.log("Error establishing CONNECT tunnel to " + host + ":" + port + ": " + e.getMessage());
        }
    }

    private void forwardData(Socket fromSocket, Socket toSocket) {
        try (InputStream fromInput = fromSocket.getInputStream();
             OutputStream toOutput = toSocket.getOutputStream()) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fromInput.read(buffer)) != -1) {
                toOutput.write(buffer, 0, bytesRead);
                toOutput.flush();
            }
        } catch (IOException e) {
            WebProxy.log("Data forwarding I/O error: " + e.getMessage());
        } finally {
            closeSocket(fromSocket);
            closeSocket(toSocket);
        }
    }

    private void closeSocket(Socket socket) {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            System.err.println("Error closing socket: " + e.getMessage());
            WebProxy.log("Error closing socket: " + e.getMessage());
        }
    }

    private String fetchPageContent(URL url, Map<String, String> headers) {
        String description = null;
        HttpURLConnection connection = null;

        try {
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
            connection.setRequestProperty("Connection", "close");

            int responseCode = connection.getResponseCode();
            WebProxy.log("Fetching content from " + url + ", response code: " + responseCode);

            if (responseCode >= 400) {
                WebProxy.log("Error response code fetching content: " + responseCode + " from " + url);
                return null;
            }

            String contentType = connection.getContentType();
            WebProxy.log("Content Type: " + contentType); // Log the content type
            if (contentType != null && !contentType.toLowerCase().contains("text/html")) {
                WebProxy.log("Content type is not text/html, skipping content check.");
                return null;
            }

            String encoding = connection.getContentEncoding();
            InputStream inputStream = connection.getInputStream();
            if ("gzip".equalsIgnoreCase(encoding)) {
                inputStream = new java.util.zip.GZIPInputStream(inputStream);
            }

            Document doc = Jsoup.parse(inputStream, null, url.toString());
            Elements metaTags = doc.select("meta[name=description]");

            if (metaTags.hasAttr("content")) {
                description = metaTags.attr("content");
                WebProxy.log("Meta description: " + description);

            } else {
                WebProxy.log("Meta description tag not found");
                description = ""; // Set to empty string to avoid null pointer
            }

        } catch (IOException e) {
            System.err.println("Error fetching page content: " + e.getMessage());
            WebProxy.log("Error fetching page content from " + url + ": " + e.getMessage());
            return null;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }

        return description;
    }

    private void sendBlockedResponse(OutputStream clientOutput, String blockedUrl) {
        try {
            System.out.println("Blocked access to: " + blockedUrl);
            WebProxy.log("URL is blocked: " + blockedUrl);
            String response = "HTTP/1.1 403 Forbidden\r\n" +
                    "Content-Type: text/html\r\n" +
                    "Content-Length: " + BLOCKED_RESPONSE_BODY.getBytes().length + "\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    BLOCKED_RESPONSE_BODY;

            clientOutput.write(response.getBytes());
            clientOutput.flush();
        } catch (IOException e) {
            System.err.println("Error sending blocked response: " + e.getMessage());
            WebProxy.log("Error sending blocked response for " + blockedUrl + ": " + e.getMessage());
        }
    }

    private static final String BLOCKED_RESPONSE_BODY =
            "<html>" +
                    "<head><title>403 Forbidden</title></head>" +
                    "<body>" +
                    "<h1>403 Forbidden</h1>" +
                    "<p>Access to this content is blocked by the proxy server.</p>" +
                    "<hr><p>" + WebProxy.PROXY_VERSION + "</p>" +
                    "</body>" +
                    "</html>";

    private void sendErrorResponse(OutputStream clientOutput, String message) {
        try {
            String response = "HTTP/1.1 400 Bad Request\r\n" +
                    "Content-Type: text/html\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    "<html><body><h1>400 Bad Request</h1><p>" + message + "</p><hr><p>" + WebProxy.PROXY_VERSION + "</p></body></html>";
            clientOutput.write(response.getBytes());
            clientOutput.flush();
        } catch (IOException e) {
            System.err.println("Error sending error response: " + e.getMessage());
            WebProxy.log("Error sending error response: " + e.getMessage());
        }
    }

    private void forwardHttpRequest(URL url, String method, OutputStream clientOutput, Map<String, String> headers) {
        HttpURLConnection connection = null;
        try {
            int port = url.getPort() == -1 ? 80 : url.getPort();
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(method);
            connection.setDoInput(true);
            connection.setDoOutput(false);

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
            }
            connection.setRequestProperty("Connection", "close");

            WebProxy.log("Forwarding request: " + method + " " + url);

            int responseCode = connection.getResponseCode();
            WebProxy.log("Received response code: " + responseCode + " from " + url);

            StringBuilder responseHeader = new StringBuilder();
            responseHeader.append("HTTP/1.1 ").append(responseCode).append(" ").append(connection.getResponseMessage()).append("\r\n");
            for (Map.Entry<String, List<String>> header : connection.getHeaderFields().entrySet()) {
                if (header.getKey() != null) {
                    for (String value : header.getValue()) {
                        responseHeader.append(header.getKey()).append(": ").append(value).append("\r\n");
                    }
                }
            }
            responseHeader.append("Connection: close\r\n");
            responseHeader.append("\r\n");

            byte[] headerBytes = responseHeader.toString().getBytes();
            clientOutput.write(headerBytes);
            clientOutput.flush();

            try (InputStream serverInput = connection.getInputStream()) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = serverInput.read(buffer)) != -1) {
                    clientOutput.write(buffer, 0, bytesRead);
                    clientOutput.flush();
                }
            } catch (IOException e) {
                WebProxy.log("Error reading response body from server: " + e.getMessage());
            }

        } catch (IOException e) {
            System.err.println("Error forwarding HTTP request: " + e.getMessage());
            WebProxy.log("Error forwarding HTTP request to " + url + ": " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}