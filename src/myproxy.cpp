#include <iostream>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <csignal>
#include <thread>
#include <queue>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstring>
#include <poll.h> 
#include <chrono>
#include <string>
#include <vector>
#include <unordered_map>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <iomanip>
#include <cctype> 
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <functional>
#include <poll.h>
#include <sstream>
#include <regex>
#include <openssl/bio.h> 
#include <openssl/ssl.h> 
#include <openssl/ssl.h>
#include <openssl/err.h> 
#include <cstdlib>
#include <sys/stat.h> 
#include <cerrno> 
#include <filesystem> 

std::mutex coutMutex;
std::mutex cerrMutex;

template<typename T>
void safePrintStdOut(const T& msg) {
    std::lock_guard<std::mutex> guard(coutMutex);
    std::cout << msg << std::endl;
}

template<typename T>
void safePrintStdErr(const T& msg) {
    std::lock_guard<std::mutex> guard(cerrMutex);
    std::cerr << msg << std::endl;
}

template<typename T>
class SafeQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cond;

public:
    SafeQueue() {}

    void enqueue(T t) {
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(t);
        cond.notify_one();
    }

    T dequeue() {
        std::unique_lock<std::mutex> lock(mutex);
        while (queue.empty()) {
            cond.wait(lock);
        }
        T val = queue.front();
        queue.pop();
        return val;
    }

    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex);
        return queue.empty();
    }
};

class ThreadPool {
private:
    std::vector<std::thread> workers;
    SafeQueue<std::function<void()>> taskQueue;
    std::atomic<bool> stop;
    std::atomic<int> activeThreads;

    void worker() {
        while (!stop) {
            std::function<void()> task = taskQueue.dequeue();
            if (task) {
                activeThreads++;
                task();
                activeThreads--;
            }
        }
    }

public:
    ThreadPool(size_t threads) : stop(false), activeThreads(0) {
        for (size_t i = 0; i < threads; ++i)
            workers.emplace_back([this] { this->worker(); });
    }

    void enqueueTask(std::function<void()> task) {
        taskQueue.enqueue(task);
    }

    void shutdown() {
    safePrintStdOut("Shutting down thread pool...");
    stop.store(true); // Signal all threads to stop
    
    // Enqueue a nullptr task for each worker thread to ensure they all wake up and exit
    for(size_t i = 0; i < workers.size(); ++i) {
        taskQueue.enqueue([]{}); // Enqueue an empty task instead of nullptr to ensure compatibility
    }

    // Join all worker threads
    for (std::thread &worker : workers) {
        if (worker.joinable()) {
            worker.join();
            safePrintStdOut("Worker thread joined.");
        }
    }
    safePrintStdOut("Thread pool shutdown complete.");
}


    int getActiveThreads() const {
        return activeThreads.load();
    }
};


#define MAX_CLIENTS 50 
#define BUFFER_SIZE 8096


struct Client_Request {
    int client_fd;
    std::string client_ip;
    std::string request_line;
    std::string method;
    std::string path;
    std::string http_version;
    std::string host;
    std::string user_agent;
    int port = 443;
};

struct Client_Log{
    std::string client_ip;
    std::string request_line;
    int size;
    int status = 0;
};

std::atomic<bool> reloadFlag(false);
std::atomic<bool> quitFlag(false);

std::atomic<int> forbiddenGlobalVersion(0);

std::unordered_set<std::string> forbiddenSites;

std::mutex forbiddenSitesMutex;
std::mutex loadMutex;
std::mutex logMutex; 

std::string logfilepath;

std::string extractDirectory(const std::string& filePath) {
    size_t found = filePath.find_last_of("/\\");
    if (found != std::string::npos) {
        return filePath.substr(0, found);
    }
    return ""; 
}

bool createDirectory(const std::string& path) {
    int result = mkdir(path.c_str(), 0777); 
    if (result == 0 || (errno == EEXIST)) {
        return true; 
    }
    std::cerr << "Failed to create directory " << path << ": " << strerror(errno) << std::endl;
    return false;
}

void checkAndCreateLogFile(const std::string& logFilePath) {
    std::string dirPath = extractDirectory(logFilePath);
    if (!dirPath.empty() && !createDirectory(dirPath)) {
        std::cerr << "Error: Failed to create directory for log file." << std::endl;
        exit(EXIT_FAILURE);
    }
    std::ofstream logFile(logFilePath, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Error: Could not open or create the log file at " << logFilePath << std::endl;
        exit(EXIT_FAILURE);
    }
    logFile.close();
}


std::string getCurrentTimeISO8601() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%FT%T") << "Z";
    return ss.str();
}


void logAccess(const Client_Log& logEntry) {
    std::lock_guard<std::mutex> guard(logMutex); // Ensure thread-safe access to the log file   
    std::ofstream logFile(logfilepath, std::ios::app); // Open in append mode

    if (!logFile.is_open()) {
        safePrintStdErr("Failed to open access.log for writing at " + logfilepath);
        return;
    }

    // Get current time in ISO 8601 format
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&in_time_t), "%FT%T") << "Z";

    // Write the log entry according to the specified format
    logFile << ss.str() << " " << logEntry.client_ip << " \"" << logEntry.request_line << "\" " << logEntry.status << " " << logEntry.size << std::endl;
}

void resolveForbiddenSites(const std::string& hostname) {

    std::lock_guard<std::mutex> guard(forbiddenSitesMutex);
    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    // Insert the hostname itself into the set
    forbiddenSites.insert(hostname);

    if ((status = getaddrinfo(hostname.c_str(), NULL, &hints, &res)) != 0) {
        std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
        return;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void* addr;
        if (p->ai_family == AF_INET) { // IPv4
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr = &(ipv4->sin_addr);
        } else { // IPv6
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            addr = &(ipv6->sin6_addr);
        }

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        forbiddenSites.insert(std::string(ipstr));
    }

    freeaddrinfo(res); // Free the linked list
}

bool isSiteForbidden(const std::string& hostnameOrIP) {

    std::lock_guard<std::mutex> guard(forbiddenSitesMutex);

    // Check if the hostname or IP is directly in the forbidden set
    if (forbiddenSites.find(hostnameOrIP) != forbiddenSites.end()) {
        return true;
    }

    struct addrinfo hints, *res, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // Use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(hostnameOrIP.c_str(), NULL, &hints, &res)) == 0) {
        for (p = res; p != NULL; p = p->ai_next) {
            void* addr;
            if (p->ai_family == AF_INET) { // IPv4
                struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
                addr = &(ipv4->sin_addr);
            } else { // IPv6
                struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
                addr = &(ipv6->sin6_addr);
            }

            inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
            if (forbiddenSites.find(std::string(ipstr)) != forbiddenSites.end()) {
                freeaddrinfo(res);
                return true; // Found a forbidden IP
            }
        }
        freeaddrinfo(res);
    } else {
        std::cerr << "getaddrinfo error while checking forbidden site: " << gai_strerror(status) << std::endl;
    }

    return false;
}

void loadForbiddenSites(const std::string &filepath) {
    std::lock_guard<std::mutex> guard(loadMutex); 
    std::ifstream file(filepath);

    if (!file.is_open()) {
        safePrintStdErr("Error opening file: " + filepath + ". Continuing without loading new forbidden sites.");
        return; 
    }
    std::string line;
    forbiddenSites.clear();
    while (getline(file, line)) {
        if (line.find("www.") != std::string::npos) { 
            resolveForbiddenSites(line);
        } else {
            forbiddenSites.insert(line); 
        }
    }
    forbiddenGlobalVersion++;
    safePrintStdOut("Forbidden sites list loaded successfully.");
}

void signalHandler(int signum) {
    if (signum == SIGINT) {
        // Set reload flag
        reloadFlag.store(true);
    } else if (signum == SIGQUIT) {
        // Set quit flag
        quitFlag.store(true);
    }
}

void setupSignalHandling() {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &signalHandler;
    // Register the same handler for both signals
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);  
}


int sockInit(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        std::cerr << "Error getting flags for socket" << std::endl;
        return -1;
    }

    flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1) {
        std::cerr << "Error setting socket to non-blocking" << std::endl;
        return -1;
    }

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }

    if (listen(sock, 1) < 0) {
        perror("Listen failed");
        close(sock);
        return -1;
    }

    return sock;
}

void send_response(int client_socket, int status_code, const std::string& client_ip, const std::string& request_line, int size) {
    char response[2048]; // Increased size to accommodate larger headers
    const char* status_message;
    switch (status_code) {
        case 200:
            status_message = "OK";
            break;
        case 400:
            status_message = "Bad Request";
            break;
        case 403:
            status_message = "Forbidden";
            break;
        case 501:
            status_message = "Not Implemented";
            break;
        case 502:
            status_message = "Bad Gateway";
            break;
        case 504:
            status_message = "Gateway Timeout";
            break;
        case 500:
            status_message = "Internal Server Error";
            break;
        default:
            status_message = "Unknown";
            break;
    }

    // Include the Content-Length header with the appropriate size
    // Note: Ensure the size is accurately reflecting the length of the body being sent.
    // For responses without a body, this can be 0.
    int message_length = strlen(status_message) + 1;

    snprintf(response, sizeof(response), 
        "HTTP/1.1 %d %s\r\n"
        "Server: myproxy156\r\n"
        "Content-Length: %d\r\n" // Now set to the length of the message
        "Connection: keep-alive\r\n"
        "Content-Type: text/plain\r\n\r\n" // Indicate that the content is plain text
        "%s\n", // Placeholder for the message body itself
        status_code, status_message, message_length, status_message); // Use the length of the message for the Content-Length header

    // Send the HTTP response message to the client socket
    send(client_socket, response, strlen(response), 0);

    // Log the response for debugging
    safePrintStdOut("Sent response to " + client_ip + ": " + request_line + 
            " -- Status: " + std::to_string(status_code) + ", Size: " + std::to_string(strlen(response)));

    Client_Log Log;
    Log.client_ip = client_ip;
    Log.request_line = request_line;
    Log.size = strlen(response);
    Log.status = status_code;
    
    logAccess(Log);
}

static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}


Client_Request ParseRequest(const std::string& httpRequest, int client_fd, const std::string& client_ip) {
    Client_Request request;
    request.client_fd = client_fd;
    request.client_ip = client_ip;

    std::istringstream requestStream(httpRequest);
    std::string line;
    std::getline(requestStream, line);

    line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());
    request.request_line = line;

    std::regex requestLinePattern(R"(^(\S+)\s+(\S+)\s+(HTTP/\d\.\d))");
    std::smatch match;

    if (std::regex_search(line, match, requestLinePattern) && match.size() == 4) {
        request.method = match[1];
        std::string url = match[2];
        request.http_version = match[3];

        std::regex urlPattern(R"(^http://[^/]+(/[^? ]*))");
        if (std::regex_search(url, match, urlPattern) && match.size() > 1) {
            request.path = match[1];
        } else {
            request.path = "/"; // Default path if not specified
        }
    }

    while (std::getline(requestStream, line, '\n')) {
        
        line.erase(std::remove(line.begin(), line.end(), '\r'), line.end());

        std::regex hostPattern(R"(^Host:\s*([^:]+)(?::(\d+))?)", std::regex_constants::icase);
        std::regex userAgentPattern(R"(^User-Agent:\s*(.+)$)", std::regex_constants::icase);

        // Match and extract the Host header
        if (std::regex_search(line, match, hostPattern)) {
            request.host = match[1].str();
            trim(request.host);
            if (match.size() == 3 && match[2].matched) {
                request.port = std::stoi(match[2].str());
            }
        }
        else if (std::regex_search(line, match, userAgentPattern) && match.size() > 1) {
            request.user_agent = match[1].str();
        }
    }

    return request;
}


void setupSSLConnection(const Client_Request& parsedRequest, int localForbiddenVar) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd;
    struct addrinfo hints, *res;

    int localForbiddenVersion = localForbiddenVar;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // Create a new SSL context
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, parsedRequest.request_line, 0);
        return;
    }

    // Load root CA certificates
    if (!SSL_CTX_load_verify_locations(ctx, "/etc/ssl/certs/ca-certificates.crt", nullptr)) {
        send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, parsedRequest.request_line, 0);
        SSL_CTX_free(ctx);
        return;
    }

    // Set verification mode of the context
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Resolve hostname to IP Address
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    

    if (getaddrinfo(parsedRequest.host.c_str(), std::to_string(parsedRequest.port).c_str(), &hints, &res) != 0) {
        send_response(parsedRequest.client_fd, 502, parsedRequest.client_ip, parsedRequest.request_line, 0);
        SSL_CTX_free(ctx);
        return;
    }

    // Create socket and connect
    server_fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (server_fd < 0) {
        send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, parsedRequest.request_line, 0);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return;
    }

    if (connect(server_fd, res->ai_addr, res->ai_addrlen) != 0) {
        send_response(parsedRequest.client_fd, 504, parsedRequest.client_ip, parsedRequest.request_line, 0);
        close(server_fd);
        freeaddrinfo(res);
        SSL_CTX_free(ctx);
        return;
    }

    freeaddrinfo(res);

    // Create a new SSL connection state object
    ssl = SSL_new(ctx);
    if (!ssl) {
        send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, parsedRequest.request_line, 0);
        close(server_fd);
        SSL_CTX_free(ctx);
        return;
    }

    // Connect the SSL object with a file descriptor
    SSL_set_fd(ssl, server_fd);
    if (SSL_connect(ssl) != 1) {
        send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, parsedRequest.request_line, 0);
        SSL_free(ssl);
        close(server_fd);
        SSL_CTX_free(ctx);
        return;
    }

    // Verify the SSL certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) X509_free(cert);
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        send_response(parsedRequest.client_fd, 504, parsedRequest.client_ip, parsedRequest.request_line, 0);
        SSL_free(ssl);
        close(server_fd);
        SSL_CTX_free(ctx);
        return;
    }

    // Construct the request line and headers
    std::string Request;
    Request += parsedRequest.method + " " + parsedRequest.path + " " + parsedRequest.http_version + "\r\n";
    Request += "Host: " + parsedRequest.host + "\r\n";
    Request += "User-Agent: " + parsedRequest.user_agent +"\r\n";
    Request += "Accept: */*\r\n";
    Request += "Connection: close\r\n";
    Request += "\r\n"; 

    // Writing the constructed request to the server
    if (SSL_write(ssl, Request.c_str(), Request.length()) <= 0) {
        send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, "SSL_write failed", 0);
        SSL_free(ssl);
        close(server_fd);
        SSL_CTX_free(ctx);
        return;
    }

    char buffer[BUFFER_SIZE] = {0};
    bool process_head_request = parsedRequest.method == "HEAD";
    int total_bytes_written = 0;
    int content_length = 0;

    bool header_end = false;
    int status_code = 0;
    int head_size = 0;
    bool gotContentLength = false;

    struct pollfd pfds[2];
    pfds[0].fd = parsedRequest.client_fd;
    pfds[1].fd = SSL_get_fd(ssl); // Get the file descriptor for the SSL connection
    pfds[0].events = pfds[1].events = POLLIN;


    while (true) {
        if (forbiddenGlobalVersion.load() != localForbiddenVersion) {
            if (isSiteForbidden(parsedRequest.host)) {
                send_response(parsedRequest.client_fd, 403, parsedRequest.client_ip, parsedRequest.request_line, 0);
                break;
            } else {
                localForbiddenVersion = forbiddenGlobalVersion.load();
            }
        }

        int poll_count = poll(pfds, 2, 5000); // 5-second timeout
        if (poll_count == 0) {
            send_response(parsedRequest.client_fd, 504, parsedRequest.client_ip, "Gateway Timeout", 0);
            break;
        } else if (poll_count < 0) {
            send_response(parsedRequest.client_fd, 500, parsedRequest.client_ip, "Error polling sockets", 0);
            break;
        }

        // Handle SSL (server) socket input
        if (pfds[1].revents & POLLIN) {
            int bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0'; 
                const char* http_version = "HTTP/";
                char* http_pos = strstr(buffer, http_version);
                if (http_pos) {
                    int read_status_code = 0;
                    if (sscanf(http_pos, "HTTP/%*d.%*d %d", &read_status_code) == 1) {
                        status_code = read_status_code; 
                    }
                }

                // Check for chunked transfer encoding
                if (strstr(buffer, "Transfer-Encoding: chunked")) {
                    send_response(parsedRequest.client_fd, 501, parsedRequest.client_ip, parsedRequest.request_line, 0);
                    break; // Chunked encoding not supported, exit loop
                }

                // Parse Content-Length, regardless of Transfer-Encoding
                char* cl_pos = strstr(buffer, "Content-Length: ");
                if (cl_pos) {
                    sscanf(cl_pos, "Content-Length: %d", &content_length);
                    gotContentLength = true;
                }

                // Check for end of headers and calculate header size

                char* header_end_pos = strstr(buffer, "\r\n\r\n");
                if (header_end_pos != NULL && !header_end) {
                    header_end = true;
                    head_size += (header_end_pos - buffer) + 4; // Include the length of "\r\n\r\n"
                } else if (!header_end) {
                    // If the end of the headers hasn't been found, add the size of the current read
                    head_size += bytes_read;
                }

                // Process HEAD request
                if (process_head_request && header_end) {
                    send(parsedRequest.client_fd, buffer, bytes_read, 0);
                    break;
                } 
                else {
                     // Forward response to client GET request
                    send(parsedRequest.client_fd, buffer, bytes_read, 0);
                    total_bytes_written += bytes_read;
                    // Break out of the loop if we've written all content for non-chunked responses
                    if (gotContentLength && total_bytes_written >= (content_length + head_size) ) {
                        break;
                    }
                }
            }
            else if (bytes_read <= 0) {
                break;
            }
        }
    }
   
   
    // Logging
    Client_Log Log;
    Log.client_ip = parsedRequest.client_ip;
    Log.request_line = parsedRequest.request_line;
    Log.size = process_head_request ? head_size : total_bytes_written;
    
    Log.status = status_code;
    safePrintStdOut("SSL request completed -- Status: " + std::to_string(status_code) + ", Size: " + std::to_string(Log.size));
    logAccess(Log);

    SSL_free(ssl);
    close(server_fd);
    SSL_CTX_free(ctx);
}

void handleConnection(int client_fd, const std::string& client_ip, int forbiddenLocalVersion) {
    while (true) {
        char buffer[BUFFER_SIZE] = {0};
        ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1); // Attempt to read data

        if (bytes_read > 0) {
            std::string httpRequest(buffer);
            Client_Request parsedRequest = ParseRequest(httpRequest, client_fd, client_ip);

            std::stringstream messageStream;
            messageStream << "From client: " << parsedRequest.client_ip
                          << " handled by thread " << std::this_thread::get_id()
                          << "\nRequest Line: " << parsedRequest.request_line;
            safePrintStdOut(messageStream.str());

            if (isSiteForbidden(parsedRequest.host)) {
                safePrintStdErr("Forbidden site accessed: " + parsedRequest.host);
                send_response(parsedRequest.client_fd, 403, client_ip, parsedRequest.request_line, 0);
                
            } else if ((parsedRequest.method == "GET" || parsedRequest.method == "HEAD") && parsedRequest.http_version == "HTTP/1.1") {
                safePrintStdOut("Setting up SSL connection for: " + parsedRequest.host);
                setupSSLConnection(parsedRequest, forbiddenLocalVersion);
            } else if (parsedRequest.method != "GET" && parsedRequest.method != "HEAD") {
                send_response(client_fd, 501, client_ip, parsedRequest.request_line, 0);
                safePrintStdErr("Unsupported HTTP method: " + parsedRequest.method);
            
               
            } else if (parsedRequest.http_version != "HTTP/1.1") {
                safePrintStdErr("Unsupported HTTP version: " + parsedRequest.http_version);
                send_response(client_fd, 505, client_ip, parsedRequest.request_line, 0);
            } else {
                safePrintStdErr("Server error");
                send_response(client_fd, 500, client_ip, parsedRequest.request_line, 0);
            }
        } else if (bytes_read == 0) {
            safePrintStdOut("Client closed connection.");
            break; 
        } else {
            safePrintStdErr("Error reading from client socket");
            break;
        }
    }
    close(client_fd);
    return;
}



int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <listen_port> <forbidden_sites_file_path> <access_log_file_path>" << std::endl;
        return 1;
    }


    int port;
    try {
    port = std::stoi(argv[1]);
    } catch (const std::invalid_argument &ia) {
        std::cerr << "Error: Port must be a valid number." << std::endl;
        return 1;
    } catch (const std::out_of_range &oor) {
        std::cerr << "Error: Port is out of range." << std::endl;
        return 1;
    }

    if (port < 1024 || port > 65535) {
        std::cerr << "Error: Port number must be between 1024 and 65535." << std::endl;
        return 1;
    }

    std::string forbiddenfilePath = argv[2];
    logfilepath = argv[3];

    checkAndCreateLogFile(logfilepath);
    loadForbiddenSites(forbiddenfilePath);  

    setupSignalHandling();
    ThreadPool pool(50);

    int serverFd = sockInit(port);
    if (serverFd < 0) return -1; // Exit if socket initialization failed

    // Prepare for polling the server socket
    struct pollfd fds[1];
    fds[0].fd = serverFd;
    fds[0].events = POLLIN; // Monitor for incoming connections

    while (!quitFlag.load()) {
        int ret = poll(fds, 1, 1000); // 1 second timeout

        if (ret < 0) {
            if (errno == EINTR) {
                // Check if it's a reload request
                if (errno == EINTR && reloadFlag.load()) {
                    std::cout << " Reloading configuration..." << std::endl;
                    loadForbiddenSites(forbiddenfilePath); // Assuming argv[2] is the path to the forbidden sites list
                    forbiddenGlobalVersion++; // Increment version
                    reloadFlag.store(false); // Reset reload flag
                }
                
                if (quitFlag.load()) {
                    std::cout << "Quitting..." << std::endl;
                    break;
                }
            } else {
                safePrintStdErr("Poll error: " + std::string(strerror(errno)));
                break;
            }
        }

        if (fds[0].revents & POLLIN) {
            sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int client_fd = accept(serverFd, (struct sockaddr*)&client_addr, &addr_len);
            if (client_fd < 0) {
                safePrintStdErr("Error accepting connection: " + std::string(strerror(errno)));
                continue;
            }

            char client_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip_str, INET_ADDRSTRLEN);
            std::string client_ip(client_ip_str);

            int forbiddenVersionCopy = forbiddenGlobalVersion;

            // Submit a task to the thread pool, capturing client_fd, client_ip, and forbiddenGlobalVersion by value
            pool.enqueueTask([client_fd, client_ip, forbiddenVersionCopy]() {
                handleConnection(client_fd, client_ip, forbiddenVersionCopy);
            });
        }
    }

    // Clean up before exiting
    pool.shutdown();
    close(serverFd);

    std::cout << "Server shutdown gracefully." << std::endl;
    return 0;
}