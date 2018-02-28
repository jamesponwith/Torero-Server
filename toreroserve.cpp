/**
 * ToreroServe: A Lean Web Server
 * COMP 375 (Spring 2018) Project 02
 *
 * This program should take two arguments:
 * 	1. The port number on which to bind and listen for connections
 * 	2. The directory out of which to serve files.
 *
 * Author 1: Patrick Hall
 * 			 patrickhall@sandeigo.edu
 * Author 2: James Ponwith
 * 			 jponwith@sandeiego.edu
 *
 *
 * 	Testing list:
 * 	TODO: Select thread
 * 	TODO: Make thread receive http request
 * 	Done: check if valid get request
 * 		Yes case -- validates
 * 		No case -- send 404 request
 * 	TODO: Does file exist
 * 		TODO: yes case
 * 		TODO: no case
 * 	TODO: check if file or dir
 * 		TODO: file case
 * 		TODO: does it contain index.html?
 * 			TODO: if no, gnerate html links
 * 	TODO: send http200 ok response
 *
 */

// standard C libraries
#include <ctime>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <cstring>

// operating system specific libraries
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>

// C++ standard libraries
#include <vector>
#include <thread>
#include <string>
#include <iostream>
#include <system_error>

#include <mutex>
#include <regex>
#include <thread>
#include <fstream>

//#include <conditional_variables>

//Boost filesystem libraries
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/iterator_range.hpp>
namespace fs = boost::filesystem;

#define DEBUG 1

using std::cout;
using std::endl;
using std::string;
using std::thread;
using std::vector;

// This will limit how many clients can be waiting for a connection.
static const int BACKLOG = 10;
static const int BUFF_SIZE = 2048;

// forward declarations
void handleClient(const int client_sock);
int createSocketAndListen(const int port_num);
void acceptConnections(const int server_sock);
int receiveData(int socked_fd, char *dest, size_t buff_size);
void sendData(int socked_fd, const char *data, size_t data_length);

string date_to_string();
bool is_valid_request(string buff);
void send_bad_request(const int client_sock, string html_type);
string generate_index_html(fs::path dir);
fs::path get_path(string location_str); 
void generate_appropriate_response(const int client_sock, fs::path p, string http_type);
void send_file_not_found(const int client_sock, string http_response);
void send_http200_response(const int client_sock, int size, fs::path ext, vector<char> s, string content, string http_type);

int main(int argc, char** argv) {

    /* Make sure the user called our program correctly. */
    if (argc != 3) {
        cout << "INCORRECT USAGE!\n";
        cout << "usage: [port to listen on]\n"
            << "       [directory out of which to serve files]\n";
        exit(1);
    }

    /* Read the port number from the first command line argument. */
    int port = std::stoi(argv[1]);

    /* Create a socket and start listening for new connections on the
     * specified port. */
    int server_sock = createSocketAndListen(port);

    /* Now let's start accepting connections. */
    acceptConnections(server_sock);

    close(server_sock);

    return 0;
}

/**
 * Receives a request from a connected HTTP client and sends back the
 * appropriate response.
 *
 * @note After this function returns, client_sock will have been closed (i.e.
 * may not be used again).
 *
 * @param client_sock The client's socket file descriptor.
 */
void handleClient(const int client_sock) {
    /* receive client data */
    char buff[1024];
    int client_request = receiveData(client_sock, buff, sizeof(buff));
    if (client_request <= 0) {
        cout << "no data received" << endl;
    }

    cout << "THIS IS THE BUFFER\n" << buff << "\n\n";

    char *cmd = std::strtok(buff, " ");
    char *location = std::strtok(NULL, " ");
    char *http_type = std::strtok(NULL, " ");

    string cmd_str(cmd);
    string location_str(location);
    string http_type_str(http_type);


    /* check if valid request */
    if (is_valid_request(buff)) {
        send_bad_request(client_sock, http_type);
        // close(client_sock);
        return; // invalid request - we peacing out!
    }
    else {
        // cout << "valid request" << endl;
    }

    /* get path from request */
    fs::path path_to_file = get_path(location_str);

    /* check if file exists */
    if(!fs::exists(path_to_file)) {
        send_file_not_found(client_sock, http_type);
        // close(client_sock);
        return;
    }

    generate_appropriate_response(client_sock, path_to_file, http_type);

    // TODO: Send response to client.

    // TODO: Close connection with client.
    // close(client_sock);
}

/**
 * Generates appropriate response of the GET request
 */
void generate_appropriate_response(const int client_sock, fs::path p, string http_type) {
    if (fs::is_directory(p)) {
        if (fs::path_traits::empty(p)) {
			cout << "Directory is empty" << endl;
        }
        /* check if contains index.html */
		fs::path tmp_path = p;
		tmp_path /= "index.html";
		string html;
        if (fs::exists(tmp_path)) {
			html = tmp_path.string();
            generate_appropriate_response(client_sock, tmp_path, http_type);
			// send_http200_response(client_sock, -1, ".html", vector<char>(), html);
        }
        else {
            html = generate_index_html(p);
			send_http200_response(client_sock, -1, ".html", vector<char>(), html, http_type);
        }
    }
    else if (fs::is_regular_file(p)) {
        fs::path d(fs::extension(p));

        std::ifstream in_file(p.string(), std::ios::binary|std::ios::in);
        //in_file.open(p.string(), std::ios::binary|std::ios::in);
        if (!in_file) {
            cout << "Unable to open file\r\n";
        }

        in_file.seekg(0, std::ios::end);
        std::streampos position = in_file.tellg();
        // cout << "length: " << position << "\r\n";
        in_file.seekg(0, std::ios::beg);
        vector<char> buffer((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());
        int pass_pos = (int) position;
        in_file.close();
        send_http200_response(client_sock, pass_pos, fs::extension(p), buffer, string(), http_type);
    }
    else {
        cout << p << " exists, but is neither a regular file nor a directory\n";
    }
}

/**
 * Generates html code for the index.html fil
 * @param boost::filesystem path for the specified directory
 * @return html code in form of C++ string
 */
string generate_index_html(fs::path dir) {
    cout << "FULL PATH-------------------------\n" << dir;
    vector<fs::directory_entry> list;
    std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(list));
    string ret_html("<html><head><title>Parent Directory</title></head><body>Files in directory ");
    ret_html.append(dir.string());
    ret_html.append("<br>");

    for (fs::directory_entry d: list) {
        string next_link("<a href=\"");
        next_link.append(d.path().string());
        next_link.append("\">");
        next_link.append(d.path().string());
        next_link.append("</a><br>");
        ret_html.append(next_link);
    }

    ret_html.append("</body></html>");
    return ret_html;
}


/**
 * Sends a http 200 OK response
 */
void send_http200_response(const int client_sock, int size, fs::path ext, vector<char> s, string content, string http_type) {
    cout << "HTTP TYPE: >>>>>>> " << http_type << endl << endl;

	//string ret("HTTP/1.1 200 OK\r\nDate: ");
	
	string ret;
	ret += http_type;
	ret.append(" 200 OK\r\nDate: ");
	
	//cout << ext << "\r\n";

    /* add date */
    ret.append(date_to_string());
    ret.append("\r\n");
    ret.append("Content-Length: ");
    if (size < 0) {
        ret.append(boost::lexical_cast<string>(content.length()));
    }
    else {
        ret.append(boost::lexical_cast<string>(s.size()));
    }
    ret.append("\r\n");

    /* add content type */
    ret.append("Content-Type: ");
    string extension(ext.string());
    ret.append(extension.substr(1));
    ret.append("\r\n\r\n");

	int msg_size;
    if (size < 0) {
        msg_size = ret.length() + 2 + content.length();
    }
	else {
		msg_size = ret.length() + 2 + size;
	}

    /* two extra buffers for c_stringy operations */
    char message[ret.length() + 1];
    strcpy(message, ret.c_str());

    char final_msg[msg_size];
    memcpy(final_msg, message, ret.length());

    if (size < 0) {
        char content_msg[content.length() + 1];
        strcpy(content_msg, content.c_str());
        memcpy((final_msg + ret.length()), content_msg, content.length());

        cout << "200 MSG size < 0 " << final_msg << "\r\n";
        sendData(client_sock, final_msg, msg_size);
        return;
    }

    char entity_body[s.size() + 1];
    std::copy(s.begin(), s.end(), entity_body);
    memcpy((final_msg + ret.length()), entity_body, s.size());
    
    cout << "200 MSG size > 0 " << final_msg << "\r\n";
    sendData(client_sock, final_msg, msg_size);
    // cout << final_msg << "\r\n";
}

/**
 * Send 404 error html page
 */
void send_file_not_found(const int client_sock, string http_type) {
    string ret(http_type);
	cout << "HTTP TYPE IN FILE NOT FOUND :::::: " << http_type << endl << endl;
    ret.append("404 File not found\r\nConnection: close\r\nDate: ");

    ret.append(date_to_string());
    ret.append("\r\n\r\n");
    ret.append("<html><head><title>Page not found</title></head><body><404 not found></body></html>");

    //copy to char array and sned it
    char msg[ret.length() + 1];
    strcpy(msg, ret.c_str());
    cout << "FILE NOT FOUND ERROR " << msg << "\r\n";
    sendData(client_sock, msg, sizeof(msg));
}

/**
 * Returns the boost::filesystem path to the specified path
 */
fs::path get_path(string location_str) {

    char search_buff[512];
    string folder("WWW");
    folder += location_str;
    folder.copy(search_buff, BUFF_SIZE);

    //cout << "Before sending, send buff is: " << folder << endl;

    fs::path p(folder);
    // cout << p;
    return p;
}

/**
 * Checks to see if the incoming buffer is a valid get request
 *
 * @pram buff The incoming buffer
 * @return true if valid, false if not
 */
bool is_valid_request(string buff) {
    std::regex get("GET /.+ HTTP/.*");
    // bool valid = regex_search(buff, get);
    return regex_search(buff, get);
    // return valid;
}


/**
 * Send http 400 bad request response
 */
void send_bad_request(const int client_sock, string http_type) {
	string ret(http_type);
	ret.append("400 Bad Request\r\nConnection: close\r\nDate: ");
    //string ret("HTTP:/1.1 400 Bad Request\r\nConnection: close\r\nDate: ");
    ret.append(date_to_string());
    ret.append("\r\n");

    char msg[ret.length() + 1];
    strcpy(msg, ret.c_str());
    cout << "BAD REQUEST: " << msg << endl;
    sendData(client_sock, msg, sizeof(msg));
}

/*
void send_bad_request(const int client_sock, string html_type) {
    string ret;
    ret += http_type;
    ret.append(" 404 File not found\r\nConnection: close\r\nDate: ");

    ret.append(date_to_string());
    ret.append("\r\n\r\n");
    ret.append("<html><head><title>Page not found</title></head><body><404 not found></body></html>");

    //copy to char array and sned it
    char msg[ret.length() + 1];
    strcpy(msg, ret.c_str());
    cout << "FILE NOT FOUND ERROR " << msg << "\r\n";
    sendData(client_sock, msg, sizeof(msg));
}
*/

/**
 * Converts time_t of current time to a string
 * @return date_str the date string
 */
string date_to_string() {
    time_t curr_time = time(0);
    char get_data[80];
    strftime(get_data, 80, "%a, %d %b %Y %X", localtime(&curr_time));
    string date_str(get_data);
    return date_str;
}

/**
 * Creates a new socket and starts listening on that socket for new
 * connections.
 *
 * @param port_num The port number on which to listen for connections.
 * @returns The socket file descriptor
 */
int createSocketAndListen(const int port_num) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Creating socket failed");
        exit(1);
    }

    /*
     * A server socket is bound to a port, which it will listen on for incoming
     * connections.  By default, when a bound socket is closed, the OS waits a
     * couple of minutes before allowing the port to be re-used.  This is
     * inconvenient when you're developing an application, since it means that
     * you have to wait a minute or two after you run to try things again, so
     * we can disable the wait time by setting a socket option called
     * SO_REUSEADDR, which tells the OS that we want to be able to immediately
     * re-bind to that same port. See the socket(7) man page ("man 7 socket")
     * and setsockopt(2) pages for more details about socket options.
     */
    int reuse_true = 1;

    int retval; // for checking return values

    retval = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_true,
            sizeof(reuse_true));

    if (retval < 0) {
        perror("Setting socket option failed");
        exit(1);
    }

    /*
     * Create an address structure.  This is very similar to what we saw on the
     * client side, only this time, we're not telling the OS where to connect,
     * we're telling it to bind to a particular address and port to receive
     * incoming connections.  Like the client side, we must use htons() to put
     * the port number in network byte order.  When specifying the IP address,
     * we use a special constant, INADDR_ANY, which tells the OS to bind to all
     * of the system's addresses.  If your machine has multiple network
     * interfaces, and you only wanted to accept connections from one of them,
     * you could supply the address of the interface you wanted to use here.
     */
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_num);
    addr.sin_addr.s_addr = INADDR_ANY;

    /*
     * As its name implies, this system call asks the OS to bind the socket to
     * address and port specified above.
     */
    retval = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (retval < 0) {
        perror("Error binding to port");
        exit(1);
    }

    /*
     * Now that we've bound to an address and port, we tell the OS that we're
     * ready to start listening for client connections. This effectively
     * activates the server socket. BACKLOG (a global constant defined above)
     * tells the OS how much space to reserve for incoming connections that have
     * not yet been accepted.
     */
    retval = listen(sock, BACKLOG);
    if (retval < 0) {
        perror("Error listening for connections");
        exit(1);
    }

    return sock;
}

/**
 * Sit around forever accepting new connections from client.
 *
 * @param server_sock The socket used by the server.
 */
void acceptConnections(const int server_sock) {
    while (true) {
        // Declare a socket for the client connection.
        int sock;

        /*
         * Another address structure.  This time, the system will automatically
         * fill it in, when we accept a connection, to tell us where the
         * connection came from.
         */
        struct sockaddr_in remote_addr;
        unsigned int socklen = sizeof(remote_addr);

        /*
         * Accept the first waiting connection from the server socket and
         * populate the address information.  The result (sock) is a socket
         * descriptor for the conversation with the newly connected client.  If
         * there are no pending connections in the back log, this function will
         * block indefinitely while waiting for a client connection to be made.
         */
        sock = accept(server_sock, (struct sockaddr*) &remote_addr, &socklen);
        if (sock < 0) {
            perror("Error accepting connection");
            exit(1);
        }

        /*
         * At this point, you have a connected socket (named sock) that you can
         * use to send() and recv(). The handleClient function should handle all
         * of the sending and receiving to/from the client.
         *
         * TODO: You shouldn't call handleClient directly here. Instead it
         * should be called from a separate thread. You'll just need to put sock
         * in a shared buffer and notify the threads (via a condition variable)
         * that there is a new item on this buffer.
         */
        handleClient(sock);

        /*
         * Tell the OS to clean up the resources associated with that client
         * connection, now that we're done with it.
         */
        close(sock);
    }
}

/**
 * Sends message over given socket, raising an exception if there was a problem
 * sending.
 *
 * @param socket_fd The socket to send data over.
 * @param data The data to send.
 * @param data_length Number of bytes of data to send.
 */
void sendData(int socked_fd, const char *data, size_t data_length) {
    // TODO: Wrap the following code in a loop so that it keeps sending until
    // the data has been completely sent.
    int num_bytes_left = data_length;
    while (num_bytes_left > 0) {
        int num_bytes_sent = send(socked_fd, data, data_length, 0);
        if (num_bytes_sent == -1) {
            std::error_code ec(errno, std::generic_category());
            throw std::system_error(ec, "send failed");
        }
        num_bytes_left -= num_bytes_sent;
    }
}

/**
 * Receives message over given socket, raising an exception if there was an
 * error in receiving.
 *
 * @param socket_fd The socket to send data over.
 * @param dest The buffer where we will store the received data.
 * @param buff_size Number of bytes in the buffer.
 * @return The number of bytes received and written to the destination buffer.
 */
int receiveData(int socked_fd, char *dest, size_t buff_size) {
    int num_bytes_received = recv(socked_fd, dest, buff_size, 0);
    if (num_bytes_received == -1) {
        std::error_code ec(errno, std::generic_category());
        throw std::system_error(ec, "recv failed");
    }

    return num_bytes_received;
}
