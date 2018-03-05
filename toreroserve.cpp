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
#include <regex>
#include <mutex>
#include <vector>
#include <string>
#include <thread>
#include <fstream>
#include <iostream>
#include <pthread.h>
#include <system_error>

//Boost filesystem libraries
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/range/iterator_range.hpp>
namespace fs = boost::filesystem;

#include "BoundedBuffer.hpp"

using std::cout;
using std::endl;
using std::string;
using std::thread;
using std::vector;

// This will limit how many clients can be waiting for a connection.
static std::mutex mutex;
static const int BACKLOG = 10;
static const int BUFF_SIZE = 2048;

// forward declarations
string date_to_string();
bool is_valid_request(string buff);
void handleClient(BoundedBuffer &buff);
fs::path strip_root(const fs::path &p); 
fs::path get_path(string location_str); 
string generate_html_links(fs::path dir);
int createSocketAndListen(const int port_num);
void acceptConnections(const int server_sock);
int receiveData(int socked_fd, char *dest, size_t buff_size);
void send_bad_request(const int client_sock, string html_type);
void sendData(int socked_fd, const char *data, size_t data_length);
void send_file_not_found(const int client_sock, string http_response);
void generate_response(const int client_sock, fs::path p, string http_type);
void send_regular_file(const int client_sock, fs::path p, string http_type); 
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
 * Sit around forever accepting new connections from client.
 *
 * @param server_sock The socket used by the server.
 */
void acceptConnections(const int server_sock) {
	BoundedBuffer buffer(10);

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
		 * Spawn a thread to run handleClient function which will handle all
		 * of the sending and receiving to/from the client.
		 */
		thread clientThread(handleClient, std::ref(buffer));
		clientThread.detach();

		/*
		 * Tell the OS to clean up the resources associated with that client
		 * connection, now that we're done with it.
		 */
		buffer.putItem(sock);
	}
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
void handleClient(BoundedBuffer &buffer) {
	int client_sock = buffer.getItem();

	/* receive client data */
	char buff[1024];
	int client_request = receiveData(client_sock, buff, sizeof(buff));
	if (client_request <= 0) {
		return;
	}

	/* Tokenize buff */
	char *cmd = std::strtok(buff, " ");
	char *location = std::strtok(NULL, " ");
	char *http_type = std::strtok(NULL, " ");

	/* Append tokens to empty string (avoiding the std::string constructor) */
	string cmd_str = "";
	cmd_str += cmd;

	string location_str = "";
	location_str += location;

	string http_type_str = "";
	if (http_type == NULL) {
		http_type_str += "HTTP/1.1";
	}
	else {
		http_type_str += http_type;
	}

	/* Create message by appending the strings together with a space between */
	string message_buffer = "";
	message_buffer += cmd_str;
	message_buffer += " ";
	message_buffer += location_str;
	message_buffer += " ";
	message_buffer += http_type_str;

	/* check if valid request */
	if(!is_valid_request(message_buffer)) {
		send_bad_request(client_sock, http_type_str);
		close(client_sock);
		return; 
	}
	/* get path from request */
	fs::path path_to_file = get_path(location_str);

	/* check if file exists */
	if(!fs::exists(path_to_file)) {
		send_file_not_found(client_sock, http_type_str);
		close(client_sock);
		return;
	}
	generate_response(client_sock, path_to_file, http_type_str);
	close(client_sock);
} 

/**
 * Checks to see if the incoming buffer is a valid get request
 *
 * @pram buff The incoming buffer
 * @return true if valid, false if not
 */
bool is_valid_request(string buff) {
	std::regex get("GET([ \t]+)/([a-zA-Z1-9_\\-\\/.]*)([ \t]+)HTTP/([0-9]+).([0-9]+)([^]*)(Host:)*([^]*)", std::regex_constants::ECMAScript);
	return regex_match(buff, get);
}

/**
 * Generates appropriate response of the GET request
 *
 * @param client_sock Represents the socket assaigned to the client
 * @param p Boost file system formatted path for requested content
 * @param http_type Holds the HTTP/#.# from client request
 */
void generate_response(const int client_sock, fs::path p, string http_type) {
	if (fs::is_directory(p)) {
		/* check if contains index.html */
		fs::path tmp_path = p;
		tmp_path /= "index.html";
		string html = "";
		if (fs::exists(tmp_path)) {
			html += tmp_path.string();
			generate_response(client_sock, tmp_path, http_type);
		}
		else { // doesn't contain index.html; generate links and send with links
			html = generate_html_links(p);
			send_http200_response(client_sock, -1, ".html", vector<char>(), html, http_type);
		}
	}
	else if (fs::is_regular_file(p)) {
		send_regular_file(client_sock, p, http_type); 
	}
}

/**
 * Sends regurlar file after checking if the request is not a directory
 *
 * @param client_sock The socket assaigned to the given client
 * @param p Holds the path of the content requested
 * @param http_type HTTP/#.# retrieved from client request
 */
void send_regular_file(const int client_sock, fs::path p, string http_type) {
	fs::path d(fs::extension(p));

	std::ifstream in_file(p.string(), std::ios::binary|std::ios::in);
	if (!in_file) {
		cout << "Cant open file\r\n";
	}

	in_file.seekg(0, std::ios::end);
	std::streampos length = in_file.tellg();
	in_file.seekg(0, std::ios::beg);
	vector<char> buffer((std::istreambuf_iterator<char>(in_file)), std::istreambuf_iterator<char>());
	int length_int = (int) length;
	in_file.close();
	send_http200_response(client_sock, length_int, fs::extension(p), buffer, string(), http_type);
}

/**
 * Strips the root directory from a file path
 * &p Holds a certain path which the root must be removed
 */
fs::path strip_root(const fs::path &p) {
	const fs::path& parent_path = p.parent_path();
	if(parent_path.empty() || parent_path.string() == "/") {
		return fs::path();
	}
	else {
		return strip_root(parent_path) / p.filename();
	}
}

/**
 * Generates html code for the index.html fil
 *
 * @param boost::filesystem path for the specified directory
 * @return html code in form of C++ string
 */
string generate_html_links(fs::path dir) {
	fs::path path_no_root = strip_root(dir);

	vector<fs::directory_entry> list;
	std::copy(fs::directory_iterator(dir), fs::directory_iterator(), std::back_inserter(list));

	string ret_html = "";
	ret_html += "<html><head><title>Parent Directory</title></head><body>Files: ";

	ret_html.append(path_no_root.string());
	ret_html.append("<br>");

	for (fs::directory_entry d: list) {
		string next_link = "";
		next_link += "<a href=\"";

		next_link.append(d.path().filename().string());
		next_link.append("/");

		next_link.append("\">");
		next_link.append(d.path().filename().string());
		next_link.append("/");
		next_link.append("</a><br>");
		ret_html.append(next_link);
	}
	ret_html.append("</body></html>");
	return ret_html;
}

/**
 * Generates the header for the OK 200 response
 *
 * @param size Size of Vector 
 * @param http_type The HTTP/#.# obtained from client request
 * @param content The contnet of HTML file
 * @param s Vector of binary contents of file read from handleClient
 * @param ext The extension of the file requested
 * @return ret Holds the compiled header message required to form a correct
 * 200 response
 */
string generate_ok_header(int size, string http_type, string content, vector<char> s, fs::path ext) {
	string ret = "";
	ret += http_type.substr(0,8);
	ret.append(" 200 OK\r\nDate: ");
	ret.append(date_to_string());
	ret.append("\r\n");
	ret.append("Content-Length: ");

	try {
		if (size < 0) {
			ret.append(boost::lexical_cast<string>(content.length()));
		}
		else {
			ret.append(boost::lexical_cast<string>(s.size()));
		}
	} catch (const boost::bad_lexical_cast &e) {
		std::cerr <<e.what() << endl;
	}
	ret.append("\r\n");

	/* add content type */
	ret.append("Content-Type: ");
	string extension = "";
	extension += ext.string();
	ret.append(extension.substr(1));
	ret.append("\r\n\r\n");
	return ret;
}

/**
 * Sends a http 200 OK response
 *
 * @param client_sock Represents the socket assigned to the client
 * @param size Size of the vector 
 * @param ext Extension of the file read into s
 * @param s Vector of contents of file read from handleClient
 * @param content Contents of HTML file
 * @param http_type A string holding the HTTP/#.# from the client request
 */
void send_http200_response(const int client_sock, int len, fs::path ext, vector<char> s, string content, string http_type) {
	string ret = "";
	ret += generate_ok_header(len, http_type, content, s, ext);

	int msg_size = 0;
	msg_size = (len < 0) ? ret.length() +2+ content.length() : ret.length() +2+ len;

	char message[ret.length() + 1];
	strcpy(message, ret.c_str());

	char final_msg[msg_size];
	memcpy(final_msg, message, ret.length());

	if (len < 0) {
		char content_msg[content.length() + 1];
		strcpy(content_msg, content.c_str());
		memcpy((final_msg + ret.length()), content_msg, content.length());
	}
	else {
		char msg_body[s.size() + 1];
		std::copy(s.begin(), s.end(), msg_body);
		memcpy((final_msg + ret.length()), msg_body, s.size());
	}
	sendData(client_sock, final_msg, msg_size);
}

/**
 * Send 404 error html page
 *
 * @param clinet_sock Represents the socket assigned to the client
 * @param http_type String holding the HTTP/1.1 portion of the message recieved from
 * the client
 */
void send_file_not_found(const int client_sock, string http_type) {
	string ret = "";
	ret += http_type;
	ret.append("Error 404 File not found\r\nConnection: close\r\nDate: ");

	ret.append(date_to_string());
	ret.append("\r\n\r\n");
	ret.append("<html><head><title>Page not found</title></head><body><404 not found></body></html>");

	sendData(client_sock, ret.c_str(), ret.length()+1);
}

/**
 * Returns the boost::filesystem path to the specified path
 * 
 * @param location_str The path of the desired request which will have WWW
 * appended 
 * @return p A Boost FIle System formatted path  
 */
fs::path get_path(string location_str) {
	string folder = "";
	folder += "WWW";
	folder += location_str;
	fs::path p(folder);
	return p;
}


/**
 * Send http 400 bad request response
 *
 * @param client_sock Represents the socket assaigned to the client
 * @param http_type String holding the HTTP/#.# from the client request
 */
void send_bad_request(const int client_sock, string http_type) {
	if (http_type.empty()) {
		http_type = "HTTP/1.1";
	}
	string ret = "";
	ret += http_type;
	ret.append(" 400 Bad Request\r\nConnection: close\r\nDate: ");
	ret.append(date_to_string());
	ret.append("\r\n");

	char msg[ret.length() + 1];
	strcpy(msg, ret.c_str());
	sendData(client_sock, msg, sizeof(msg));
}

/**
 * Converts time_t of current time to a string
 * 
 * @return date_str the date string
 */
string date_to_string() {
	time_t rawtime;
	struct tm *timeinfo;
	char buff[80];
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(buff, sizeof(buff), "%d-%m-%Y %I:%M:%S", timeinfo);
	string str(buff);
	return str;
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
 * Sends message over given socket, raising an exception if there was a problem
 * sending.
 *
 * @param socket_fd The socket to send data over.
 * @param data The data to send.
 * @param data_length Number of bytes of data to send.
 */
void sendData(int socked_fd, const char *data, size_t data_length) {
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
