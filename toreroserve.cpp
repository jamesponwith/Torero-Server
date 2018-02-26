/**
 * ToreroServe: A Lean Web Server
 * COMP 375 (Spring 2018) Project 02
 *
 * This program should take two arguments:
 * 	1. The port number on which to bind and listen for connections
 * 	2. The directory out of which to serve files.
 *
 * 	TODO: update author info with names and USD email addresses
 *
 * Author 1: Patrick Hall
 * 			 patrickhall@sandeigo.edu
 * Author 2: James Ponwith
 * 			 jponwith@sandeiego.edu
 */

// standard C libraries
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ctime>

// operating system specific libraries
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

// C++ standard libraries
#include <vector>
#include <thread>
#include <string>
#include <iostream>
#include <system_error>

#include <thread>
#include <mutex>

//#include <conditional_variables>

// Un-comment the following lines if you plan on using Boost's Filesystem Library.
#include <boost/filesystem.hpp>
#include <regex>
namespace fs = boost::filesystem;

#define DEBUG 1

using std::cout;
using std::string;
using std::vector;
using std::thread;
using std::endl;

// This will limit how many clients can be waiting for a connection.
static const int BACKLOG = 10;
static const int BUFF_SIZE = 2048;

// forward declarations
int createSocketAndListen(const int port_num);
void acceptConnections(const int server_sock);
void handleClient(const int client_sock);
void sendData(int socked_fd, const char *data, size_t data_length);
int receiveData(int socked_fd, char *dest, size_t buff_size);

bool is_valid_request(string buff); 
void send_bad_request(const int client_sock);
fs::path get_path(char buff[1024]); 


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
	while (num_bytes_left < 0) {
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
	// receive client data
	char buff[1024];
	int client_request = receiveData(client_sock, buff, sizeof(buff));  
	if (client_request <= 0) {
		cout << "no data received" << endl;
	}

	cout << buff << endl;

	// uses regex to  determine if valid GET request
	if (!is_valid_request(buff)) {
		// I think we need to use the filesystem library
		send_bad_request(client_sock);
		close(client_sock);
		return; // invalid request - we peacing out!
	}
	else {
		cout << "valid request" << endl;
		//cout << "invalid request" << endl;
	}


	// TODO: Parse the request to determine what response to generate. I
	fs::path path_to_file = get_path(buff);

	// TODO: Generate appropriate response.

	// TODO: Send response to client.
	// send the requested information

	//char tmp_buff[1024];
	//std::copy(buff, buff+1024, b);

	//cout << "cmd: " << cmd_str << endl;
	//cout << "location: " << location << endl;
	//cout << "http_type: " << http_type << endl;
	
	// TODO: Close connection with client.
	// woot woot
}

fs::path get_path(char buff[1024]) {
	char *cmd = std::strtok(buff, " ");
	char *location = std::strtok(NULL, " ");
	char *http_type = std::strtok(NULL, " ");

	string cmd_str(cmd);
	string location_str(location);
	string http_type_str(http_type);

	char search_buff[512];
	std::string folder("WWW");
	folder += location_str;
	folder.copy(search_buff, BUFF_SIZE);

	cout << "Before sending, send buff is: " << folder << std::endl;

	fs::path p(folder);
	cout << p;
	return p;
}

bool is_valid_request(string buff) {
	std::regex get("GET /.+ HTTP/.*");
	cout << "BUFF: " << buff << std::endl;
	bool valid = regex_search(buff, get);
	cout << (valid? "valid" : "invalid") << std::endl;
	return valid;
}

std::string date_to_string() {
	time_t curr_time = time(0);
	char get_data[80];
	strftime(get_data, 80, "%a, %d %b %Y %X", localtime(&curr_time));
	std::string date_str(get_data);
	return date_str;
}
/**
*/
void send_bad_request(const int client_sock) {
	std::string ret("HTTP:/1.1 400 Bad Request\r\nConnection: close\r\nDate: ");
	ret.append(date_to_string());
	ret.append("\r\n");

	char msg[ret.length() + 1];
	strcpy(msg, ret.c_str());
	sendData(client_sock, msg, sizeof(msg));
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
