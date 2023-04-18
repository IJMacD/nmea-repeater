#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#define UDP_PORT "10110"   // Port we're listening on
#define TCP_PORT "10110"   // Port we're listening on

volatile sig_atomic_t stop;

void inthand(int signum) {
    stop = 1;
}

// Get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void print_address (struct addrinfo *p) {
    char ipstr[INET6_ADDRSTRLEN];
    void *addr;
    char *ipver;

    // get the pointer to the address itself,
    // different fields in IPv4 and IPv6:
    if (p->ai_family == AF_INET) { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("%s", ipstr);
    } else { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);

        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf("[%s]", ipstr);
    }

}

// Return a listening socket
int get_listener_socket(int socktype, char *port)
{
    int listener;     // Listening socket descriptor
    int yes=1;        // For setsockopt() SO_REUSEADDR, below
    int rv;

    struct addrinfo hints, *ai, *p;

    // Get us a socket and bind it
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, port, &hints, &ai)) != 0) {
        fprintf(stderr, "selectserver: %s\n", gai_strerror(rv));
        exit(1);
    }

    for(p = ai; p != NULL; p = p->ai_next) {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) {
            continue;
        }

        // Lose the pesky "address already in use" error message
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            close(listener);
            continue;
        }

        // printf("Bound to ");
        // print_address(p);
        // printf(":%s\n", port);

        break;
    }

    freeaddrinfo(ai); // All done with this

    if (p == NULL) {
        // If we got here, it means we didn't get bound
        fprintf(stderr, "Not bound\n");
        return -1;
    }

    if (socktype == SOCK_STREAM) {
        // Listen
        if (listen(listener, 10) == -1) {
            fprintf(stderr, "Unable to listen\n");
            return -1;
        }
    }

    return listener;
}

// Add a new file descriptor to the set
void add_to_pfds(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size)
{
    // If we don't have room, add more space in the pfds array
    if (*fd_count == *fd_size) {
        *fd_size *= 2; // Double it

        *pfds = realloc(*pfds, sizeof(**pfds) * (*fd_size));
    }

    (*pfds)[*fd_count].fd = newfd;
    (*pfds)[*fd_count].events = POLLIN; // Check ready-to-read

    fcntl(newfd, F_SETFL, O_NONBLOCK);

    (*fd_count)++;
}

// Remove an index from the set
void del_from_pfds(struct pollfd pfds[], int i, int *fd_count)
{
    // Copy the one from the end over this one
    pfds[i] = pfds[*fd_count-1];

    (*fd_count)--;
}

// Main
int main(void)
{
    int udp_listener, tcp_listener;     // Listening socket descriptors

    int newfd;        // Newly accept()ed socket descriptor
    struct sockaddr_storage remoteaddr; // Client address
    socklen_t addrlen;

    char buf[256];    // Buffer for client data

    char remoteIP[INET6_ADDRSTRLEN];

    signal(SIGINT, inthand);

    // Start off with room for 5 connections
    // (We'll realloc as necessary)
    int fd_count = 0;
    int fd_size = 5;
    struct pollfd *pfds = malloc(sizeof *pfds * fd_size);

    // Set up and get a UDP listening socket
    udp_listener = get_listener_socket(SOCK_DGRAM, UDP_PORT);

    if (udp_listener == -1) {
        fprintf(stderr, "error getting udp listening socket\n");
        exit(1);
    }

    // Add the udp listener to set
    pfds[0].fd = udp_listener;
    pfds[0].events = POLLIN; // Report ready to read on incoming connection

    printf("Listening on UDP %s\n", UDP_PORT);

    // Set up and get a TCP listening socket
    tcp_listener = get_listener_socket(SOCK_STREAM, TCP_PORT);

    if (tcp_listener == -1) {
        fprintf(stderr, "error getting tcp listening socket\n");
        exit(1);
    }

    // Add the listener to set
    pfds[1].fd = tcp_listener;
    pfds[1].events = POLLIN; // Report ready to read on incoming connection

    printf("Listening on TCP %s\n", TCP_PORT);

    fd_count = 2; // For the listeners

    // Main loop
    while(!stop) {

        int poll_count = poll(pfds, fd_count, 500);

        if (poll_count == -1) {
            // We don't need to print an error if there's an interrupt (e.g. Ctrl-C)
            if (errno == EINTR) {
                break;
            }

            perror("poll");
            exit(1);
        }
        else if (poll_count == 0) {
            // Timeout

            // OpenCPN wants server to be noisy since it has 1 second timeout
            // Run through the connections to keep alive
            for(int i = 0; i < fd_count; i++) {
                if (pfds[i].fd != udp_listener && pfds[i].fd != tcp_listener) {
                    send(pfds[i].fd, "", 0, 0);
                }
            }
        }
        else {
            // someone wants to talk

            // fprintf(stderr, "poll_count = %d\n", poll_count);

            // Run through the existing connections looking for data to read
            for(int i = 0; i < fd_count; i++) {

                // Check if someone's ready to read
                if (pfds[i].revents & POLLIN) { // We got one!!

                    // fprintf(stderr, "socket %d wants to talk\n", pfds[i].fd);

                    if (pfds[i].fd == tcp_listener) {
                        // If listener is ready to read, handle new connection

                        // fprintf(stderr, "It's the TCP listener\n");

                        addrlen = sizeof remoteaddr;
                        newfd = accept(tcp_listener,
                            (struct sockaddr *)&remoteaddr,
                            &addrlen);

                        if (newfd == -1) {
                            perror("accept");
                        } else {
                            add_to_pfds(&pfds, newfd, &fd_count, &fd_size);

                            fprintf(stderr, "new connection from %s on "
                                "socket %d\n",
                                inet_ntop(remoteaddr.ss_family,
                                    get_in_addr((struct sockaddr*)&remoteaddr),
                                    remoteIP, INET6_ADDRSTRLEN),
                                newfd);
                        }
                    } else if (pfds[i].fd == udp_listener) {

                        // fprintf(stderr, "It's the UDP listener\n");

                        // If it's the udp listener, we're getting some data
                        int nbytes = recvfrom(pfds[i].fd, buf, sizeof buf, 0, (struct sockaddr *)&remoteaddr, &addrlen);

                        // fprintf(stderr, "Got %d bytes\n", nbytes);

                        if (nbytes > 0) {
                            // We got some good data from udp listener
                            printf("%s", buf);

                            for(int j = 0; j < fd_count; j++) {
                                // Send to everyone!
                                int dest_fd = pfds[j].fd;

                                // Except the listeners
                                if (dest_fd != tcp_listener && dest_fd != udp_listener) {
                                    if (send(dest_fd, buf, nbytes, 0) == -1) {
                                        perror("send");
                                    }
                                }
                            }
                        }
                    } else {

                        // If not the one of the listeners, we're just a regular client
                        int nbytes = recv(pfds[i].fd, buf, sizeof buf, 0);

                        if (nbytes <= 0) {
                            // Got error or connection closed by client
                            if (nbytes == 0) {
                                // Connection closed
                                printf("socket %d hung up\n", pfds[i].fd);
                            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // Why?
                                // printf("socket %d had nothing to say\n", pfds[i].fd);
                                continue;
                            }
                            else {
                                perror("recv");
                            }

                            close(pfds[i].fd); // Bye!

                            del_from_pfds(pfds, i, &fd_count);
                        }
                        else {
                            // We don't care what client says
                            // fprintf(stderr, "socket %d: %s", pfds[i].fd, buf);
                        }

                        // We just ignore anything else the client sends
                    } // END handle data from client
                } // END got ready-to-read from poll()
            } // END looping through file descriptors
        }
    } // END for(;;)--and you thought it would never end!

    // Run through the connections to do some cleanup
    for(int i = 0; i < fd_count; i++) {
        if (pfds[i].fd != udp_listener) {
            close(pfds[i].fd); // Bye!
        }
    }


    return 0;
}