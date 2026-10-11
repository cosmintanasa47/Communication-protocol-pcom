#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
#include <sys/timerfd.h>

using namespace std;

std::map<int, struct connection *> cons;
struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;
int listen_sockfd; // socket used only for listening for new connections
int global_recv_buffer_bytes = 0; // size of recv buffer
pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER; // global mutex for structs used by multiple threads

int recv_data(int conn_id, char *buffer, int len)
{
    // get pointer to connection
    pthread_mutex_lock(&global_lock);
    auto itc = cons.find(conn_id);
    if (itc == cons.end()) {
        pthread_mutex_unlock(&global_lock);
        return -1;
    }
    struct connection *con = itc->second;
    pthread_mutex_unlock(&global_lock);

    while (1) {
        pthread_mutex_lock(&con->con_lock);

        // check for packets in the window
        if (!con->receiver_window.empty()) {
            auto it = con->receiver_window.begin();
            uint16_t seq = it->first;

            // check if pachet is in order - not out of order
            if (seq < con->expected_seq) {
                // read the packet or parts of it if it is too large
                std::vector<char>& packet = it->second;
                struct poli_tcp_data_hdr *hdr = (struct poli_tcp_data_hdr *)packet.data();
                int payload_len = ntohs(hdr->len);
                int available_bytes = payload_len - con->read_offset;
                int bytes_to_copy = available_bytes;

                if (bytes_to_copy > len)
                    bytes_to_copy = len;

                memcpy(buffer, packet.data() + sizeof(struct poli_tcp_data_hdr) + con->read_offset, bytes_to_copy);
                con->read_offset += bytes_to_copy;

                if (con->read_offset == payload_len) {
                    con->receiver_window.erase(it);
                    con->read_offset = 0;
                }

                pthread_mutex_unlock(&con->con_lock);
                return bytes_to_copy;
            }
        }

        pthread_mutex_unlock(&con->con_lock);
        usleep(1000);
    }
}

void *receiver_handler(void *arg)
{
    char segment[MAX_SEGMENT_SIZE];
    int res;
    DEBUG_PRINT("starting receiver handler\n");

    while (1) {
        // check for active connections
        // if no conns - sleep 10 ms
        pthread_mutex_lock(&global_lock);
        bool empty = cons.empty();
        pthread_mutex_unlock(&global_lock);

        if (empty) {
            usleep(10000);
            continue;
        }

        int conn_id = -1;
        // check if we receive packet or timeout
        // sleep to avoid busy waiting
        do {
            pthread_mutex_lock(&global_lock);
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
            pthread_mutex_unlock(&global_lock);
            if (res == -14)
                usleep(1000);
        } while (res == -14);

        if (res < 0 && res != -1)
            continue;

        // we have a pachet and we lock the connection for processing
        pthread_mutex_lock(&global_lock);
        auto itc = cons.find(conn_id);
        if (itc == cons.end()) {
            pthread_mutex_unlock(&global_lock);
            continue;
        }
        struct connection *con = itc->second;
        pthread_mutex_unlock(&global_lock);

        pthread_mutex_lock(&con->con_lock);


        // check if it a data packet
        if (res > 0) {
            struct poli_tcp_data_hdr *data_hdr = (struct poli_tcp_data_hdr *)segment;

            if (data_hdr->protocol_id == POLI_PROTOCOL_ID && data_hdr->type == TYPE_DATA) {
                uint16_t seq = ntohs(data_hdr->seq_num);
                uint16_t payload_len = ntohs(data_hdr->len);

                // check if packet is a new one, if duplicate we still send ack
                if (seq >= con->expected_seq) {
                    std::vector<char> packet(sizeof(struct poli_tcp_data_hdr) + payload_len);
                    memcpy(packet.data(), segment, packet.size());
                    con->receiver_window[seq] = packet;

                    // slide the window to the oldest packet not received
                    while (con->receiver_window.find(con->expected_seq) != con->receiver_window.end())
                        con->expected_seq++;
                }

                // send cummulative ack for the sequence of packets received
                if (con->expected_seq > 0) {
                    struct poli_tcp_ctrl_hdr ack_hdr;
                    memset(&ack_hdr, 0, sizeof(ack_hdr));

                    ack_hdr.protocol_id = POLI_PROTOCOL_ID;
                    ack_hdr.conn_id = conn_id;
                    ack_hdr.type = TYPE_ACK;
                    ack_hdr.ack_num = htons(con->expected_seq - 1);

                    // flow control
                    uint16_t free_space = 0;
                    if (con->recv_window_size > con->receiver_window.size())
                        free_space = con->recv_window_size - con->receiver_window.size();

                    ack_hdr.recv_window = htons(free_space);

                    // send ack
                    sendto(con->sockfd, &ack_hdr, sizeof(ack_hdr), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
                }
            }
        }
        pthread_mutex_unlock(&con->con_lock);
    }

    return NULL;
}

int wait4connect(uint32_t ip, uint16_t port)
{
    struct connection *con = new connection();

    // reserve unique id for connection
    pthread_mutex_lock(&global_lock);
    int conn_id = fdmax;
    fdmax++;
    pthread_mutex_unlock(&global_lock);

    // initial receiver parameters
    con->expected_seq = 0;
    con->read_offset = 0;
    con->recv_window_size = global_recv_buffer_bytes / MAX_SEGMENT_SIZE;

    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    char buf[MAX_SEGMENT_SIZE];
    struct poli_tcp_ctrl_hdr *syn_hdr = (struct poli_tcp_ctrl_hdr *)buf;

    // wait for syn from sender
    do {
        memset(buf, 0, sizeof(buf));
        cli_len = sizeof(cli_addr);
        recvfrom(listen_sockfd, buf, MAX_SEGMENT_SIZE, 0, (struct sockaddr *)&cli_addr, &cli_len);
    } while (syn_hdr->protocol_id != POLI_PROTOCOL_ID || syn_hdr->type != TYPE_SYN);

    con->servaddr = cli_addr;

    // create new conndection on another port for the communication
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in new_serv_addr;
    memset(&new_serv_addr, 0, sizeof(struct sockaddr_in));
    new_serv_addr.sin_family = AF_INET;
    new_serv_addr.sin_port = 0;
    new_serv_addr.sin_addr.s_addr = INADDR_ANY;
    bind(con->sockfd, (const struct sockaddr *)&new_serv_addr, sizeof(new_serv_addr));

    socklen_t new_len = sizeof(new_serv_addr);
    getsockname(con->sockfd, (struct sockaddr *)&new_serv_addr, &new_len);
    uint16_t new_port = new_serv_addr.sin_port;

    // timeout for the new socket
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


    // handshake that begins on port 8032 and finishes on the new connection's port
    char syn_ack_buf[sizeof(struct poli_tcp_data_hdr) + sizeof(uint16_t)];
    struct poli_tcp_data_hdr *syn_ack_hdr = (struct poli_tcp_data_hdr *)syn_ack_buf;

    while (1) {
        memset(syn_ack_buf, 0, sizeof(syn_ack_buf));
        syn_ack_hdr->protocol_id = POLI_PROTOCOL_ID;
        syn_ack_hdr->conn_id = conn_id;
        syn_ack_hdr->type = TYPE_SYN_ACK;
        syn_ack_hdr->seq_num = 0;
        syn_ack_hdr->len = htons(sizeof(uint16_t));
        memcpy(syn_ack_buf + sizeof(struct poli_tcp_data_hdr), &new_port, sizeof(uint16_t));

        sendto(listen_sockfd, syn_ack_buf, sizeof(syn_ack_buf), 0, (struct sockaddr *)&cli_addr, cli_len);

        memset(buf, 0, sizeof(buf));
        int ret = recvfrom(con->sockfd, buf, MAX_SEGMENT_SIZE, 0, NULL, NULL);

        if (ret > 0) {
            int pkt_type = ((struct poli_tcp_ctrl_hdr *)buf)->type;
            if (pkt_type == TYPE_ACK || pkt_type == TYPE_DATA)
                break;
        }
    }

    // unable timeout - we use poll with timer for multiplexing after handshake
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    pthread_mutex_lock(&global_lock);
    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    data_fds[conn_id].fd = con->sockfd;
    data_fds[conn_id].events = POLLIN;

    timer_fds[conn_id].fd = timerfd_create(CLOCK_REALTIME, 0);
    timer_fds[conn_id].events = POLLIN;
    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = 10000000;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = 10000000;
    timerfd_settime(timer_fds[conn_id].fd, 0, &spec, NULL);
    pthread_mutex_unlock(&global_lock);

    DEBUG_PRINT("connection established");
    return conn_id;
}

void init_receiver(int recv_buffer_bytes)
{
    pthread_t thread1;
    int ret;

    // create socket for receiving syn
    listen_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv_addr;
    socklen_t socket_len = sizeof(struct sockaddr_in);

    memset(&serv_addr, 0, socket_len);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(8032);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    int rc = bind(listen_sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    assert(rc >= 0);

    // initialize pollfds with fd -1 for unused slots
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        data_fds[i].fd = -1;
        data_fds[i].events = 0;
        timer_fds[i].fd = -1;
        timer_fds[i].events = 0;
    }

    ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);

    // save size of buffer for calculating window size
    global_recv_buffer_bytes = recv_buffer_bytes;
}
