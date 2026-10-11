#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>

using namespace std;

std::map<int, struct connection *> cons;
struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;
int global_window_size = 0; // global size of transmission window
pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER; // mutex for structs used by multiple threads (cons, data_fds, timer_fds, fdmax)

int send_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    // get pointer to connection from cons
    pthread_mutex_lock(&global_lock);
    auto itc = cons.find(conn_id);
    if (itc == cons.end()) {
        pthread_mutex_unlock(&global_lock);
        return -1;
    }
    struct connection *con = itc->second;
    pthread_mutex_unlock(&global_lock);

    // lock mutex for this connection
    pthread_mutex_lock(&con->con_lock);

    // flow control - check if sender's window is full
    if (con->sender_window.size() >= (size_t)con->max_window_seq) {
        pthread_mutex_unlock(&con->con_lock);
        usleep(1000);
        return -1;
    }

    // limit data size
    int bytes_to_send = len;
    if (bytes_to_send > MAX_DATA_SIZE)
        bytes_to_send = MAX_DATA_SIZE;

    // build pachet (header and payload)
    std::vector<char> packet(sizeof(struct poli_tcp_data_hdr) + bytes_to_send);
    struct poli_tcp_data_hdr *hdr = (struct poli_tcp_data_hdr *)packet.data();

    hdr->protocol_id = POLI_PROTOCOL_ID;
    hdr->conn_id = conn_id;
    hdr->type = TYPE_DATA;
    hdr->seq_num = htons(con->next_seq_num);
    hdr->len = htons(bytes_to_send);

    memcpy(packet.data() + sizeof(struct poli_tcp_data_hdr), buffer, bytes_to_send);

    // send packet via UDP
    sendto(con->sockfd, packet.data(), packet.size(), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

    DEBUG_PRINT("packet sent - seq_num %d, len %d\n", con->next_seq_num, bytes_to_send);

    // save packet in sliding window and update connection's state variables
    con->sender_window[con->next_seq_num] = packet;
    con->next_seq_num++;
    size = bytes_to_send;

    pthread_mutex_unlock(&con->con_lock);
    return size; // return the number of bytes sent
}

void *sender_handler(void *arg)
{
    int res = 0;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {
        // check for active connections
        pthread_mutex_lock(&global_lock);
        bool empty = cons.empty();
        pthread_mutex_unlock(&global_lock);

        if (empty) {
            usleep(10000);
            continue;
        }

        int conn_id = -1;

        // wait for message or timeout
        // use sleep to avoid busy waiting
        do {
            pthread_mutex_lock(&global_lock);
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
            pthread_mutex_unlock(&global_lock);
            if (res == -14)
                usleep(1000);
        } while (res == -14);

        // ignore unexpected errors
        if (res < 0 && res != -1)
            continue;

        // check if connection is open to avoid errors
        pthread_mutex_lock(&global_lock);
        auto itc = cons.find(conn_id);
        if (itc == cons.end()) {
            pthread_mutex_unlock(&global_lock);
            continue;
        }
        struct connection *con = itc->second;
        pthread_mutex_unlock(&global_lock);

        // lock the current connection for processing
        pthread_mutex_lock(&con->con_lock);

        if (res > 0) {
            // got packet and process it
            struct poli_tcp_ctrl_hdr *ctrl_hdr = (struct poli_tcp_ctrl_hdr *)buf;

            if (ctrl_hdr->protocol_id == POLI_PROTOCOL_ID && ctrl_hdr->type == TYPE_ACK) {
                // extract acks if we have and for the number of acks we slide the window and delete the packets
                uint16_t ack_num = ntohs(ctrl_hdr->ack_num);
                DEBUG_PRINT("got cummulative ack %d\n", ack_num);

                for (uint16_t seq = con->send_base; seq <= ack_num; seq++)
                    con->sender_window.erase(seq);

                if (ack_num >= con->send_base)
                    con->send_base = ack_num + 1;
            }
        }
        else if (res == -1) {
            // timeout for timerfd - we have to retransmit the first packet from the window
            if (!con->sender_window.empty()) {
                auto it = con->sender_window.begin();
                sendto(con->sockfd, it->second.data(), it->second.size(), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
            }
        }
        pthread_mutex_unlock(&con->con_lock);
    }
}

int setup_connection(uint32_t ip, uint16_t port)
{
    struct connection *con = new connection();

    // get unique id for connection
    pthread_mutex_lock(&global_lock);
    int conn_id = fdmax;
    fdmax++;
    pthread_mutex_unlock(&global_lock);

    // create socket for connection and initialize connection's parameters
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    con->max_window_seq = global_window_size;
    con->send_base = 0;
    con->next_seq_num = 0;

    // timeout for socket
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // set the server's address, initialize and continue the handshake in while
    memset(&con->servaddr, 0, sizeof(struct sockaddr_in));
    con->servaddr.sin_family = AF_INET;
    con->servaddr.sin_port = port;
    con->servaddr.sin_addr.s_addr = ip;

    struct poli_tcp_ctrl_hdr syn_hdr;
    memset(&syn_hdr, 0, sizeof(struct poli_tcp_ctrl_hdr));
    syn_hdr.protocol_id = POLI_PROTOCOL_ID;
    syn_hdr.conn_id = conn_id;
    syn_hdr.type = TYPE_SYN;

    char buf[MAX_SEGMENT_SIZE];
    struct sockaddr_in recv_addr;
    socklen_t recv_len = sizeof(recv_addr);
    struct poli_tcp_data_hdr *syn_ack_hdr = (struct poli_tcp_data_hdr *)buf;

    while (1) {
        sendto(con->sockfd, &syn_hdr, sizeof(syn_hdr), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        memset(buf, 0, sizeof(buf));
        recv_len = sizeof(recv_addr);
        int ret = recvfrom(con->sockfd, buf, MAX_SEGMENT_SIZE, 0, (struct sockaddr *)&recv_addr, &recv_len);

        if (ret > 0 && syn_ack_hdr->protocol_id == POLI_PROTOCOL_ID && syn_ack_hdr->type == TYPE_SYN_ACK)
            break;
    }

    // get the new port allocated on server
    uint16_t new_port;
    memcpy(&new_port, buf + sizeof(struct poli_tcp_data_hdr), sizeof(uint16_t));
    con->servaddr.sin_port = new_port;

    // finish handshake with final ack
    struct poli_tcp_ctrl_hdr ack_hdr;
    memset(&ack_hdr, 0, sizeof(struct poli_tcp_ctrl_hdr));
    ack_hdr.protocol_id = POLI_PROTOCOL_ID;
    ack_hdr.conn_id = conn_id;
    ack_hdr.type = TYPE_ACK;

    sendto(con->sockfd, &ack_hdr, sizeof(ack_hdr), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

    // unable timeout and use poll for multiplexing
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // populate the global structs with the new connection
    pthread_mutex_lock(&global_lock);
    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    data_fds[conn_id].fd = con->sockfd;
    data_fds[conn_id].events = POLLIN;

    // create 10ms timer for retransmission
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
    return conn_id; // return the id of established connection
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;

    global_window_size = (speed * delay * 125) / MAX_DATA_SIZE;

    // initialize pollfds with fd -1 for unused slots
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        data_fds[i].fd = -1;
        data_fds[i].events = 0;
        timer_fds[i].fd = -1;
        timer_fds[i].events = 0;
    }

    DEBUG_PRINT("initialized sender - window size = %d\n", global_window_size);

    ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
