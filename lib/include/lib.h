#pragma once

#include <cstdint>
#include "utils.h"
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <unistd.h>
#include <cstring>

#define MAX_DATA_SIZE 1500
#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(poli_tcp_data_hdr))
#define MAX_CONNECTIONS 32

struct connection {
    // common parameters
    int sockfd; // socket used for this connection
    int conn_id; // connection id
    struct sockaddr_in servaddr; // struct used to identify the destination
    pthread_mutex_t con_lock; // mutex for the connection

    // parameters for sender
    int max_window_seq; // maximum size of transmission window
    uint16_t send_base; // oldest pachet that doesn't have an ack received for it
    uint16_t next_seq_num; // next sequence number
    std::map<uint16_t, std::vector<char>> sender_window; // sender's sliding window <seqence number, pachet>

    // paramaters for receiver
    uint16_t expected_seq; // next sequence number expected
    uint16_t read_offset; // offset in pachet - useful when pachet is too large and has to be splitted
    uint16_t recv_window_size; // size of recever's transmission window
    std::map<uint16_t, std::vector<char>> receiver_window; // receiver's sliding window <seqence number, pachet>
};

int wait4connect(uint32_t ip, uint16_t port);
int setup_connection(uint32_t ip, uint16_t port);
int recv_data(int connectionid, char *buffer, int len);
int send_data(int conn_id, char *buffer, int len);
void init_receiver(int recv_buffer_bytes);
void init_sender(int speed, int delay);
int recv_message_or_timeout(char *buff, size_t len, int *conn_id);
