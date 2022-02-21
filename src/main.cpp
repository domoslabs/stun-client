
#include <iostream>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <json/json.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <string>
#include <json/value.h>
#include "CLI11.hpp"
#include "stun++/message.h"
std::string stun_server_ip;
std::string  stun_server_port;
std::string  port;
struct STUNResult {
    char ext_address[NI_MAXHOST];
    char ext_port[NI_MAXSERV];

    char changed_address[NI_MAXHOST];
    char changed_port[NI_MAXSERV];

    char source_address[NI_MAXHOST];
    char source_port[NI_MAXSERV];
};
int bind_socket(const char* port){
    // Create a UDP socket
    int socketd = socket(AF_INET, SOCK_DGRAM, 0);

    // Local Address
    auto* localAddress = (sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    bzero(localAddress, sizeof(struct sockaddr_in));
    localAddress->sin_family = AF_INET;
    localAddress->sin_addr.s_addr = INADDR_ANY;
    localAddress->sin_port = htons(std::stoul(port));

    if (bind(socketd, (struct sockaddr*) localAddress, sizeof(struct sockaddr_in)) < 0)
    {
        free(localAddress);
        close(socketd);
        throw std::runtime_error("Could not bind socket.");
    }
    return socketd;
}
const char* get_local_ip(){
    const char* google_dns_server = "8.8.8.8";
    int dns_port = 53;
    struct sockaddr_in serv{};

    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
    //Socket could not be created
    if(sock < 0)
    {
        throw std::runtime_error("Socket could not be created.");
    }

    memset( &serv, 0, sizeof(serv) );
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr( google_dns_server );
    serv.sin_port = htons( dns_port );
    if(connect( sock , (const struct sockaddr*) &serv , sizeof(serv) ) < 0){
        close(sock);
        throw std::runtime_error("Could not connect to DNS.");
    }
    struct sockaddr_in name{};
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*) &name, &namelen);
    char* buffer = (char *) malloc(sizeof(char)*100);
    static const char* p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    if(p != nullptr)
    {
        close(sock);
        return p;
    }
    return nullptr;
}
unsigned char* get_identifier(){
    static unsigned char identifier[16];
    for (unsigned char & index : identifier)
    {
        struct timeval t{};
        gettimeofday(&t, nullptr);
        srand((unsigned int) t.tv_usec);
        index = rand();
    }
    return identifier;
}
void send_stun_msg(stun::message msg, const char* server_address, const char* server_port, int socketd){


    // Remote Address
    // First resolve the STUN server address
    struct addrinfo* results = nullptr;

    auto* hints = (addrinfo *)malloc(sizeof(struct addrinfo));
    bzero(hints, sizeof(struct addrinfo));
    hints->ai_family = AF_INET;
    hints->ai_socktype = SOCK_STREAM;

    if (getaddrinfo(server_address, nullptr, hints, &results) != 0)
    {
        close(socketd);
        throw std::runtime_error("Could not get address info.");
    }

    struct in_addr stunaddr{};

    // `results` is a linked list
    // Read the first node
    if (results != nullptr)
    {
        stunaddr = ((struct sockaddr_in*) results->ai_addr)->sin_addr;
    }
    else
    {
        close(socketd);
        throw std::runtime_error("Error");
    }
    // Create the remote address
    auto* remoteAddress = (sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    bzero(remoteAddress, sizeof(struct sockaddr_in));

    remoteAddress->sin_family = AF_INET;
    remoteAddress->sin_addr = stunaddr;
    remoteAddress->sin_port = htons(std::stoul(server_port));

    // Send the request
    if (sendto(socketd, msg.data(), msg.size(), 0, (struct sockaddr*) remoteAddress, sizeof(struct sockaddr_in)) == -1)
    {
        close(socketd);
        throw std::runtime_error("Could not send STUN request.");
    }
}
STUNResult recv_stun_msg(int socketd){
    STUNResult res{};
    stun::message rmsg;

    // Allocate a 2k memory block
    rmsg.resize(2*1024);

    // Receive network data directly into your STUN message block

    // Set the timeout
    struct timeval tv = {1, 0};
    setsockopt(socketd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    // Read the response
    char* buffer = (char *)malloc(sizeof(char) * 512);

    bzero(buffer, 512);

    long length = read(socketd, rmsg.data(), rmsg.capacity());
    if(length < 0){
        return res;
    }
    // Reduce the size to the packet size
    rmsg.resize(length);
    if (!rmsg.verify()) {
        throw std::runtime_error("Invalid STUN message");
    }
    // Iterate over the message attributes
    using namespace stun::attribute;
    for (auto & i : rmsg) {
        sockaddr_storage address{};
        // First, check the attribute type
        switch (i.type()) {
            case 0x8020:
            case type::xor_mapped_address:
                i.to<type::xor_mapped_address>().to_sockaddr((sockaddr*)&address);
                getnameinfo((struct sockaddr *)&address,
                            sizeof(address), res.ext_address, NI_MAXHOST, res.ext_port, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV);
                break;
            case type::changed_address:
            case type::other_address:
                i.to<type::changed_address>().to_sockaddr((sockaddr*)&address);
                getnameinfo((struct sockaddr *)&address,
                            sizeof(address), res.changed_address, NI_MAXHOST, res.changed_port, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV);
                break;
            case type::source_address:
                i.to<type::source_address>().to_sockaddr((sockaddr*)&address);
                getnameinfo((struct sockaddr *)&address,
                            sizeof(address), res.source_address, NI_MAXHOST, res.source_port, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV);
                break;
        }
    }
    return res;
}
STUNResult stun_test1(const char* server_address, const char* server_port, int socketd){

    stun::message msg(stun::message::binding_request, get_identifier() );
    STUNResult res{};
    for(int i = 0; i < 3; i++){
        send_stun_msg(msg, server_address, server_port, socketd);
        res = recv_stun_msg(socketd);
        if(strlen(res.ext_address) != 0){
            break;
        }
    }
    return res;
}
STUNResult stun_test2(const char* server_address, const char* server_port, int socketd){
    stun::message msg(stun::message::binding_request,get_identifier() );
    // Request change IP (4) and new Port (2)
    unsigned int change_data = 0x04|0x02;
    msg << stun::attribute::change_request(change_data);
    STUNResult res{};
    for(int i = 0; i < 3; i++){
        send_stun_msg(msg, server_address, server_port, socketd);
        res = recv_stun_msg(socketd);
        if(strlen(res.ext_address) != 0){
            break;
        }
    }

    return res;
}
STUNResult stun_test3(const char* server_address, const char* server_port, int socketd){
    stun::message msg(stun::message::binding_request,get_identifier() );
    // Request change Port (2)
    unsigned int change_data = 0x02;
    msg << stun::attribute::change_request(change_data);
    STUNResult res{};
    for(int i = 0; i < 3; i++){
        send_stun_msg(msg, server_address, server_port, socketd);
        res = recv_stun_msg(socketd);
        if(strlen(res.ext_address) != 0){
            break;
        }
    }
    return res;
}
int main(int argc, char **argv) {
    CLI::App app{"STUN Client implementation adapted from https://github.com/0xFireWolf/STUNExternalIP, by Domos."};
    app.add_option("--stun_server_ip", stun_server_ip, "The address of the STUN server.")->default_val("stun.ekiga.net");
    app.add_option("--stun_server_port", stun_server_port, "The port of the STUN server.")->default_val("3478");
    app.add_option("port", port, "The port that you want to punch through, and obtain the NAT translation of.")->required();
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }
    const char* ip = get_local_ip();
    Json::Value root;
    int socketd = bind_socket(port.c_str());
    // Perform STUN
    auto res1 = stun_test1(stun_server_ip.c_str(), stun_server_port.c_str(), socketd);
    // Determine NAT type
    if(strlen(res1.ext_address) == 0){
        root["nat_type"] = "blocked";
    }
    if(strcmp(res1.ext_address, ip) == 0 && strcmp(res1.ext_port, port.c_str()) == 0){
        auto res2 = stun_test2(stun_server_ip.c_str(), stun_server_port.c_str(), socketd);
        // Check if response
        if(strlen(res2.ext_address) == 0){
            // Symmetric UDP
            root["nat_type"] = "firewall";
        } else {
            // Open Internet
            root["nat_type"] = "open";
        }
    } else {
        auto res2 = stun_test2(stun_server_ip.c_str(), stun_server_port.c_str(), socketd);
        // Check if response
        if(strlen(res2.ext_address) != 0){
            root["nat_type"] = "full_cone";
        // Some other type of NAT, perform test1 with new IP.
        } else {
            auto res1_changed = stun_test1(res1.changed_address, res1.changed_port, socketd);
            if(strcmp(res1_changed.ext_address, res1.ext_address) == 0 && strcmp(res1_changed.ext_port, res1.ext_port) == 0){
                auto res3 = stun_test3(res1.changed_address, res1.changed_port, socketd);
                if(strlen(res3.ext_address) == 0){
                    root["nat_type"]="restricted_port";
                } else {
                    root["nat_type"]="restricted_cone";
                }
            } else {
                root["nat_type"]="symmetric";
            }
        }
    }
    Json::StreamWriterBuilder builder;
    root["ext_ip"] = res1.ext_address;
    root["ext_port"] = res1.ext_port;
    std::cout << Json::writeString(builder, root) << std::endl;
}
