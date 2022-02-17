#include <iostream>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include "CLI11.hpp"
#include "stun++/message.h"
#include <json/json.h>
std::string stun_server_ip;
unsigned short stun_server_port;
unsigned short port;
struct STUNResult {
    char ext_address[NI_MAXHOST];
    char ext_port[NI_MAXSERV];

    char changed_address[NI_MAXHOST];
    char changed_port[NI_MAXSERV];

    char source_address[NI_MAXHOST];
    char source_port[NI_MAXSERV];
};
int send_stun_msg(stun::message msg){
    // Create a UDP socket
    int socketd = socket(AF_INET, SOCK_DGRAM, 0);

    // Local Address
    auto* localAddress = (sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    bzero(localAddress, sizeof(struct sockaddr_in));
    localAddress->sin_family = AF_INET;
    localAddress->sin_addr.s_addr = INADDR_ANY;
    localAddress->sin_port = htons(port);

    if (bind(socketd, (struct sockaddr*) localAddress, sizeof(struct sockaddr_in)) < 0)
    {
        free(localAddress);
        close(socketd);
        throw std::runtime_error("Could not bind socket.");
    }

    // Remote Address
    // First resolve the STUN server address
    struct addrinfo* results = nullptr;

    auto* hints = (addrinfo *)malloc(sizeof(struct addrinfo));
    bzero(hints, sizeof(struct addrinfo));
    hints->ai_family = AF_INET;
    hints->ai_socktype = SOCK_STREAM;

    if (getaddrinfo(stun_server_ip.c_str(), nullptr, hints, &results) != 0)
    {
        free(localAddress);
        free(hints);
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
    remoteAddress->sin_port = htons(stun_server_port);

    // Send the request
    if (sendto(socketd, msg.data(), msg.size(), 0, (struct sockaddr*) remoteAddress, sizeof(struct sockaddr_in)) == -1)
    {
        close(socketd);
        throw std::runtime_error("Could not send STUN request.");
    }

    return socketd;
}
STUNResult recv_stun_msg(int socketd){
    STUNResult res{};
    stun::message rmsg;

    // Allocate a 2k memory block
    rmsg.resize(2*1024);

    // Receive network data directly into your STUN message block
    // Set the timeout
    struct timeval tv = {10, 0};

    setsockopt(socketd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));

    // Read the response
    char* buffer = (char *)malloc(sizeof(char) * 512);

    bzero(buffer, 512);

    long length = read(socketd, rmsg.data(), rmsg.capacity());
    if(length < 0){
        throw std::runtime_error("Timed out.");
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

int main(int argc, char **argv) {
    CLI::App app{"STUN Client implementation adapted from https://github.com/0xFireWolf/STUNExternalIP, by Domos."};
    app.add_option("stun_server_ip", stun_server_ip, "The address of the STUN server.")->required();
    app.add_option("stun_server_port", stun_server_port, "The port of the STUN server.")->required();
    app.add_option("port", port, "The port that you want to punch through, and obtain the NAT translation of.")->required();
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError &e) {
        return app.exit(e);
    }

    unsigned char identifier[16];
    for (int index = 0; index < 16; index++)
    {
        srand((unsigned int) time(0));
        identifier[index] = rand();
    }
    stun::message msg(stun::message::binding_request,identifier );


    int socketd = send_stun_msg(msg);
    auto res = recv_stun_msg(socketd);

    Json::StreamWriterBuilder builder;
    Json::Value root;
    root["ext_ip"] = res.ext_address;
    root["ext_port"] = res.ext_port;
    root["changed_address"] = res.changed_address;
    root["changed_port"] = res.changed_port;
    root["source_address"] = res.source_address;
    root["source_port"] = res.source_port;
    std::cout << Json::writeString(builder, root) << std::endl;

}
