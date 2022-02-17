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
void recv_stun_msg(int socketd, char* hoststr, char* portstr){
    stun::message rmsg;

    // Allocate a 2k memory block
    rmsg.resize(2*1024);

    // Receive network data directly into your STUN message block
    // Set the timeout
    struct timeval tv = {5, 0};

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
    for (stun::message::iterator i = rmsg.begin(), ie = rmsg.end(); i != ie; i++) {
        // First, check the attribute type
        switch (i->type()) {
            case type::xor_mapped_address:
                sockaddr_storage address;
                i->to<type::xor_mapped_address>().to_sockaddr((sockaddr*)&address);


                getnameinfo((struct sockaddr *)&address,
                            sizeof(address), hoststr, NI_MAXHOST, portstr, NI_MAXSERV,
                            NI_NUMERICHOST | NI_NUMERICSERV);
                break;
        }
    }
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
    int a = 2;
    int b = 4;
    msg << stun::attribute::change_request(a|b);

    char hoststr[NI_MAXHOST];
    char portstr[NI_MAXSERV];
    int socketd = send_stun_msg(msg);
    recv_stun_msg(socketd, hoststr, portstr);


    Json::StreamWriterBuilder builder;
    Json::Value root;
    root["ip"] = hoststr;
    root["port"] = portstr;
    //STUNResults results = getSTUNResults(server, port, msg);
    std::cout << Json::writeString(builder, root) << std::endl;

}
