//
//  STUNExternalIP.c
//  STUNExternalIP
//
//  Created by FireWolf on 2016-11-16.
//  Revised by FireWolf on 2017-02-24.
//
//  Copyright © 2016-2017 FireWolf. All rights reserved.
//

#include "stun.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdexcept>

// MARK: === PRIVATE DATA STRUCTURE ===

// RFC 5389 Section 6 STUN Message Structure
struct STUNMessageHeader
{
    // Message Type (Binding Request / Response)
    unsigned short type;
    
    // Payload length of this message
    unsigned short length;
    
    // Magic Cookie
    unsigned int cookie;
    
    // Unique Transaction ID
    unsigned int identifier[3];
};

#define XOR_MAPPED_ADDRESS_TYPE 0x0020

// RFC 5389 Section 15 STUN Attributes
struct STUNAttributeHeader
{
    // Attibute Type
    unsigned short type;
    
    // Payload length of this attribute
    unsigned short length;
};

#define IPv4_ADDRESS_FAMILY 0x01;
#define IPv6_ADDRESS_FAMILY 0x02;

// RFC 5389 Section 15.2 XOR-MAPPED-ADDRESS
struct STUNXORMappedIPv4Address
{
    unsigned char reserved;
    
    unsigned char family;
    
    unsigned short port;
    
    unsigned int address;
};

///
/// Get the external IPv4 address
///
/// @param server A STUN server
/// @param address A non-null buffer to store the public IPv4 address
/// @return 0 on success.
/// @warning This function returns
///          -1 if failed to bind the socket;
///          -2 if failed to resolve the given STUN server;
///          -3 if failed to send the STUN request;
///          -4 if failed to read from the socket (and timed out; default = 5s);
///          -5 if failed to get the external address.
///
struct STUNResults getSTUNResults(struct STUNServer server, unsigned short port)
{
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
    
    if (getaddrinfo(server.address, nullptr, hints, &results) != 0)
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
        free(localAddress);
        
        free(hints);
        
        freeaddrinfo(results);
        
        close(socketd);

        throw std::runtime_error("Error");
    }
    
    // Create the remote address
    auto* remoteAddress = (sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    
    bzero(remoteAddress, sizeof(struct sockaddr_in));
    
    remoteAddress->sin_family = AF_INET;
    
    remoteAddress->sin_addr = stunaddr;
    
    remoteAddress->sin_port = htons(server.port);
    
    // Construct a STUN request
    auto* request = (STUNMessageHeader *)malloc(sizeof(struct STUNMessageHeader));
    
    request->type = htons(0x0001);
    
    request->length = htons(0x0000);
    
    request->cookie = htonl(0x2112A442);
    
    for (int index = 0; index < 3; index++)
    {
        srand((unsigned int) time(0));
        
        request->identifier[index] = rand();
    }
    
    // Send the request
    if (sendto(socketd, request, sizeof(struct STUNMessageHeader), 0, (struct sockaddr*) remoteAddress, sizeof(struct sockaddr_in)) == -1)
    {
        free(localAddress);
        
        free(hints);
        
        freeaddrinfo(results);
        
        free(remoteAddress);
        
        free(request);
        
        close(socketd);

        throw std::runtime_error("Could not send STUN request.");
    }
    
    // Set the timeout
    struct timeval tv = {5, 0};
    
    setsockopt(socketd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(struct timeval));
    
    // Read the response
    char* buffer = (char *)malloc(sizeof(char) * 512);
    
    bzero(buffer, 512);
    
    long length = read(socketd, buffer, 512);
    
    if (length < 0)
    {
        free(localAddress);
        free(hints);
        freeaddrinfo(results);
        free(remoteAddress);
        free(request);
        free(buffer);
        close(socketd);

        throw std::runtime_error("Could not read response.");
    }
    
    char* pointer = buffer;
    
    auto* response = (struct STUNMessageHeader*) buffer;
    
    if (response->type == htons(0x0101))
    {
        // Check the identifer
        for (int index = 0; index < 3; index++)
        {
            if (request->identifier[index] != response->identifier[index])
            {
                throw std::runtime_error("Received wrong identifier.");
            }
        }
        
        pointer += sizeof(struct STUNMessageHeader);
        
        while (pointer < buffer + length)
        {
            auto* header = (struct STUNAttributeHeader*) pointer;
            
            if (header->type == htons(XOR_MAPPED_ADDRESS_TYPE))
            {
                pointer += sizeof(struct STUNAttributeHeader);
                
                auto* xorAddress = (struct STUNXORMappedIPv4Address*) pointer;
                
                unsigned int numAddress = htonl(xorAddress->address)^0x2112A442;
                unsigned short port = htons(xorAddress->port)^0x2112;
                char *strAddress = (char *)malloc(20);
                // Parse the IP address, and save it in strAddress
                snprintf(strAddress, 20, "%d.%d.%d.%d",
                         (numAddress >> 24) & 0xFF,
                         (numAddress >> 16) & 0xFF,
                         (numAddress >> 8)  & 0xFF,
                         numAddress & 0xFF);
                STUNResults stunResults = {
                        strAddress,
                        port
                };
                free(localAddress);
                free(hints);
                freeaddrinfo(results);
                free(remoteAddress);
                free(request);
                free(buffer);
                close(socketd);
                return stunResults;
            }
            
            pointer += (sizeof(struct STUNAttributeHeader) + ntohs(header->length));
        }
    }
    
    free(localAddress);
    free(hints);
    freeaddrinfo(results);
    free(remoteAddress);
    free(request);
    free(buffer);
    close(socketd);

    throw std::runtime_error("Undefined error.");
}

