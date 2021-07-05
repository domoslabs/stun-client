#include <iostream>
#include <getopt.h>
#include "stun.h"
void show_help(char* progname){
    std::cout << "\nSTUN Client implementation adapted from https://github.com/0xFireWolf/STUNExternalIP, by Vladimir Monakhov. \n" << std::endl;
    std::cout << "Usage: " << progname << " <stun_server_ip> <stun_server_port> <port> [--help]"<< std::endl;
    std::cout << "stun_server_ip                  The address of the STUN server." << std::endl;
    std::cout << "stun_server_port                The port of the STUN server." << std::endl;
    std::cout << "port                            The port that you want to punch through, and obtain the NAT translation of." << std::endl;
    std::cout << "-h    --help                    Show this message." << std::endl;
}
std::string stun_server_ip;
unsigned short stun_server_port;
unsigned short port;
void parse_args(int argc, char **argv){
    const char *shortopts = "h";
    const struct option longopts[] = {
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0},
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, shortopts, longopts, &option_index)) != -1)
        switch (c)
        {
            case 'h':
                show_help(argv[0]);
                std::exit(EXIT_SUCCESS);
            default:
                std::cerr << "Invalid argument: " << c << ". See --help." << std::endl;
                std::exit(EXIT_FAILURE);
        }
    if (optind == argc) {
        std::cerr << "Missing positional arguments. See --help" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    if (optind + 3 < argc) {
        std::cerr << "Too many positional arguments. See --help" << std::endl;
        std::exit(EXIT_FAILURE);
    }
    stun_server_ip = argv[optind];
    stun_server_port = std::stoi(argv[optind+1]);
    port = std::stoi(argv[optind+2]);
}
int main(int argc, char **argv) {
    parse_args(argc, argv);
    STUNServer server = {
            &stun_server_ip[0],
            stun_server_port
    };
    STUNResults results = getSTUNResults(server, port);
    std::cout << results.ip << ":"<<unsigned(results.port)<<std::endl;
    return 0;
}
