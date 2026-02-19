#include "common.hpp"
#include <unordered_set>

int main(int argc, char** argv) {
     if (argc != 2) {
          std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
          std::cerr << "Incorrect number of arguments. Try to use key --help." << std::endl;
          exit(-1);
     }
     
     bool success = true;
     int port = std::stoi(argv[1]);
     srand(time(0));
     Message msg = { };
     std::unordered_set<int> numbers;
     auto dest_address = local_addr(port);
     int sock_fd = check(make_socket(SOCK_STREAM));
     check(connect(sock_fd, (sockaddr * ) & dest_address, sizeof(dest_address)));
     
     int min = 0, max = 10000;
     
     msg = {0, Start};
     msg.to_net_order();
     send(sock_fd, &msg, sizeof msg, MSG_WAITALL);
     msg = {min, SetMin};
     msg.to_net_order();
     send(sock_fd, &msg, sizeof msg, MSG_WAITALL);
     msg = {max, SetMax};
     msg.to_net_order();
     send(sock_fd, &msg, sizeof msg, MSG_WAITALL);
     auto size = check_except(recv(sock_fd, &msg, sizeof(msg), MSG_WAITALL), ENOTCONN);
     
     if (size < 1) {
          close(sock_fd);
          std::cout << "Bot >> Server has been disconnected\n";
          exit(0);
     }
     
     msg.to_host_order();
     if (msg.status == Guess) {
          while(true) {
               int number = min + rand() % (max - min + 1);
               while (numbers.find(number) != numbers.end())
                    number = min + rand() % (max - min + 1);
               numbers.insert(number);
               std::cout << "Bot >> Trying a number " << number << std::endl;
               msg = {number, Number};
               msg.to_net_order();
               send(sock_fd, &msg, sizeof msg, MSG_WAITALL);
               auto size = check_except(recv(sock_fd, &msg, sizeof(msg), MSG_WAITALL), ENOTCONN);
               if (size < 1) {
                    success = false;
                    break;
               }
               
               msg.to_host_order();
               if (msg.status == Equal) {
                    std::cout << "Guesser >> You guess! Guessed number is " << number << std::endl;
                    std::cout << "Bot << I guess number " << number;
                    break;
               } else if (msg.status == Large || msg.status == Less) {
                    std::cout << "Guesser >> No, guessed number is not " << number << std::endl;
               } else
                    std::cout << "Guesser >> Your number is out of guess bounds\n";
               sleep(1);
          }
     } else
          std::cout << "Bot >> The max value has been less or equal to the min value\n";
     
     close(sock_fd);
     
     if (!success)
          std::cout << "Bot >> Server has been disconnected\n";
     
     return 0;
}

