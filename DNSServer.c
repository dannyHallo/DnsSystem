#include "global.h"

const char *ipAddress = "127.0.0.3";

int main() {
  int tcpSock = createTCPSocket();          // this is a client for TCP traffics
  bindSocket(tcpSock, ipAddress, DNS_PORT); // since this is a server, we need to bind it to an local address and port
  listen(tcpSock, 5);                       // listen for incoming connections
  printf("Listening...\n");

  for (;;) {
    struct sockaddr_in clientInfo;
    int clientInfoSize = sizeof(clientInfo);

    int forClientSockfd = accept(tcpSock, (struct sockaddr *)&clientInfo, &clientInfoSize);
    receiveTCP(forClientSockfd, sendBuffer, SEND_BUFFER_SIZE);
    printf("Received: %s\n", sendBuffer);
    char message[] = "hello, I am a DNS server!\n";
    send(forClientSockfd, message, sizeof(message), 0);
  }
  close(tcpSock);
}
