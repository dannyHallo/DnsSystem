#include "global.h"

// http://zake7749.github.io/2015/03/17/SocketProgramming/

const char *ipAddress = "127.0.0.2";

int main() {
  int udpSock = createUDPSocket();          // this is a server for UDP traffics
  int tcpSock = createTCPSocket();          // this is a client for TCP traffics
  bindSocket(udpSock, ipAddress, DNS_PORT); // since this is a server, we need to bind it to an local address and port

  printf("Listening...\n");

  for (;;) {
    int receivedBufferSize;
    char receivedFromAddressBuffer[50];
    unsigned short receivedFromPort;

    printf("Testing UDP...\n");
    receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, &receivedBufferSize, receivedFromAddressBuffer,
               sizeof(receivedFromAddressBuffer), &receivedFromPort);
    printf("Handling client %s\n", receivedFromAddressBuffer);
    sendUDP(udpSock, receivedFromAddressBuffer, receivedFromPort, sendBuffer, receivedBufferSize);
    printf("Sent back to client %s\n", sendBuffer);

    printf("Testing TCP...\n");
    char bufferToSend[] = "hello, this is a Local DNS server, also a TCP client!\n";
    // connect socket with the tcp server
    connectSocket(tcpSock, "127.0.0.3", DNS_PORT);
    sendTCP(tcpSock, bufferToSend, sizeof(bufferToSend));
    printf("Sent to DNSClient.\n");
    receiveTCP(tcpSock, sendBuffer, SEND_BUFFER_SIZE);
    printf("Received: %s\n", sendBuffer);
  }
  close(udpSock);
  close(tcpSock);
}
