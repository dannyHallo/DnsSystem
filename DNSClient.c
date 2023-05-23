#include "global.h"

const char *ipAddress = "127.0.0.1";

int main(int argc, char *argv[]) {
  int udpSock = createUDPSocket();
  // bindSocket(udpSock, ipAddress, tmpPort);

  char strTest[] = "hello world";

  sendUDP(udpSock, "127.0.0.2", DNS_PORT, strTest, strlen(strTest));
  printf("message sent to LocalDNSServer.\n");

  receiveUDP(udpSock, receivedBuffer, RECEIVED_BUFFER_SIZE, NULL, NULL, 0, NULL);
  printf("Received: %s\n", receivedBuffer);

  close(udpSock);
}