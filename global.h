#include <stdio.h> // for printf() and fprintf()

#include <stdlib.h> // for atoi() and exit()
#include <string.h> // for memset()

#ifdef __linux__
#include <arpa/inet.h>  // for sockaddr_in and inet_addr()
#include <sys/socket.h> // for socket(), sendto() and recvfrom()
#include <unistd.h>     // for close()
#elif _WIN32
#include <windows.h>
#pragma comment(lib, "wsock32.lib") // link with wsock32.lib
// #include <WinSock2.h> // windows alternative to sys/socket.h
#endif

#define RECEIVED_BUFFER_SIZE 512
#define DNS_PORT 53

char receivedBuffer[RECEIVED_BUFFER_SIZE];

int createUDPSocket() {
  int sock;
  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    printf("socket() failed.\n");
    return -1;
  }
  return sock;
}

int createTCPSocket() {
  int sock;
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    printf("socket() failed.\n");
    return -1;
  }
  return sock;
}

void bindSocket(const int socket, const char *bindToAddress, const unsigned short bindToPort) {
  // construct local address structure
  struct sockaddr_in thisAddr;
  memset(&thisAddr, 0, sizeof(thisAddr));
  thisAddr.sin_family      = AF_INET;
  thisAddr.sin_addr.s_addr = inet_addr(bindToAddress);
  // thisAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  thisAddr.sin_port = htons(bindToPort);

  // bind to the local address
  int bindResult = bind(socket, (struct sockaddr *)&thisAddr, sizeof(thisAddr));
  if (bindResult < 0) {
    printf("bind() failed.\n");
  }
}

void connectSocket(const int socket, const char *connectToAddress, const unsigned short connectToPort) {
  // construct local address structure
  struct sockaddr_in thisAddr;
  memset(&thisAddr, 0, sizeof(thisAddr));
  thisAddr.sin_family      = AF_INET;
  thisAddr.sin_addr.s_addr = inet_addr(connectToAddress);
  thisAddr.sin_port        = htons(connectToPort);

  int err = connect(socket, (struct sockaddr *)&thisAddr, sizeof(thisAddr));
  if (err < 0) {
    printf("connect() failed.\n");
  }
}

void sendUDP(const int socket, const char *sendToAddress, const unsigned short sendToPort, const char *bufferToSend,
             const int bufferSize) {
  // construct the server address structure
  struct sockaddr_in sendToAddr;
  memset(&sendToAddr, 0, sizeof(sendToAddr));
  sendToAddr.sin_family      = AF_INET;                  // internet addr family
  sendToAddr.sin_addr.s_addr = inet_addr(sendToAddress); // server IP address
  sendToAddr.sin_port        = htons(sendToPort);        // server port

  sendto(socket, bufferToSend, bufferSize, 0, (struct sockaddr *)&sendToAddr, sizeof(sendToAddr));
}

void sendTCP(const int socket, const char *bufferToSend, const int bufferSize) { send(socket, bufferToSend, bufferSize, 0); }

void receiveUDP(const int socket, char *bufferToReceive, const int bufferSize, int *receivedBufferSize,
                char *receivedFromAddressBuffer, const int receivedFromAddressBufferSize, unsigned short *receivedFromPort) {
  if (bufferToReceive == NULL) {
    printf("Error: bufferToReceive is NULL\n");
    return;
  }
  memset(bufferToReceive, 0, bufferSize);

  if (receivedFromAddressBuffer != NULL)
    memset(receivedFromAddressBuffer, 0, receivedFromAddressBufferSize);

  struct sockaddr_in receivedFromAddr;
  unsigned int senderAddrSize = sizeof(receivedFromAddr);

  if (receivedBufferSize == NULL) {
    recvfrom(socket, bufferToReceive, bufferSize, 0, (struct sockaddr *)&receivedFromAddr, &senderAddrSize);
  } else {
    *receivedBufferSize = recvfrom(socket, bufferToReceive, bufferSize, 0, (struct sockaddr *)&receivedFromAddr, &senderAddrSize);
  }

  if (receivedFromAddressBuffer != NULL)
    strcpy(receivedFromAddressBuffer, inet_ntoa(receivedFromAddr.sin_addr));
  if (receivedFromPort != NULL)
    *receivedFromPort = ntohs(receivedFromAddr.sin_port);
}

void receiveTCP(const int socket, char *bufferToReceive, const int bufferSize) {
  memset(bufferToReceive, 0, bufferSize);
  recv(socket, bufferToReceive, bufferSize, 0);
}