#include "global.h"

// http://zake7749.github.io/2015/03/17/SocketProgramming/ <- tutorial for TCP connections

const char *ipAddress = "127.0.0.2";
const char *fileName  = "rr2.txt";

int udpSock, tcpSock;
char sendBuffer2[SEND_BUFFER_SIZE];
char sendBuffer3[SEND_BUFFER_SIZE];
char clientIpAddress[20];
unsigned short clientPort;

// handle queries sent from client
void handleUDP() {
  struct DNSHeader dnsHeaderParsed;
  struct DNSQuery dnsQueryParsed;
  char domainNameBuffer[100];
  parseDNSHeader(&dnsHeaderParsed);
  parseDNSQuery(&dnsQueryParsed, domainNameBuffer, sizeof(domainNameBuffer));

  char queryTypeStr[10];
  memset(queryTypeStr, 0, sizeof(queryTypeStr));
  if (dnsQueryParsed.qtype == QUERY_TYPE_A) {
    strcpy(queryTypeStr, "A");
  } else if (dnsQueryParsed.qtype == QUERY_TYPE_MX) {
    strcpy(queryTypeStr, "MX");
  } else if (dnsQueryParsed.qtype == QUERY_TYPE_CNAME) {
    strcpy(queryTypeStr, "CNAME");
  } else if (dnsQueryParsed.qtype == QUERY_TYPE_PTR) {
    strcpy(queryTypeStr, "PTR");
  }

  char lineBuffer[100];
  int lineNum          = 0;
  int directMatchFound = 0;

  // step 1: find direct match
  while (readLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));

    if (!strcmp(rrBuffer, queryTypeStr)) {
      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      if (domainMatches(rrBuffer, dnsQueryParsed.domainName)) {
        directMatchFound = 1;
        break;
      }
    }
  }

  if (directMatchFound) {
    printf("Direct match found!\n");
    // TODO: typically, direct A matches in local DNS server is in the cache file, handle this later
  }

  lineNum               = 0;
  int nsDomainNameFound = 0;
  char nsDomainNameBuffer[100];
  // step 2: find domain name of related DNS server
  while (readLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
    if (!strcmp(rrBuffer, "NS")) {
      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      int returnValue = domainContains(rrBuffer, dnsQueryParsed.domainName);

      if (returnValue) {
        parseResourceRecord(lineBuffer, RR_RDATA, nsDomainNameBuffer, sizeof(nsDomainNameBuffer));
        nsDomainNameFound = 1;
        break;
      }
    }
  }

  // the conguration file has some problem, check it now
  if (!nsDomainNameFound) {
    printf("WARNING: NO NS RECORD FOR ROOT SERVER! CHECK CONFIG!\n");
  }

  lineNum       = 0;
  int nsIpFound = 0;
  char nsIpBuffer[100];
  // step 3: find ip of the root dns server
  while (readLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
    if (!strcmp(rrBuffer, "A")) {
      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      if (domainMatches(rrBuffer, nsDomainNameBuffer)) {
        parseResourceRecord(lineBuffer, RR_RDATA, nsIpBuffer, sizeof(nsIpBuffer));
        nsIpFound = 1;
        break;
      }
    }
  }

  // the conguration file has some problem, check it now
  if (!nsIpFound) {
    printf("WARNING: NO NS RECORD FOR ROOT SERVER! CHECK CONFIG!\n");
  }

  printf("Next hop address found\n");

  // query to another DNS server
  if (dnsHeaderParsed.answerCount == 0) {
    struct DNSHeader dnsHeader;
    struct DNSQuery dnsQuery;
    struct DNSRR dnsRR;
    char encodedDomainNameBuffer[100];

    makeHeader(&dnsHeader, dnsHeaderParsed.id, TRUE, FALSE, FALSE, 1, 0, 0, 0);
    makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer,
              sizeof(encodedDomainNameBuffer));
    makeSendBuffer(&dnsHeader, &dnsQuery, NULL);
  }

  // connect with DNS server
  printf("Connecting to %s:%d\n", nsIpBuffer, DNS_PORT);
  connectSocket(tcpSock, nsIpBuffer, DNS_PORT);

  sendTCP(tcpSock, sendBuffer, sendBufferUsed);
}

// handle queries sent from other DNS servers, decide whether to send to client or to another DNS server
void handleTCP() {
  for (;;) {
    receiveTCP(tcpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);
    // close connection
    close(tcpSock);
    tcpSock = createTCPSocket();

    printInHex(sendBuffer, sendBufferUsed);

    struct DNSHeader dnsHeaderParsed;
    struct DNSQuery dnsQueryParsed;
    char domainNameBuffer1[100];

    parseDNSHeader(&dnsHeaderParsed);
    int pointerOffset = parseDNSQuery(&dnsQueryParsed, domainNameBuffer1, sizeof(domainNameBuffer1));

    // query to another DNS server
    if (dnsHeaderParsed.authorCount > 0 && dnsHeaderParsed.answerCount == 0) {
      struct DNSRR dnsRRParsed;
      char domainNameBuffer2[100];
      char resourceDataBuffer[100];
      parseDNSRR(&dnsRRParsed, pointerOffset, domainNameBuffer2, sizeof(domainNameBuffer2), resourceDataBuffer,
                 sizeof(resourceDataBuffer));

      struct DNSHeader dnsHeader;
      struct DNSQuery dnsQuery;
      char encodedDomainNameBuffer[100];

      makeHeader(&dnsHeader, dnsHeaderParsed.id, TRUE, FALSE, FALSE, 1, 0, 0, 0);
      makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer,
                sizeof(encodedDomainNameBuffer));
      makeSendBuffer(&dnsHeader, &dnsQuery, NULL);

      printf("Next hop address retrieved: %s\n", resourceDataBuffer);
      // connect with DNS server
      printf("Connecting to %s:%d\n", resourceDataBuffer, DNS_PORT);
      connectSocket(tcpSock, resourceDataBuffer, DNS_PORT);

      sendTCP(tcpSock, sendBuffer, sendBufferUsed);
      continue;
    }

    // answer DNS client
    if (dnsHeaderParsed.answerCount > 0) {
      printf("Answering DNS client\n");

      printInHex(sendBuffer, sendBufferUsed);
      printf("\n");
      printInHex(sendBuffer, SEND_BUFFER_SIZE);

      struct DNSHeader dnsHeader;
      struct DNSQuery dnsQuery;
      char encodedDomainNameBuffer1[100];

      // save receiving buffer
      memcpy(sendBuffer2, sendBuffer, SEND_BUFFER_SIZE);

      // update sendBuffer for sending
      makeHeader(&dnsHeader, dnsHeaderParsed.id, FALSE, TRUE, TRUE, 1, dnsHeaderParsed.answerCount, 0,
                 dnsHeaderParsed.additionalCount);
      makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer1,
                sizeof(encodedDomainNameBuffer1));
      makeSendBuffer(&dnsHeader, &dnsQuery, NULL);

      // save constructioning buffer
      memcpy(sendBuffer3, sendBuffer, SEND_BUFFER_SIZE);

      int i;
      for (i = 0; i < dnsHeaderParsed.answerCount + dnsHeaderParsed.additionalCount; ++i) {
        // load receiving buffer
        memcpy(sendBuffer, sendBuffer2, SEND_BUFFER_SIZE);

        struct DNSRR dnsRRParsed;
        char domainNameBuffer2[100];
        char resourceDataBuffer[100];
        pointerOffset = parseDNSRR(&dnsRRParsed, pointerOffset, domainNameBuffer2, sizeof(domainNameBuffer2), resourceDataBuffer,
                                   sizeof(resourceDataBuffer));

        struct DNSRR dnsRR;
        char encodedDomainNameBuffer2[100];
        char encodedResourceDataBuffer[100];
        makeResourceRecord(&dnsRR, dnsRRParsed.domainName, dnsRRParsed.resourceData, dnsRRParsed.qtype, dnsRRParsed.qclass,
                           dnsRRParsed.ttl, encodedDomainNameBuffer2, sizeof(encodedDomainNameBuffer2), encodedResourceDataBuffer,
                           sizeof(encodedResourceDataBuffer));

        // load constructioning buffer
        memcpy(sendBuffer, sendBuffer3, SEND_BUFFER_SIZE);
        appendResourceRecord(&dnsRR);
        // save constructioning buffer
        memcpy(sendBuffer3, sendBuffer, SEND_BUFFER_SIZE);
      }

      // send to client
      sendUDP(udpSock, clientIpAddress, clientPort, sendBuffer, sendBufferUsed);
      return;
    }
  }
}

int main() {
  checkFileExistance(fileName);

  udpSock = createUDPSocket();              // this is a server for UDP traffics
  tcpSock = createTCPSocket();              // this is a client for TCP traffics
  bindSocket(udpSock, ipAddress, DNS_PORT); // since this is a server, we need to bind it to an local address and port

  printf("Local DNS Server Started\n");

  for (;;) {
    printf("Waiting for client...\n");
    receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, clientIpAddress, sizeof(clientIpAddress), &clientPort);
    printf("UDP packet received from %s:%d\n", clientIpAddress, clientPort);

    printf("Handling queries...\n");
    handleUDP();
    printf("Queries handled\n");

    printf("Waiting for TCP...\n");
    handleTCP();
    printf("TCP handled\n");
  }
  close(udpSock);
  close(tcpSock);
}
