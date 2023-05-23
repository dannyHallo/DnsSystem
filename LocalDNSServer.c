#include "global.h"

// http://zake7749.github.io/2015/03/17/SocketProgramming/ <- tutorial for TCP connections

const char *ipAddress = "127.0.0.2";
const char *fileName  = "rr2.txt";

int udpSock, tcpSock;

void handleUDP() {
  printf("handling UDP packet\n");

  struct DNSHeader dnsHeaderParsed;
  struct DNSQuery dnsQueryParsed;
  char domainNameBuffer[100];
  parseDNSHeader(&dnsHeaderParsed);
  parseDNSQuery(&dnsQueryParsed, domainNameBuffer, sizeof(domainNameBuffer));

  char lineBuffer[100];
  int lineNum          = 0;
  int directMatchFound = 0;

  // step 1: find direct match
  while (readLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));

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
      if (domainContains(rrBuffer, dnsQueryParsed.domainName)) {
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

  // connect socket with the tcp server
  connectSocket(tcpSock, nsIpBuffer, DNS_PORT);
  sendTCP(tcpSock, sendBuffer, sendBufferUsed);
  printf("Sent to DNSServer.\n");
}

int main() {
  int udpSock = createUDPSocket();          // this is a server for UDP traffics
  int tcpSock = createTCPSocket();          // this is a client for TCP traffics
  bindSocket(udpSock, ipAddress, DNS_PORT); // since this is a server, we need to bind it to an local address and port

  printf("Local DNS Server Started\n");

  for (;;) {
    char clientAddress[50];
    unsigned short clientPort;

    printf("Waiting for UDP...\n");
    receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, clientAddress, sizeof(clientAddress), &clientPort);
    handleUDP();

    receiveTCP(tcpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);
    printf("Received: %s\n", sendBuffer);

    // reply client by using this:
    sendUDP(udpSock, clientAddress, clientPort, sendBuffer, sendBufferUsed);
  }
  close(udpSock);
  close(tcpSock);
}
