#include "global.h"

// http://zake7749.github.io/2015/03/17/SocketProgramming/ <- tutorial for TCP connections

const char *ipAddress     = "127.0.0.2";
const char *fileName      = "rr2.txt";
const char *cacheFileName = "cache.txt";

int udpSock, tcpSock;
char sendBuffer2[SEND_BUFFER_SIZE];
char sendBuffer3[SEND_BUFFER_SIZE];
char clientIpAddress[20];
unsigned short clientPort;

// create the cache file if it doesn't exist
void createCacheIfNotExists() {
  FILE *cacheFile = fopen(cacheFileName, "a");
  fclose(cacheFile);
}

// add a line to the cache file (to the tail of the file)
void addCache(const char *lineToBeCached) {
  // append line to the laast line of cache file
  FILE *cacheFile = fopen(cacheFileName, "a");
  fprintf(cacheFile, "%s\n", lineToBeCached);
  fclose(cacheFile);
}

// if direct match is found, send back to Local DNS Server, return 1, else return 0
int findDirectMatch(const struct DNSHeader *dnsHeaderParsed, const struct DNSQuery *dnsQueryParsed) {
  // convert query type to string
  char queryTypeStr[10];
  memset(queryTypeStr, 0, sizeof(queryTypeStr));
  if (dnsQueryParsed->qtype == QUERY_TYPE_A) {
    strcpy(queryTypeStr, "A");
  } else if (dnsQueryParsed->qtype == QUERY_TYPE_MX) {
    strcpy(queryTypeStr, "MX");
  } else if (dnsQueryParsed->qtype == QUERY_TYPE_CNAME) {
    strcpy(queryTypeStr, "CNAME");
  } else if (dnsQueryParsed->qtype == QUERY_TYPE_PTR) {
    strcpy(queryTypeStr, "PTR");
  }

  printf("Answering to query: %s, query type: %s\n", dnsQueryParsed->domainName, queryTypeStr);
  printf("Finding direct match...\n");

  // try to find a direct match
  int directMatchesFound = 0;
  {
    char lineBuffer[100];
    int lineNum = 0;
    while (readCacheLine(cacheFileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
      char rrBuffer[100];
      parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
      if (!strcmp(rrBuffer, queryTypeStr)) {
        parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
        if (domainMatches(rrBuffer, dnsQueryParsed->domainName)) {
          directMatchesFound = 1;
          break;
        }
      }
    }
  }
  if (!directMatchesFound)
    return 0;

  struct DNSHeader dnsHeader;
  struct DNSQuery dnsQuery;
  char encodedDomainNameBuffer1[100];

  makeQuery(&dnsQuery, dnsQueryParsed->domainName, dnsQueryParsed->qtype, dnsQueryParsed->qclass, encodedDomainNameBuffer1,
            sizeof(encodedDomainNameBuffer1));
  makeSendBuffer(NULL, &dnsQuery, NULL);

  // append answers to send buffer
  int lineNum                = 0;
  int answersAdded           = 0;
  int additionalRecordsAdded = 0;
  char lineBuffer[100];
  while (readCacheLine(cacheFileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    printf("Checking line: %s\n", lineBuffer);

    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
    if (!strcmp(rrBuffer, queryTypeStr)) {
      struct DNSRR dnsRR;
      char resourceDataBuffer[100];
      char encodedDomainNameBuffer2[100];
      char encodedResourceDataBuffer[100];

      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      if (domainMatches(rrBuffer, dnsQueryParsed->domainName)) {
        parseResourceRecord(lineBuffer, RR_TTL, rrBuffer, sizeof(rrBuffer));
        uint32_t decodedTTL = decodeTTL(rrBuffer);
        parseResourceRecord(lineBuffer, RR_CLASS, rrBuffer, sizeof(rrBuffer));
        uint16_t decodedClass = decodeClass(rrBuffer); // this should always be in class IN (internet)
        parseResourceRecord(lineBuffer, RR_RDATA, resourceDataBuffer, sizeof(resourceDataBuffer));
        char *resourceDataBufferPtr = resourceDataBuffer;

        makeResourceRecord(&dnsRR, dnsQueryParsed->domainName, resourceDataBufferPtr, dnsQueryParsed->qtype, decodedClass,
                           decodedTTL, encodedDomainNameBuffer2, sizeof(encodedDomainNameBuffer2), encodedResourceDataBuffer,
                           sizeof(encodedResourceDataBuffer));
        addResourceRecord(&dnsRR);
        answersAdded++;
      }
    }
  }

  // append additional records to MX data types
  if (dnsQueryParsed->qtype == QUERY_TYPE_MX) {
    lineNum = 0;
    while (readCacheLine(cacheFileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
      char rrBuffer[100];
      parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
      if (!strcmp(rrBuffer, "MX")) {
        char dnsDomainNameBuffer[100];

        // get the domain name of the MX record
        parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));

        // if the domain name of the MX record matches the domain name of the query
        if (domainMatches(rrBuffer, dnsQueryParsed->domainName)) {
          parseResourceRecord(lineBuffer, RR_RDATA, dnsDomainNameBuffer, sizeof(dnsDomainNameBuffer));

          // printf("Finding matching A record for this DNS domain name: %s\n", dnsDomainNameBuffer);

          int l = 0;
          while (readCacheLine(cacheFileName, lineBuffer, sizeof(lineBuffer), l++)) {
            parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));

            // find corresponding A record of the this MX record
            if (!strcmp(rrBuffer, "A")) {
              parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));

              // if the owner of the A record matches the data of the MX record
              if (domainMatches(rrBuffer, dnsDomainNameBuffer)) {
                struct DNSRR dnsRR;
                char dnsServerIpBuffer[100];
                char encodedDomainNameBuffer2[100];
                char encodedResourceDataBuffer[100];

                parseResourceRecord(lineBuffer, RR_TTL, rrBuffer, sizeof(rrBuffer));
                uint32_t decodedTTL = decodeTTL(rrBuffer);
                parseResourceRecord(lineBuffer, RR_CLASS, rrBuffer, sizeof(rrBuffer));
                uint16_t decodedClass = decodeClass(rrBuffer); // this should always be in class IN (internet)
                parseResourceRecord(lineBuffer, RR_RDATA, dnsServerIpBuffer, sizeof(dnsServerIpBuffer));

                makeResourceRecord(&dnsRR, dnsDomainNameBuffer, dnsServerIpBuffer, QUERY_TYPE_A, decodedClass, decodedTTL,
                                   encodedDomainNameBuffer2, sizeof(encodedDomainNameBuffer2), encodedResourceDataBuffer,
                                   sizeof(encodedResourceDataBuffer));
                addResourceRecord(&dnsRR);

                additionalRecordsAdded++;
              }
            }
          }
        }
      }
    }
  }

  // make the header now, since we know how many answers and additional records we have
  makeHeader(&dnsHeader, dnsHeaderParsed->id, FALSE, TRUE, FALSE, TRUE, TRUE, 1, answersAdded, 0, additionalRecordsAdded);
  changeDNSHeader(&dnsHeader);

  printf("Direct match found in cache, sending back to client...\n");
  sendUDP(udpSock, clientIpAddress, clientPort, sendBuffer, sendBufferUsed);
  return 1;
}

// if next hop is found, send back to Local DNS Server, return 1, else return 0
int findNextHop(const struct DNSHeader *dnsHeaderParsed, const struct DNSQuery *dnsQueryParsed) {
  printf("Finding next hop...\n");

  int lineNum                = 0;
  int nextHopDomainNameFound = 0;
  char lineBuffer[100];
  char nsDomainNameBuffer[100];
  while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
    if (!strcmp(rrBuffer, "NS")) {
      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      if (domainContains(rrBuffer, dnsQueryParsed->domainName)) {
        parseResourceRecord(lineBuffer, RR_RDATA, nsDomainNameBuffer, sizeof(nsDomainNameBuffer));
        nextHopDomainNameFound = 1;
        break;
      }
    }
  }

  if (!nextHopDomainNameFound) {
    return 0;
  }

  lineNum            = 0;
  int nextHopIpFound = 0;
  char nextHopIpBuffer[100];
  // step 3: find ip address of the DNS server by its domain name
  while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
    if (!strcmp(rrBuffer, "A")) {
      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      if (domainMatches(rrBuffer, nsDomainNameBuffer)) {
        parseResourceRecord(lineBuffer, RR_RDATA, nextHopIpBuffer, sizeof(nextHopIpBuffer));
        nextHopIpFound = 1;
        break;
      }
    }
  }

  if (!nextHopIpFound)
    printf("Warning: No A record for root server! Check config!\n");

  // query to another DNS server
  {
    struct DNSHeader dnsHeader;
    struct DNSQuery dnsQuery;
    char encodedDomainNameBuffer[100];

    makeHeader(&dnsHeader, dnsHeaderParsed->id, TRUE, TRUE, FALSE, FALSE, FALSE, 1, 0, 0, 0);
    makeQuery(&dnsQuery, dnsQueryParsed->domainName, dnsQueryParsed->qtype, dnsQueryParsed->qclass, encodedDomainNameBuffer,
              sizeof(encodedDomainNameBuffer));
    makeSendBuffer(&dnsHeader, &dnsQuery, NULL);
  }
  // connect with DNS server
  printf("Connecting to %s:%d\n", nextHopIpBuffer, DNS_PORT);
  connectSocket(tcpSock, nextHopIpBuffer, DNS_PORT);

  sendTCP(tcpSock, sendBuffer, sendBufferUsed);
  return 1;
}

// handle queries sent from client, return 1 if cache is found, else return 0
int handleUDP() {
  struct DNSHeader dnsHeaderParsed;
  struct DNSQuery dnsQueryParsed;
  char domainNameBuffer[100];

  parseDNSHeader(&dnsHeaderParsed);
  parseDNSQuery(&dnsQueryParsed, domainNameBuffer, sizeof(domainNameBuffer));

  if (findDirectMatch(&dnsHeaderParsed, &dnsQueryParsed))
    return 1;

  if (findNextHop(&dnsHeaderParsed, &dnsQueryParsed))
    return 0;

  printf("ERROR: No next hop found!\n");
}

// handle queries sent from other DNS servers, decide whether to send to client or to another DNS server
void handleTCP() {
  for (;;) {
    receiveTCP(tcpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);
    // reset connection
    close(tcpSock);
    tcpSock = createTCPSocket();
    bindSocket(tcpSock, ipAddress, 5678); // we don't need to bind it to an local address and port for functionality

    printf("Received TCP packet:\n");
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

      makeHeader(&dnsHeader, dnsHeaderParsed.id, TRUE, TRUE, FALSE, FALSE, FALSE, 1, 0, 0, 0);
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

      struct DNSHeader dnsHeader;
      struct DNSQuery dnsQuery;
      char encodedDomainNameBuffer1[100];

      // save receiving buffer
      memcpy(sendBuffer2, sendBuffer, SEND_BUFFER_SIZE);

      // update sendBuffer for sending
      makeHeader(&dnsHeader, dnsHeaderParsed.id, FALSE, TRUE, TRUE, TRUE, TRUE, 1, dnsHeaderParsed.answerCount, 0,
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

        // add dns rr line to cache
        char cachedLine[100];
        constructResourceRecordLine(&dnsRRParsed, cachedLine, sizeof(cachedLine));
        addCache(cachedLine); // add to cache

        struct DNSRR dnsRR;
        char encodedDomainNameBuffer2[100];
        char encodedResourceDataBuffer[100];
        makeResourceRecord(&dnsRR, dnsRRParsed.domainName, dnsRRParsed.resourceData, dnsRRParsed.qtype, dnsRRParsed.qclass,
                           dnsRRParsed.ttl, encodedDomainNameBuffer2, sizeof(encodedDomainNameBuffer2), encodedResourceDataBuffer,
                           sizeof(encodedResourceDataBuffer));

        // load constructioning buffer
        memcpy(sendBuffer, sendBuffer3, SEND_BUFFER_SIZE);
        addResourceRecord(&dnsRR);
        // save constructioning buffer
        memcpy(sendBuffer3, sendBuffer, SEND_BUFFER_SIZE);
      }

      // send to client
      // printf("Sending response:\n");
      // printInHex(sendBuffer, sendBufferUsed);
      sendUDP(udpSock, clientIpAddress, clientPort, sendBuffer, sendBufferUsed);
      return;
    }
    // no next hop or answer
    else {
      {
        struct DNSRR dnsRRParsed;
        struct DNSHeader dnsHeader;
        struct DNSQuery dnsQuery;
        char encodedDomainNameBuffer[100];

        makeHeader(&dnsHeader, dnsHeaderParsed.id, FALSE, TRUE, TRUE, TRUE, TRUE, 1, 0, 0, 0);
        makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer,
                  sizeof(encodedDomainNameBuffer));
        makeSendBuffer(&dnsHeader, &dnsQuery, NULL);

        // send to client
        sendUDP(udpSock, clientIpAddress, clientPort, sendBuffer, sendBufferUsed);
        return;
      }
    }
  }
}

int main() {
  checkFileExistance(fileName);
  createCacheIfNotExists();

  udpSock = createUDPSocket();              // this is a server for UDP traffics
  tcpSock = createTCPSocket();              // this is a client for TCP traffics
  bindSocket(udpSock, ipAddress, DNS_PORT); // since this is a server, we need to bind it to an local address and port
  bindSocket(tcpSock, ipAddress, 5678);     // we don't need to bind it to an local address and port for functionality
  printf("Local DNS Server Started\n");

  for (;;) {
    printf("\nWaiting for client...\n");
    receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, clientIpAddress, sizeof(clientIpAddress), &clientPort);

    if (handleUDP())
      continue;

    printf("\nWaiting for dns server...\n");
    handleTCP();
  }
  close(udpSock);
  close(tcpSock);
}
