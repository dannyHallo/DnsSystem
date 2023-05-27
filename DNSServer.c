#include "global.h"

char ipAddress[50];
char fileName[50];
int forClientSock;
int tcpSock;

void handleRequest() {
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

  printf("Answering to query: %s, query type: %s\n", dnsQueryParsed.domainName, queryTypeStr);

  // step 1: check if there is at least one direct match
  char lineBuffer[100];
  int lineNum            = 0;
  int directMatchesFound = 0;
  while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
    char rrBuffer[100];
    parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
    if (!strcmp(rrBuffer, queryTypeStr)) {
      parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
      if (domainMatches(rrBuffer, dnsQueryParsed.domainName)) {
        directMatchesFound = 1;
        break;
      }
    }
  }

  if (directMatchesFound) {
    struct DNSHeader dnsHeader;
    struct DNSQuery dnsQuery;
    char encodedDomainNameBuffer1[100];

    makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer1,
              sizeof(encodedDomainNameBuffer1));
    makeSendBuffer(NULL, &dnsQuery, NULL);

    // append answers to send buffer
    lineNum                    = 0;
    int answersAdded           = 0;
    int additionalRecordsAdded = 0;
    while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
      char rrBuffer[100];
      parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
      if (!strcmp(rrBuffer, queryTypeStr)) {
        struct DNSRR dnsRR;
        char resourceDataBuffer[100];
        char encodedDomainNameBuffer2[100];
        char encodedResourceDataBuffer[100];

        parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));
        if (domainMatches(rrBuffer, dnsQueryParsed.domainName)) {
          parseResourceRecord(lineBuffer, RR_TTL, rrBuffer, sizeof(rrBuffer));
          uint32_t decodedTTL = decodeTTL(rrBuffer);
          parseResourceRecord(lineBuffer, RR_CLASS, rrBuffer, sizeof(rrBuffer));
          uint16_t decodedClass = decodeClass(rrBuffer); // this should always be in class IN (internet)
          parseResourceRecord(lineBuffer, RR_RDATA, resourceDataBuffer, sizeof(resourceDataBuffer));
          char *resourceDataBufferPtr = resourceDataBuffer;

          makeResourceRecord(&dnsRR, dnsQueryParsed.domainName, resourceDataBufferPtr, dnsQueryParsed.qtype, decodedClass,
                             decodedTTL, encodedDomainNameBuffer2, sizeof(encodedDomainNameBuffer2), encodedResourceDataBuffer,
                             sizeof(encodedResourceDataBuffer));
          addResourceRecord(&dnsRR);
          answersAdded++;
        }
      }
    }

    // append additional records to MX data types
    if (dnsQueryParsed.qtype == QUERY_TYPE_MX) {
      lineNum = 0;
      while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
        char rrBuffer[100];
        parseResourceRecord(lineBuffer, RR_TYPE, rrBuffer, sizeof(rrBuffer));
        if (!strcmp(rrBuffer, "MX")) {
          char dnsDomainNameBuffer[100];

          // get the domain name of the MX record
          parseResourceRecord(lineBuffer, RR_OWNER, rrBuffer, sizeof(rrBuffer));

          // if the domain name of the MX record matches the domain name of the query
          if (domainMatches(rrBuffer, dnsQueryParsed.domainName)) {
            parseResourceRecord(lineBuffer, RR_RDATA, dnsDomainNameBuffer, sizeof(dnsDomainNameBuffer));

            printf("Finding matching A record for this DNS domain name: %s\n", dnsDomainNameBuffer);

            int l = 0;
            while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), l++)) {
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
    makeHeader(&dnsHeader, dnsHeaderParsed.id, FALSE, FALSE, FALSE, 1, answersAdded, 0, additionalRecordsAdded);
    changeDNSHeader(&dnsHeader);

    printf("Packet created:\n");
    printInHex(sendBuffer, sendBufferUsed);
    sendTCP(forClientSock, sendBuffer, sendBufferUsed);
    return;
  }

  printf("No answer found in this server.\n");

  lineNum               = 0;
  int nsDomainNameFound = 0;
  char nsDomainNameBuffer[100];
  while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
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

  if (!nsDomainNameFound) {
    printf("No NS record found!\n");

    struct DNSHeader dnsHeader;
    struct DNSQuery dnsQuery;
    char encodedDomainNameBuffer1[100];
    makeHeader(&dnsHeader, dnsHeaderParsed.id, FALSE, FALSE, FALSE, 1, 0, 0, 0);
    makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer1,
              sizeof(encodedDomainNameBuffer1));
    makeSendBuffer(&dnsHeader, &dnsQuery, NULL);

    sendTCP(forClientSock, sendBuffer, sendBufferUsed);
    return;
  }

  lineNum       = 0;
  int nsIpFound = 0;
  char nsIpBuffer[100];
  // step 3: find ip address of the DNS server by its domain name
  while (readResourceRecordLine(fileName, lineBuffer, sizeof(lineBuffer), lineNum++)) {
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
    printf("Warning: No A record for root server! Check config!\n");
  }

  printf("Next hop address retrieved: %s\n", nsIpBuffer);
  {
    struct DNSHeader dnsHeader;
    struct DNSQuery dnsQuery;
    struct DNSRR dnsRR;
    char encodedDomainNameBuffer1[100];
    char encodedDomainNameBuffer2[100];
    char encodedResourceDataBuffer[100];

    printf("next DNS server: %s\n", nsIpBuffer);

    makeHeader(&dnsHeader, dnsHeaderParsed.id, FALSE, FALSE, FALSE, 1, 0, 1, 0);
    makeQuery(&dnsQuery, dnsQueryParsed.domainName, dnsQueryParsed.qtype, dnsQueryParsed.qclass, encodedDomainNameBuffer1,
              sizeof(encodedDomainNameBuffer1));
    makeResourceRecord(&dnsRR, nsDomainNameBuffer, nsIpBuffer, QUERY_TYPE_A, QUERY_CLASS_IN, 86400, encodedDomainNameBuffer2,
                       sizeof(encodedDomainNameBuffer2), encodedResourceDataBuffer, sizeof(encodedResourceDataBuffer));

    makeSendBuffer(&dnsHeader, &dnsQuery, &dnsRR);
  }

  printf("Sending back to client...\n");
  sendTCP(forClientSock, sendBuffer, sendBufferUsed);
}

int main(int argc, char *argv[]) {
  strcpy(fileName, argv[1]);
  strcpy(ipAddress, argv[2]);

  checkFileExistance(fileName);

  tcpSock = createTCPSocket();              // this is a client for TCP traffics
  bindSocket(tcpSock, ipAddress, DNS_PORT); // since this is a server, we need to bind it to an local address and port
  listen(tcpSock, 5);                       // listen for incoming connections
  printf("DNS Server Started\n");

  for (;;) {
    printf("\nWaiting for incoming connections...\n");

    struct sockaddr_in clientInfo;
    int clientInfoSize = sizeof(clientInfo);

    forClientSock = accept(tcpSock, (struct sockaddr *)&clientInfo, &clientInfoSize);
    receiveTCP(forClientSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);

    handleRequest();
    close(forClientSock);
  }
  close(tcpSock);
}
