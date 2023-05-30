// TODO: print trace

#include "global.h"

const char *ipAddress = "127.0.0.1";
int udpSock;
int seed = 2147483647;

void makeQueryContent(const char *originalQueryContent, char *queryContentBuffer, const int queryContentBufferSize) {
  // Split the IP address into octets
  int octets[4];
  sscanf(originalQueryContent, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]);

  // Generate the PTR query string in reverse order
  snprintf(queryContentBuffer, queryContentBufferSize, "%d.%d.%d.%d.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
}

// send request to local DNS server
void DNSRequest(const uint16_t queryType, const char *queryContent) {
  printf("Processing user query: %s\n", queryContent);

  {
    char domainNameBuffer[200];
    struct DNSHeader dnsHeader;
    makeHeader(&dnsHeader, getRandomID(&seed), TRUE, TRUE, FALSE, TRUE, FALSE, 1, 0, 0, 0);
    struct DNSQuery dnsQuery;

    char realQueryContent[100];
    memset(realQueryContent, 0, sizeof(realQueryContent));
    if (queryType == QUERY_TYPE_PTR) {
      makeQueryContent(queryContent, realQueryContent, sizeof(realQueryContent));
    } else {
      strcpy(realQueryContent, queryContent);
    }

    printf("Query: %s\n", realQueryContent);
    makeQuery(&dnsQuery, realQueryContent, queryType, QUERY_CLASS_IN, domainNameBuffer, sizeof(domainNameBuffer));
    makeSendBuffer(&dnsHeader, &dnsQuery, NULL);
  }

  const char *localDNSServerAddress = "127.0.0.2";
  printf("Server: %s\n", localDNSServerAddress);
  printf("Server: %s#53\n\n", localDNSServerAddress);

  // send packet to local DNS server
  sendUDP(udpSock, localDNSServerAddress, DNS_PORT, sendBuffer, sendBufferUsed);
}

void handleReply() {
  struct DNSHeader dnsHeaderParsed;
  struct DNSQuery dnsQueryParsed;
  struct DNSRR dnsRRParsed;
  char domainNameBuffer1[100];
  char domainNameBuffer2[100];
  char resourceDataBuffer[100];

  parseDNSHeader(&dnsHeaderParsed);
  int pointerOffset = parseDNSQuery(&dnsQueryParsed, domainNameBuffer1, sizeof(domainNameBuffer1));

  // answer found
  if (dnsHeaderParsed.answerCount > 0) {
    // check if it is an authoritive answer
    uint16_t isAuthoritiveAnswer = dnsHeaderParsed.tag & TAG_IS_AA_BIT;
    if (isAuthoritiveAnswer) {
      printf("\nAuthoritative answer: \n");
    } else {
      printf("\nNon-authoritative answer: \n");
    }

    int i;
    for (i = 0; i < dnsHeaderParsed.answerCount + dnsHeaderParsed.additionalCount; ++i) {
      pointerOffset = parseDNSRR(&dnsRRParsed, pointerOffset, domainNameBuffer2, sizeof(domainNameBuffer2), resourceDataBuffer,
                                 sizeof(resourceDataBuffer));

      char answerNotice[50];
      if (dnsRRParsed.qtype == QUERY_TYPE_A) {
        strcpy(answerNotice, "Address");
      } else if (dnsQueryParsed.qtype == QUERY_TYPE_CNAME) {
        strcpy(answerNotice, "Canonical name");
      } else if (dnsQueryParsed.qtype == QUERY_TYPE_MX) {
        strcpy(answerNotice, "Mail exchange");
      } else if (dnsQueryParsed.qtype == QUERY_TYPE_PTR) {
        strcpy(answerNotice, "Name");
      } else {
        strcpy(answerNotice, "Unknown Type");
      }

      printf("Name: %s\n", dnsRRParsed.domainName);
      printf("%s: %s\n\n", answerNotice, dnsRRParsed.resourceData);
    }
    return;
  }
  // no answer found
  else {
    printf("\nNo data found!\n\n");
    return;
  }
}

// format:
// -type=queryType queryName
void oneTimeQuery(int argc, char *argv[]) {
  char *queryName = argv[2];

  uint16_t queryType;
  if (!strcmp(argv[1], "-type=a")) {
    queryType = QUERY_TYPE_A;
  } else if (!strcmp(argv[1], "-type=mx")) {
    queryType = QUERY_TYPE_MX;
  } else if (!strcmp(argv[1], "-type=cname")) {
    queryType = QUERY_TYPE_CNAME;
  } else if (!strcmp(argv[1], "-type=ptr")) {
    queryType = QUERY_TYPE_PTR;
  } else {
    printf("Invalid command found!\n");
    printf("Usage: ./DNSClient -type=[a|mx|cname|ptr] queryName\n");
    return;
  }

  // send query
  DNSRequest(queryType, queryName);

  // waiting for local DNS server's reply
  receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);
  handleReply();
  close(udpSock);
}

// format:
// 1. set type=queryType queryName
// 2. queryName (using previous queryType) (default queryType=MX)
void recursiveQuery() {
  uint16_t queryType = QUERY_TYPE_PTR;

  printf("DNSClient Started\n");
  for (;;) {
  nextTry : {
    char queryName[100];
    memset(queryName, 0, sizeof(queryName));

    char inputCommand[100];
    char littleBuf[100];
    memset(inputCommand, 0, sizeof(inputCommand));
    memset(littleBuf, 0, sizeof(littleBuf));

    printf("> ");
    fgets(inputCommand, sizeof(inputCommand), stdin);

    char *ptr     = inputCommand - 1;
    int termCount = 0;

    char *lbp = littleBuf;
    while (*(++ptr)) {
      // meets null terminator
      if (*ptr == 0x0a) {
        termCount++;

        // start a query
        if (termCount == 1) {
          strcpy(queryName, littleBuf);
          DNSRequest(queryType, queryName);
          break;
        }
        // set query type
        else if (termCount == 2) {
          // check for standard format
          const char *standardFormat = "type=";
          const char *p              = standardFormat - 1;
          const char *p2             = littleBuf;
          while (*(++p)) {
            if (*(p2++) != *p) {
              printf("Invalid command found!\n");
              goto nextTry;
            }
          }
          p2--;

          // extract out the query type
          char queryTypeBuffer[10];
          char *p3 = queryTypeBuffer;
          memset(queryTypeBuffer, 0, sizeof(queryTypeBuffer));
          while (*(++p2)) {
            *(p3++) = *p2;
          }

          if (!strcmp(queryTypeBuffer, "a")) {
            queryType = QUERY_TYPE_A;
          } else if (!strcmp(queryTypeBuffer, "mx")) {
            queryType = QUERY_TYPE_MX;
          } else if (!strcmp(queryTypeBuffer, "cname")) {
            queryType = QUERY_TYPE_CNAME;
          } else if (!strcmp(queryTypeBuffer, "ptr")) {
            queryType = QUERY_TYPE_PTR;
          } else {
            printf("unknown query type: %s\n", queryTypeBuffer);
          }
          goto nextTry;
        } else {
          printf("Too much parameters!\n");
          goto nextTry;
        }
      }

      if (*ptr == ' ') {
        termCount++;

        if (termCount == 1) {
          // if the first command is not set
          if (strcmp(littleBuf, "set")) {
            printf("Invalid command found!\n");
            goto nextTry;
          }
        } else {
          printf("Too much parameters!\n");
          goto nextTry;
        }

        memset(littleBuf, 0, sizeof(littleBuf));
        lbp = littleBuf;
        continue;
      }
      *(lbp++) = tolower(*ptr);
    }

    // waiting for local DNS server's reply
    receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);
    handleReply();
  }
  }
  close(udpSock);
}

int main(int argc, char *argv[]) {
  udpSock = createUDPSocket();

  if (argc == 1) {
    recursiveQuery();
  } else if (argc == 3) {
    oneTimeQuery(argc, argv);
  } else {
    printf("Invalid command!\n");
  }
}