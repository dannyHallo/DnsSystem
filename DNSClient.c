#include "global.h"

const char *ipAddress = "127.0.0.1";
int udpSock;

void DNSRequest(const uint16_t queryType, const char *queryContent) {
  printf("Processing user query: %s\n", queryContent);

  {
    char domainNameBuffer[200];
    struct DNSHeader dnsHeader;
    makeHeader(&dnsHeader, getRandomID(), TRUE, TRUE, FALSE, 1, 0, 0, 0);
    struct DNSQuery dnsQuery;
    makeQuery(&dnsQuery, queryContent, queryType, QUERY_CLASS_IN, domainNameBuffer, sizeof(domainNameBuffer));
    makeSendBuffer(&dnsHeader, &dnsQuery, NULL);
  }

  const char *localDNSServerAddress = "127.0.0.2";
  printf("Server: %s\n", localDNSServerAddress);
  printf("Server: %s#53\n\n", localDNSServerAddress);

  // send packet to local DNS server
  sendUDP(udpSock, localDNSServerAddress, DNS_PORT, sendBuffer, sendBufferUsed);
  printf("DNS query created and sent to LocalDNSServer.\n");
  printInHex(sendBuffer, sendBufferUsed);
}

int main(int argc, char *argv[]) {
  udpSock = createUDPSocket();

  // set the default query type to A
  uint16_t queryType = QUERY_TYPE_A;

  for (;;) {
  nextTry:
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
        // set query
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

          break;
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
  }

  receiveUDP(udpSock, sendBuffer, SEND_BUFFER_SIZE, NULL, NULL, 0, NULL);
  printf("Received: %s\n", sendBuffer);

  close(udpSock);
}