#include <stdio.h> // for printf() and fprintf()

#include <stdint.h> // for uint16_t...
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

#define SEND_BUFFER_SIZE 512
#define DNS_PORT 53

#define FALSE 0
#define TRUE 1

#define PATH_OF_RR "records/"

// the following structs announced are of padding 1
#pragma pack(push, 1)
struct DNSHeader {
  uint16_t id;
  uint16_t tag;
  uint16_t questionCount;
  uint16_t answerCount;
  uint16_t authorCount;
  uint16_t additionalCount;
};

struct DNSQuery {
  char *domainName;
  uint16_t qtype;
  uint16_t qclass;
};

struct DNSRR {
  char *domainName;
  uint16_t qtype;
  uint16_t qclass;
  uint32_t ttl;
  uint16_t resourceDataLength;
  char *resourceData;
};
#pragma pack(pop)

const uint16_t QUERY_TYPE_A     = 0x0001;
const uint16_t QUERY_TYPE_MX    = 0x000f;
const uint16_t QUERY_TYPE_CNAME = 0x0005;
const uint16_t QUERY_TYPE_PTR   = 0x000c;

const uint16_t QUERY_CLASS_IN = 0x0001; // indicates the internet system

// the resource records are stored in rr files
const int RR_OWNER = 0;
const int RR_TTL   = 1;
const int RR_CLASS = 2;
const int RR_TYPE  = 3;
const int RR_RDATA = 4;

char sendBuffer[SEND_BUFFER_SIZE];
int sendBufferUsed = 0;

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
    printf("Error: bufferToReceive cannot be NULL!\n");
    return;
  }
  memset(bufferToReceive, 0, bufferSize);

  if (receivedFromAddressBuffer != NULL)
    memset(receivedFromAddressBuffer, 0, receivedFromAddressBufferSize);

  struct sockaddr_in receivedFromAddr;
  unsigned int senderAddrSize = sizeof(receivedFromAddr);

  sendBufferUsed = recvfrom(socket, bufferToReceive, bufferSize, 0, (struct sockaddr *)&receivedFromAddr, &senderAddrSize);
  if (receivedBufferSize != NULL)
    *receivedBufferSize = sendBufferUsed;

  if (receivedFromAddressBuffer != NULL)
    strcpy(receivedFromAddressBuffer, inet_ntoa(receivedFromAddr.sin_addr));
  if (receivedFromPort != NULL)
    *receivedFromPort = ntohs(receivedFromAddr.sin_port);
}

// TODO: update sendBufferUsed
// void receiveTCP(const int socket, char *bufferToReceive, const int bufferSize) {
//   memset(bufferToReceive, 0, bufferSize);
//   recv(socket, bufferToReceive, bufferSize, 0);
// }

void receiveTCP(const int socket, char *bufferToReceive, const int bufferSize, int *receivedBufferSize,
                char *receivedFromAddressBuffer, const int receivedFromAddressBufferSize, unsigned short *receivedFromPort) {
  if (bufferToReceive == NULL) {
    printf("Error: bufferToReceive cannot be NULL!\n");
    return;
  }
  memset(bufferToReceive, 0, bufferSize);

  if (receivedFromAddressBuffer != NULL)
    memset(receivedFromAddressBuffer, 0, receivedFromAddressBufferSize);

  struct sockaddr_in receivedFromAddr;
  unsigned int senderAddrSize = sizeof(receivedFromAddr);

  sendBufferUsed = recvfrom(socket, bufferToReceive, bufferSize, 0, (struct sockaddr *)&receivedFromAddr, &senderAddrSize);
  if (receivedBufferSize != NULL)
    *receivedBufferSize = sendBufferUsed;

  if (receivedFromAddressBuffer != NULL)
    strcpy(receivedFromAddressBuffer, inet_ntoa(receivedFromAddr.sin_addr));
  if (receivedFromPort != NULL)
    *receivedFromPort = ntohs(receivedFromAddr.sin_port);
}

// --------------------------------------------------------------------------------------------

void printInHex(const void *ptr, size_t size);

uint16_t getRandomID();
void makeHeader(struct DNSHeader *dnsHeader, uint16_t id, uint16_t isQuery, uint16_t useRecursive, uint16_t recursiveAvailable,
                uint16_t questionCount, uint16_t answerCount, uint16_t authorCount, uint16_t additionalCount);
void makeQuery(struct DNSQuery *dnsQuery, const char *domainName, const uint16_t queryType, const uint16_t queryClass,
               char *encodedDomainNameBuffer, const int encodedDomainNameBufferSize);
void makeResourceRecord(struct DNSRR *dnsRR, const char *domainName, const char *resourceData, const uint16_t queryType,
                        const uint16_t queryClass, const uint32_t ttl, char *encodedDomainNameBuffer,
                        const int encodedDomainNameBufferSize, char *encodedResourceDataBuffer,
                        const int encodedResourceDataBufferSize);
void makeSendBuffer(struct DNSHeader *dnsHeader, struct DNSQuery *dnsQuery, struct DNSRR *dnsRR);
void appendResourceRecord(struct DNSRR *dnsRR);

uint16_t encodeDomainName(const char *domainName, char *buffer, const int bufferSize);
uint16_t encodeIP(const char *ip, char *buffer, const int bufferSize);
uint32_t decodeTTL(const char *buffer);
uint16_t decodeClass(const char *buffer);
char *decodeDomainName(char *ptr, char *buffer, const int bufferSize);
char *decodeIP(char *ptr, uint16_t resourceDataLength, char *buffer, const int bufferSize);

int parseDNSHeader(struct DNSHeader *dnsHeader);
int parseDNSQuery(struct DNSQuery *dnsQuery, char *domainNameBuffer, const int domainNameBufferSize);
int parseDNSRR(struct DNSRR *dnsRR, const int pointerOffset, char *domainNameBuffer, const int domainNameBufferSize,
               char *resourceDataBuffer, const int resourceDataBufferSize);
void checkFileExistance(const char *fileName);
int readLine(const char *fileName, char *lineBuffer, const int lineBufferSize, const int lineNum);
void parseResourceRecord(const char *lineBuffer, const int resourceRecordType, char *rrBuffer, const int rrBufferSize);

int domainContains(const char *rrOwner, const char *domainNameQueried);
int domainMatches(const char *rrOwner, const char *domainNameQueried);

unsigned int seedUsed = 0;

// local function: constructs the ID field inside a DNS header with a random number
uint16_t getRandomID() {
  srand(seedUsed++);

  uint16_t id = 0;
  int i;
  for (i = 0; i < 16; ++i) {
    int r = rand() % 2;
    id |= (r << i);
  }

  return id;
}

// local function: constructs the TAG field inside a DNS header, recursiveAvailable bit will only be turned on if the packet is a
// response
uint16_t makeTag(uint16_t isQuery, uint16_t useRecusive, uint16_t recursiveAvailable) {
  uint16_t tag = 0;
  if (useRecusive)
    tag |= (1 << 8); // set recursion desired bit

  // if the header is a request
  if (!isQuery) {
    tag |= (1 << 15); // set bit to response
    if (recursiveAvailable)
      tag |= (1 << 7); // set recursion available bit
  }
  return tag;
}

// constructs a DNS header
void makeHeader(struct DNSHeader *dnsHeader, uint16_t id, uint16_t isQuery, uint16_t useRecursive, uint16_t recursiveAvailable,
                uint16_t questionCount, uint16_t answerCount, uint16_t authorCount, uint16_t additionalCount) {
  dnsHeader->id              = htons(id);
  dnsHeader->tag             = htons(makeTag(isQuery, useRecursive, recursiveAvailable));
  dnsHeader->questionCount   = htons(questionCount);
  dnsHeader->answerCount     = htons(answerCount);
  dnsHeader->authorCount     = htons(authorCount);
  dnsHeader->additionalCount = htons(additionalCount);
}

// constructs a DNS query
void makeQuery(struct DNSQuery *dnsQuery, const char *domainName, const uint16_t queryType, const uint16_t queryClass,
               char *encodedDomainNameBuffer, const int encodedDomainNameBufferSize) {
  dnsQuery->domainName =
      encodedDomainNameBuffer; // this pointer is fixed, and is only a refenence for sending, no need to change bype order
  dnsQuery->qtype  = htons(queryType);
  dnsQuery->qclass = htons(queryClass); // this is also fixed - IN is for internet

  encodeDomainName(domainName, encodedDomainNameBuffer, encodedDomainNameBufferSize);
}

void makeResourceRecord(struct DNSRR *dnsRR, const char *domainName, const char *resourceData, const uint16_t queryType,
                        const uint16_t queryClass, const uint32_t ttl, char *encodedDomainNameBuffer,
                        const int encodedDomainNameBufferSize, char *encodedResourceDataBuffer,
                        const int encodedResourceDataBufferSize) {
  dnsRR->domainName   = encodedDomainNameBuffer;
  dnsRR->resourceData = encodedResourceDataBuffer;
  dnsRR->qtype        = htons(queryType);
  dnsRR->qclass       = htons(queryClass);
  dnsRR->ttl          = htonl(ttl); // uint32_t, same as long
  if (queryType == QUERY_TYPE_A) {
    dnsRR->resourceDataLength = htons(encodeIP(resourceData, encodedResourceDataBuffer, encodedResourceDataBufferSize));
  }
  // cases when the bitcode represents encoded domain name
  else if (queryType == QUERY_TYPE_CNAME || queryType == QUERY_TYPE_MX) {
    uint16_t resourceDataLength = encodeDomainName(resourceData, encodedResourceDataBuffer, encodedResourceDataBufferSize);
    dnsRR->resourceDataLength   = htons(resourceDataLength);
  } else {
    printf("Error: unsupported RR type\n");
  }
  encodeDomainName(domainName, encodedDomainNameBuffer, encodedDomainNameBufferSize);
}

const char spacingBuffer = 0;

// construct the sendBuffer, dnsRR can be leaved as NULL, and be appended later by calling appendResourceRecord()
void makeSendBuffer(struct DNSHeader *dnsHeader, struct DNSQuery *dnsQuery, struct DNSRR *dnsRR) {
  memset(sendBuffer, 0, SEND_BUFFER_SIZE);

  char *ptr = sendBuffer;

  memcpy(ptr, dnsHeader, sizeof(*dnsHeader));
  ptr += sizeof(*dnsHeader);

  //////////////////////////////////////

  memcpy(ptr, dnsQuery->domainName, sizeof(char) * strlen(dnsQuery->domainName));
  ptr += sizeof(char) * strlen(dnsQuery->domainName);

  // inplement a space here
  memcpy(ptr, &spacingBuffer, 1);
  ptr++;

  memcpy(ptr, &dnsQuery->qtype, sizeof(dnsQuery->qtype));
  ptr += sizeof(dnsQuery->qtype);

  memcpy(ptr, &dnsQuery->qclass, sizeof(dnsQuery->qclass));
  ptr += sizeof(dnsQuery->qclass);

  if (!dnsRR) {
    sendBufferUsed = ptr - sendBuffer;
    return;
  }

  //////////////////////////////////////

  memcpy(ptr, dnsRR->domainName, sizeof(char) * strlen(dnsRR->domainName));
  ptr += sizeof(char) * strlen(dnsRR->domainName);

  // inplement a space here
  memcpy(ptr, &spacingBuffer, 1);
  ptr++;

  memcpy(ptr, &dnsRR->qtype, sizeof(dnsRR->qtype));
  ptr += sizeof(dnsRR->qtype);

  memcpy(ptr, &dnsRR->qclass, sizeof(dnsRR->qclass));
  ptr += sizeof(dnsRR->qclass);

  memcpy(ptr, &dnsRR->ttl, sizeof(dnsRR->ttl));
  ptr += sizeof(dnsRR->ttl);

  memcpy(ptr, &dnsRR->resourceDataLength, sizeof(dnsRR->resourceDataLength));
  ptr += sizeof(dnsRR->resourceDataLength);

  memcpy(ptr, dnsRR->resourceData, ntohs(dnsRR->resourceDataLength)); // revert the bits again
  ptr += ntohs(dnsRR->resourceDataLength);

  sendBufferUsed = ptr - sendBuffer;
}

void appendResourceRecord(struct DNSRR *dnsRR) {
  char *ptr = sendBuffer + sendBufferUsed;

  memcpy(ptr, dnsRR->domainName, sizeof(char) * strlen(dnsRR->domainName));
  ptr += sizeof(char) * strlen(dnsRR->domainName);

  // inplement a space here
  memcpy(ptr, &spacingBuffer, 1);
  ptr++;

  memcpy(ptr, &dnsRR->qtype, sizeof(dnsRR->qtype));
  ptr += sizeof(dnsRR->qtype);

  memcpy(ptr, &dnsRR->qclass, sizeof(dnsRR->qclass));
  ptr += sizeof(dnsRR->qclass);

  memcpy(ptr, &dnsRR->ttl, sizeof(dnsRR->ttl));
  ptr += sizeof(dnsRR->ttl);

  memcpy(ptr, &dnsRR->resourceDataLength, sizeof(dnsRR->resourceDataLength));
  ptr += sizeof(dnsRR->resourceDataLength);

  memcpy(ptr, dnsRR->resourceData, ntohs(dnsRR->resourceDataLength)); // revert the bits again
  ptr += ntohs(dnsRR->resourceDataLength);

  sendBufferUsed = ptr - sendBuffer;
}

void printInHex(const void *ptr, size_t size) {
  unsigned char *head = (unsigned char *)ptr;

  int i = 0;
  while (size--) {
    printf("%02x", head[i++]);
    printf(" ");
  }
  printf("\n");
}

// format domain name into sending byte format, into global buffer
// returns: encoded length
uint16_t encodeDomainName(const char *domainName, char *buffer, const int bufferSize) {
  char subDomainNameBuffer[50];
  memset(subDomainNameBuffer, '\0', sizeof(subDomainNameBuffer));
  memset(buffer, '\0', bufferSize);

  uint16_t subDomainCursorPos    = 0;
  uint16_t subDomainCursorMaxPos = 0;
  uint16_t bufferCursorPos       = 0;

  int i;
  for (i = 0; i < strlen(domainName); ++i) {
    char c = domainName[i];
    // fillin current section
    if (c != '.') {
      subDomainNameBuffer[subDomainCursorPos++] = c;
    }
    // dump current section
    else {
      subDomainCursorMaxPos     = subDomainCursorPos;
      subDomainCursorPos        = 0;
      buffer[bufferCursorPos++] = subDomainCursorMaxPos;

      int j;
      for (j = 0; j < subDomainCursorMaxPos; ++j) {
        buffer[bufferCursorPos++] = subDomainNameBuffer[subDomainCursorPos++];
      }
      subDomainCursorPos = 0;
    }
  }
  // dump the last section
  subDomainCursorMaxPos     = subDomainCursorPos;
  subDomainCursorPos        = 0;
  buffer[bufferCursorPos++] = subDomainCursorMaxPos;

  int j;
  for (j = 0; j < subDomainCursorMaxPos; ++j) {
    buffer[bufferCursorPos++] = subDomainNameBuffer[subDomainCursorPos++];
  }
  return bufferCursorPos;
}

// returns the actual size of encoded data
uint16_t encodeIP(const char *ip, char *buffer, const int bufferSize) {
  char tmpBuffer[100];
  const char *pIp  = ip - 1;
  char *pTmpBuffer = tmpBuffer;
  char *pBuffer    = buffer;
  memset(tmpBuffer, 0, sizeof(tmpBuffer));
  memset(buffer, 0, bufferSize);

  while (*(++pIp)) {
    if (*pIp == '.') {
      *(pBuffer++) = (uint8_t)atoi(tmpBuffer);
      memset(tmpBuffer, 0, sizeof(tmpBuffer));
      pTmpBuffer = tmpBuffer;
    } else {
      *(pTmpBuffer++) = *pIp;
    }
  }
  *(pBuffer++) = (uint8_t)atoi(tmpBuffer);

  return pBuffer - buffer;
}

int parseDNSHeader(struct DNSHeader *dnsHeader) {
  dnsHeader->id              = 0;
  dnsHeader->tag             = 0;
  dnsHeader->questionCount   = 0;
  dnsHeader->answerCount     = 0;
  dnsHeader->authorCount     = 0;
  dnsHeader->additionalCount = 0;

  char *ptr = sendBuffer;

  dnsHeader->id |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsHeader->id |= ((uint16_t) * (ptr++) & 0x00ff);

  dnsHeader->tag |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsHeader->tag |= ((uint16_t) * (ptr++) & 0x00ff);

  dnsHeader->questionCount |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsHeader->questionCount |= ((uint16_t) * (ptr++) & 0x00ff);

  dnsHeader->answerCount |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsHeader->answerCount |= ((uint16_t) * (ptr++) & 0x00ff);

  dnsHeader->authorCount |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsHeader->authorCount |= ((uint16_t) * (ptr++) & 0x00ff);

  dnsHeader->additionalCount |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsHeader->additionalCount |= ((uint16_t) * (ptr++) & 0x00ff);

  return ptr - sendBuffer;
}

int parseDNSQuery(struct DNSQuery *dnsQuery, char *domainNameBuffer, const int domainNameBufferSize) {
  dnsQuery->domainName = domainNameBuffer;
  dnsQuery->qtype      = 0;
  dnsQuery->qclass     = 0;

  memset(domainNameBuffer, 0, domainNameBufferSize);

  const int domainNameOffsetFromBuffer = 0x0c; // this is fixed, we don't need to specify the offset
  char *ptr                            = sendBuffer + domainNameOffsetFromBuffer - 1;
  int cursorPos                        = 0;
  uint8_t subdomainLength              = 0;
  // decode domain name into readable format, and store it into domainNameBuffer
  while (*(++ptr)) {
    if (subdomainLength == 0) {
      // add dot to domainNameBuffer if it's not the first subdomain
      if (cursorPos) {
        domainNameBuffer[cursorPos++] = '.';
      }
      subdomainLength = *ptr;
      continue;
    }
    subdomainLength--;
    domainNameBuffer[cursorPos++] = *ptr;
  }
  // domain name should ends with a dot
  domainNameBuffer[cursorPos++] = '.';

  ++ptr;

  dnsQuery->qtype |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsQuery->qtype |= ((uint16_t) * (ptr++) & 0x00ff);

  dnsQuery->qclass |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsQuery->qclass |= ((uint16_t) * (ptr++) & 0x00ff);

  return ptr - sendBuffer;
}

// starting from ptr, decode domain name into readable format, and store it into buffer, returns the next position of ptr
char *decodeDomainName(char *ptr, char *buffer, const int bufferSize) {
  memset(buffer, 0, bufferSize);

  int cursorPos = 0;
  uint8_t len   = 0;

  while (*(++ptr)) {
    if (len == 0) {
      // add dot to domainNameBuffer if it's not the first subdomain
      if (cursorPos) {
        buffer[cursorPos++] = '.';
      }
      len = *ptr;
      continue;
    }
    len--;
    buffer[cursorPos++] = *ptr;
  }
  // domain name should ends with a dot
  buffer[cursorPos++] = '.';

  return ++ptr;
}

// TODO: check if the following replacement is correct

/* reverse:  reverse string s in place */
void reverse(char s[]) {
  int i, j;
  char c;

  for (i = 0, j = strlen(s) - 1; i < j; i++, j--) {
    c    = s[i];
    s[i] = s[j];
    s[j] = c;
  }
}

/* itoa:  convert n to characters in s */
void itoa(int n, char s[]) {
  int i, sign;

  if ((sign = n) < 0) /* record sign */
    n = -n;           /* make n positive */
  i = 0;
  do {                     /* generate digits in reverse order */
    s[i++] = n % 10 + '0'; /* get next digit */
  } while ((n /= 10) > 0); /* delete it */
  if (sign < 0)
    s[i++] = '-';
  s[i] = '\0';
  reverse(s);
}

// starting from ptr, decode IP address into readable format, and store it into buffer, returns the next position of ptr
// indecate the length of IP address (in bits) in resourceDataLength
char *decodeIP(char *ptr, uint16_t resourceDataLength, char *buffer, const int bufferSize) {
  memset(buffer, 0, bufferSize);

  char tmp[10];
  memset(tmp, 0, sizeof(tmp));
  char *p = buffer;
  uint16_t i;
  for (i = 0; i < resourceDataLength; ++i) {
    // itoa((int)*(ptr++) & 0x000000ff, tmp, 10);
    itoa((int)*(ptr++) & 0x000000ff, tmp);
    int s = strlen(tmp);
    strcpy(p, tmp);
    p += s;
    *(p++) = '.';
  }
  *(--p) = '\0';

  return ptr;
}

uint32_t decodeTTL(const char *buffer) { return (uint32_t)atoi(buffer); }

uint16_t decodeClass(const char *buffer) {
  if (!strcmp(buffer, "IN"))
    return QUERY_CLASS_IN;
  printf("Error: Unknown class: %s\n", buffer);
  return 0;
}

int parseDNSRR(struct DNSRR *dnsRR, const int pointerOffset, char *domainNameBuffer, const int domainNameBufferSize,
               char *resourceDataBuffer, const int resourceDataBufferSize) {
  dnsRR->domainName         = domainNameBuffer;
  dnsRR->qtype              = 0;
  dnsRR->qclass             = 0;
  dnsRR->ttl                = 0;
  dnsRR->resourceDataLength = 0;
  dnsRR->resourceData       = resourceDataBuffer;
  memset(domainNameBuffer, 0, domainNameBufferSize);
  memset(resourceDataBuffer, 0, resourceDataBufferSize);

  char *ptr = sendBuffer + pointerOffset - 1; // this offset is not fixed, we need to pass it in parameter list

  ptr = decodeDomainName(ptr, domainNameBuffer, domainNameBufferSize);

  dnsRR->qtype |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsRR->qtype |= ((uint16_t) * (ptr++) & 0x00ff);
  dnsRR->qclass |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsRR->qclass |= ((uint16_t) * (ptr++) & 0x00ff);
  dnsRR->ttl |= ((uint32_t) * (ptr++) & 0x000000ff) << 24;
  dnsRR->ttl |= ((uint32_t) * (ptr++) & 0x000000ff) << 16;
  dnsRR->ttl |= ((uint32_t) * (ptr++) & 0x000000ff) << 8;
  dnsRR->ttl |= ((uint32_t) * (ptr++) & 0x000000ff);
  dnsRR->resourceDataLength |= ((uint16_t) * (ptr++) & 0x00ff) << 8;
  dnsRR->resourceDataLength |= ((uint16_t) * (ptr++) & 0x00ff);

  if (dnsRR->qtype == QUERY_TYPE_A) {
    ptr = decodeIP(ptr, dnsRR->resourceDataLength, resourceDataBuffer, resourceDataBufferSize);
  }

  // cases when the bitcode represents encoded domain name
  else if (dnsRR->qtype == QUERY_TYPE_CNAME || dnsRR->qtype == QUERY_TYPE_MX) {
    int cursorPos           = 0;
    uint8_t subdomainLength = 0;
    --ptr;

    ptr = decodeDomainName(ptr, resourceDataBuffer, resourceDataBufferSize);
  } else {
    printf("Unsupported resource parsing for such query type!\n");
    printf("query type: %d\n", dnsRR->qtype);
  }
  return ptr - sendBuffer;
}

void checkFileExistance(const char *fileName) {
  char lineBufferTmp[100];
  // check if file exists
  if (readLine(fileName, lineBufferTmp, sizeof(lineBufferTmp), 0) == -1) {
    printf("Error: File %s not found!\n", fileName);
    return;
  }
}

// returns -1 if file not found,returns 0 if line content is empty (maybe out of range)
int readLine(const char *fileName, char *lineBuffer, const int lineBufferSize, const int lineNum) {
  char pathToFile[100];
  memset(lineBuffer, 0, lineBufferSize);
  memset(pathToFile, 0, sizeof(pathToFile));

  FILE *fp;
  strcpy(pathToFile, PATH_OF_RR);
  strcat(pathToFile, fileName);

  fp = fopen(pathToFile, "r");

  // indecates the filePath is invalid
  if (!fp)
    return -1;

  int lineCount     = 0;
  int lineCursorPos = 0;

  // Extract characters from file and store in character c
  char c;
  for (c = getc(fp); c != EOF; c = getc(fp)) {
    if (c == '\n') {
      lineCount++;
      if (lineCount > lineNum)
        break;
    }

    else if (lineCount == lineNum) {
      // avoid carrage return
      if (c == '\r')
        continue;
      lineBuffer[lineCursorPos++] = c;
    }
  }

  // places unfilled specifically are just null terminators
  fclose(fp);
  return lineCursorPos != 0;
}

void parseResourceRecord(const char *lineBuffer, const int resourceRecordType, char *rrBuffer, const int rrBufferSize) {
  const char *ptr = lineBuffer - 1;
  int cursorPos   = 0;
  int rrType      = 0;

  memset(rrBuffer, 0, rrBufferSize);

  while (*(++ptr)) {
    if (*ptr == ' ')
      rrType++;

    else if (rrType == resourceRecordType) {
      rrBuffer[cursorPos++] = *ptr;
    }
  }
}

// neither string should be empty! both domain names are allowd to be ended with dot
int domainContains(const char *rrOwner, const char *domainNameQueried) {
  const char *p1 = rrOwner;
  const char *p2 = domainNameQueried;

  while (*p1) {
    p1++;
  }
  p1--;
  if (*p1 == '.')
    p1--;

  // when rrOwner == ".", it matches all
  if (p1 < rrOwner) {
    return 1;
  }

  while (*p2) {
    p2++;
  }
  p2--;
  if (*p2 == '.')
    p2--;

  // now p1 and p2 marks the end char of each buffer
  while (p1 != rrOwner - 1) {
    if (*p1 != *p2) {
      return 0;
    }
    p1--;
    p2--;
  }
  return 1;
}

int domainMatches(const char *rrOwner, const char *domainNameQueried) {
  const char *p1 = rrOwner;
  const char *p2 = domainNameQueried;

  while (*p1) {
    p1++;
  }
  p1--;
  if (*p1 == '.') {
    p1--;
  }

  while (*p2) {
    p2++;
  }
  p2--;
  if (*p2 == '.') {
    p2--;
  }

  // now p1 and p2 marks the end char of each buffer
  while (p1 != rrOwner - 1) {
    if (*p1 != *p2) {
      return 0;
    }
    p1--;
    p2--;
  }
  // two domain names are of different lengths
  if (p2 != domainNameQueried - 1) {
    return 0;
  }
  return 1;
}
