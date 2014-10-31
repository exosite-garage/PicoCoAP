#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include "../../src/coap.h"
 
void hex_dump(uint8_t* bytes, size_t len);
void coap_pretty_print(coap_pdu*);

int main(void)
{
  char alias[] = "temp";
  char cik[] = "a32c85ba9dda45823be416246cf8b433baa068d7";

  char host[] = "coap.exosite.com";
  char port[] = "5683";

  srand(time(NULL));

  // CoAP Message Setup
  #define MSG_BUF_LEN 64
  uint8_t msg_send_buf[MSG_BUF_LEN];
  coap_pdu msg_send = {msg_send_buf, 0, 64};
  uint8_t msg_recv_buf[MSG_BUF_LEN];
  coap_pdu msg_recv = {msg_recv_buf, 0, 64};

  uint16_t message_id_counter = rand();

  // Socket to Exosite
  int localsock, remotesock;
  size_t bytes_sent;
  ssize_t bytes_recv;
  int rv;

  struct addrinfo exohints, *servinfo, *p, *q;

  memset(&exohints, 0, sizeof exohints);
  exohints.ai_family = AF_UNSPEC;
  exohints.ai_socktype = SOCK_DGRAM;
  exohints.ai_flags = AI_PASSIVE;

  if ((rv = getaddrinfo(NULL, port, &exohints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }

  // loop through all the results and make a socket
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((localsock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("bad socket");
      continue;
    }

    if (bind(localsock, p->ai_addr, p->ai_addrlen) == -1) {
      close(localsock);
      perror("bad bind");
      continue;
    }

    break;
  }

  if (p == NULL) {
      fprintf(stderr, "Failed to Bind Socket\n");
      return 2;
  }

  if ((rv = getaddrinfo(host, port, &exohints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }


  // loop through all the results and make a socket
  for(q = servinfo; q != NULL; q = q->ai_next) {
    if ((remotesock = socket(q->ai_family, q->ai_socktype, q->ai_protocol)) == -1) {
      perror("bad socket");
      continue;
    }

    break;
  }

  if (q == NULL) {
      fprintf(stderr, "Failed to Bind Socket\n");
      return 2;
  }
 
  for (;;) 
  {
    printf("--------------------------------------------------------------------------------\n");

    // Build Message
    coap_init_pdu(&msg_send);
    //memset(msg_send, 0, msg_send_len);
    coap_set_version(&msg_send, COAP_V1);
    coap_set_type(&msg_send, CT_CON);
    coap_set_code(&msg_send, CC_GET); // or POST to write
    coap_set_mid(&msg_send, message_id_counter++);
    coap_set_token(&msg_send, rand(), 2);
    coap_add_option(&msg_send, CON_URI_PATH, (uint8_t*)"1a", 2);
    coap_add_option(&msg_send, CON_URI_PATH, (uint8_t*)alias, strlen(alias));
    coap_add_option(&msg_send, CON_URI_QUERY, (uint8_t*)cik, strlen(cik));
    // to write, set payload:
    //coap_set_payload(msg_send, &msg_send_len, MSG_BUF_LEN, (uint8_t*)"99", 2);

    // Send Message
    if ((bytes_sent = sendto(remotesock, msg_send.buf, msg_send.len, 0, q->ai_addr, q->ai_addrlen)) == -1){
      fprintf(stderr, "Failed to Send Message\n");
      return 2;
    }

    printf("Sent.\n");
    coap_pretty_print(&msg_send);

    // Wait for Response
    bytes_recv = recvfrom(remotesock, (void *)msg_recv.buf, sizeof(msg_recv.buf), 0, q->ai_addr, &q->ai_addrlen);
    if (bytes_recv < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }

    msg_recv.len = bytes_recv;

    if(coap_validate_pkt(&msg_recv) == CE_NONE)
    {
      printf("Got Valid CoAP Packet\n");
      if(coap_get_mid(&msg_recv) == coap_get_mid(&msg_send) &&
         coap_get_token(&msg_recv) == coap_get_token(&msg_send))
      {
        printf("Is Response to Last Message\n");
        coap_pretty_print(&msg_recv);
      }
    }else{
      printf("Received %zi Bytes, Not Valid CoAP\n", msg_recv.len);
      hex_dump(msg_recv.buf, msg_recv.len);
    }

    sleep(1); // One Second
  }
}

void hex_dump(uint8_t* bytes, size_t len)
{
  size_t i, j;
  for (i = 0; i < len; i+=16){
    printf("  0x%.3zx    ", i);
    for (j = 0; j < 16; j++){
      if (i+j < len)
        printf("%02hhx ", bytes[i+j]);
      else
        printf("%s ", "--");
    }
    printf("   %.*s\n", (int)(16 > len-i ? len-i : 16), bytes+i);
  }
}

void coap_pretty_print(coap_pdu *pdu)
{
  coap_option opt;

  opt.num = 0;

  if (coap_validate_pkt(pdu) == CE_NONE){
      printf(" ------ Valid CoAP Packet (%zi) ------ \n", pdu->len);
      printf("Type:  %i\n",coap_get_type(pdu));
      printf("Code:  %i.%02i\n", coap_get_code_class(pdu), coap_get_code_detail(pdu));
      printf("MID:   0x%X\n", coap_get_mid(pdu));
      printf("Token: 0x%llX\n", coap_get_token(pdu));

      while ((opt = coap_get_option(pdu, &opt)).num != 0){
        if (opt.num == 0)
          break;

        printf("Option: %i\n", opt.num);
        if (opt.val != NULL && opt.len != 0)
          printf(" Value: %.*s (%zi)\n", (int)opt.len, opt.val, opt.len);
      }
      // Note: get_option returns payload pointer when it finds the payload marker
      if (opt.val != NULL && opt.len != 0)
        printf("Value: %.*s (%zi)\n", (int)opt.len, opt.val, opt.len);
    } else {
      printf(" ------ Non-CoAP Message (%zi) ------ \n", pdu->len);
      hex_dump(pdu->buf, pdu->len);
    }
}
