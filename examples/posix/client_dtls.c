#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdlib.h>
#include <time.h>

#include "coap.h"
#include "dtls.h"

#define COAPS_SRV "173.255.243.158"
#define COAPS_SRV_PORT 20220

#define BUFSIZE 2048
#define MAX_DOWNLOAD_SIZE 102400 // 100k
#define MAX_RETRY 3
#define TIMEOUT 5

#define PRINTF(...) printf(__VA_ARGS__);fflush(stdout);

#define TEST_READ 0x02
#define TEST_WRITE 0x04
#define TEST_UPLOAD_FILE 0x08
#define TEST_ACTIVATE 0x10
#define TEST_DOWNLOAD_CONTENT 0x20

#define block_size 5 // Range: 1 - 6
 
void hex_dump(uint8_t* bytes, size_t len);
void coap_pretty_print(uint8_t* pkt, size_t len);

int main(void)
{
  char alias[] = "temp";
  char cik[] = "a32c85ba9dda45823be416246cf8b433baa068d7";

  char host[] = "coap.exosite.com";
  char port[] = "5683";

  srand(time(NULL));

  // CoAP Message Setup
  #define MSG_BUF_LEN 64
  uint8_t msg_send[MSG_BUF_LEN];
  size_t  msg_send_len = 0;
  uint8_t msg_recv[MSG_BUF_LEN];
  size_t  msg_recv_len = 0;

  uint16_t message_id_counter = rand();

  // Socket to Exosite
  int localsock, remotesock;
  size_t bytes_sent;
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
    msg_send_len = 0; // Clear Message Buffer
    memset(msg_send, 0, msg_send_len);
    coap_set_version(msg_send, &msg_send_len, MSG_BUF_LEN, COAP_V1);
    coap_set_type(msg_send, &msg_send_len, MSG_BUF_LEN, CT_CON);
    coap_set_code(msg_send, &msg_send_len, MSG_BUF_LEN, CC_GET); //or POST
    coap_set_mid(msg_send, &msg_send_len, MSG_BUF_LEN, message_id_counter++);
    coap_set_token(msg_send, &msg_send_len, MSG_BUF_LEN, rand(), 2);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)"1a", 2);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)alias, strlen(alias));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_QUERY, (uint8_t*)cik, strlen(cik));
    //coap_set_payload(msg_send, &msg_send_len, MSG_BUF_LEN, (uint8_t*)"99", 2);

    // Send Message
    if ((bytes_sent = sendto(remotesock, msg_send, msg_send_len, 0, q->ai_addr, q->ai_addrlen)) == -1){
      fprintf(stderr, "Failed to Send Message\n");
      return 2;
    }

    printf("Sent.\n");
    coap_pretty_print(msg_send, msg_send_len);

    // Wait for Response
    msg_recv_len = recvfrom(remotesock, (void *)msg_recv, sizeof(msg_recv), 0, q->ai_addr, &q->ai_addrlen);
    if (msg_recv_len < 0) {
      fprintf(stderr, "%s\n", strerror(errno));
      exit(EXIT_FAILURE);
    }


    if(coap_validate_pkt(msg_recv, msg_recv_len) == CS_OK)
    {
      printf("Got Valid CoAP Packet\n");
      if(coap_get_mid(msg_recv, msg_recv_len) == coap_get_mid(msg_send, msg_send_len) &&
         coap_get_token(msg_recv, msg_recv_len, 0) == coap_get_token(msg_send, msg_send_len, 0)) //this is only actually checking token length, should check token.
      {
        printf("Is Response to Last Message\n");
        coap_pretty_print(msg_recv, msg_recv_len);
      }
    }else{
      printf("Received %zi Bytes, Not Valid CoAP\n", msg_recv_len);
      hex_dump(msg_recv, msg_recv_len);
    }

    usleep(1000000); // One Second
  }
}

// TEST_READ , TEST_WRITE
static char alias[] = "temp";
static char cik[] = "a32c85ba9dda45823be416246cf8b433baa068d7";
static char value_to_write[] = "56";

// dtls setup
static size_t dtls_connected = 0;
static size_t ready_to_recv = 0;
static dtls_context_t *dtls_context = NULL;
static session_t session;

typedef struct trans_data {
    int out;
    int ack;
    uint8* data;
    int retry;
} trans_data;

struct trans_data last_sent = {.retry=0};

#define SET_SEND_TIMESTAMP() {last_sent.out = (int)time(NULL); \
                              last_sent.data = (uint8*)sent_pdu->hdr; \
                              last_sent.ack = 0; \
                              last_sent.retry++;}
#define SET_ACK_TIMESTAMP() {last_sent.ack = (int)time(NULL); last_sent.retry = 0;}

int order_opts(void *a, void *b)
{
    if (!a || !b)
        return a < b ? -1 : 1;

    if (COAP_OPTION_KEY(*(coap_option *)a) < COAP_OPTION_KEY(*(coap_option *)b))
        return -1;

    return COAP_OPTION_KEY(*(coap_option *)a) == COAP_OPTION_KEY(*(coap_option *)b);
}

coap_pdu_t* coap_new_request(coap_context_t *ctx,  unsigned char method, coap_list_t *options, str payload )
{
    coap_pdu_t *pdu;
    coap_list_t *opt;

    if ( ! ( pdu = coap_new_pdu() ) )
        return NULL;

    pdu->hdr->type = COAP_MESSAGE_CON;
    pdu->hdr->id = coap_new_message_id(ctx);
    pdu->hdr->code = method;
    pdu->hdr->token_length = the_token.length;
    if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
        debug("cannot add token to request\n");
    }
    for (opt = options; opt; opt = opt->next) {
        coap_add_option(pdu, COAP_OPTION_KEY(*(coap_option *)opt->data),
                        COAP_OPTION_LENGTH(*(coap_option *)opt->data),
                        COAP_OPTION_DATA(*(coap_option *)opt->data));
    }
    if (payload.length) {
        if (block_flag)
            coap_add_block(pdu, payload.length, payload.s, block.num, block.szx);
        else
            coap_add_data(pdu, payload.length, payload.s);
    }

    //coap_show_pdu(pdu);

    return pdu;
}

coap_list_t* new_option_node(unsigned short key, unsigned int length, unsigned char *data)
{
    coap_option *option;
    coap_list_t *node;

    option = coap_malloc(sizeof(coap_option) + length);
    if ( !option )
        goto error;

    COAP_OPTION_KEY(*option) = key;
    COAP_OPTION_LENGTH(*option) = length;
    memcpy(COAP_OPTION_DATA(*option), data, length);
    /* we can pass NULL here as delete function since option is released automatically  */
    node = coap_new_listnode(option, NULL);

    if ( node )
        return node;

error:
    perror("new_option_node: malloc");
    coap_free( option );
    return NULL;
}

coap_context_t* get_context(const char *node, const char *port)
{
    coap_context_t *ctx = NULL;
    int s;
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

    s = getaddrinfo(node, port, &hints, &result);
    if ( s != 0 ) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return NULL;
    }
    /* iterate through results until success */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        coap_address_t addr;
        if (rp->ai_addrlen <= sizeof(addr.addr)) {
            coap_address_init(&addr);
            addr.size = rp->ai_addrlen;
            memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);

            ctx = coap_new_context(&addr);
            if (ctx) {
                goto finish;
            }
        }
    }

    fprintf(stderr, "no context available for interface '%s'\n", node);

finish:
    freeaddrinfo(result);
    return ctx;
}

coap_pdu_t* get_pdu(char* url, unsigned char method, str payload)
{
    coap_pdu_t  *pdu;
    size_t buflen;
    int res;
    optlist=NULL;

    coap_split_uri((unsigned char *)url, strlen(url), &uri );
    if (uri.path.length) {
        buflen = BUFSIZE;
        unsigned char _buf[BUFSIZE];
        unsigned char *buf = _buf;
        res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);
        while (res--) {
            coap_insert(&optlist,
                        new_option_node(
                            COAP_OPTION_URI_PATH,
                            COAP_OPT_LENGTH(buf),
                            COAP_OPT_VALUE(buf)),
                        order_opts);
            buf += COAP_OPT_SIZE(buf);
        }
    }
    if (uri.query.length) {
        buflen = BUFSIZE;
        unsigned char _buf[BUFSIZE];
        unsigned char *buf = _buf;
        res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);
        while (res--) {
            coap_insert(&optlist,
                        new_option_node(
                            COAP_OPTION_URI_QUERY,
                            COAP_OPT_LENGTH(buf),
                            COAP_OPT_VALUE(buf)),
                        order_opts);
            buf += COAP_OPT_SIZE(buf);
        }
    }
    if (NULL == coap_ctx)
        coap_ctx = get_context("0.0.0.0", "0");

    if (block_flag) {
        static unsigned char tmp[4];
        unsigned short opt;
        opt = method == COAP_REQUEST_GET ? COAP_OPTION_BLOCK2 : COAP_OPTION_BLOCK1;
        char more;
        if (coap_more_blocks(payload.length, block.num, block.szx))
            more = 0x08;
        else
            more = 0x00;
        //printf(" more:%d block num:%d\n", more, block.num);
        coap_insert(&optlist,
                    new_option_node(
                        opt,
                        coap_encode_var_bytes(tmp, (block.num << 4 | block.szx | more)),
                        tmp),
                    order_opts);
    }
    if (! (pdu = coap_new_request(coap_ctx, method, optlist, payload)))
        return NULL;
    return pdu;

}

coap_pdu_t* get_pdu_activate(char* vendor, char* model, char* serial_number)
{
    char dest[BUFSIZE];
    strcpy(dest, "coap://0.0.0.0/provision/activate/"); //address is virtual
    strcat(dest, vendor);
    strcat(dest, "/");
    strcat(dest, model);
    strcat(dest, "/");
    strcat(dest, serial_number);
    str payload = { 0, NULL };
    return get_pdu(dest, COAP_REQUEST_POST, payload);


    msg_send_len = 0; // Clear Message Buffer
    memset(msg_send, 0, msg_send_len);
    coap_set_version(msg_send, &msg_send_len, MSG_BUF_LEN, COAP_V1);
    coap_set_type(msg_send, &msg_send_len, MSG_BUF_LEN, CT_CON);
    coap_set_code(msg_send, &msg_send_len, MSG_BUF_LEN, CC_POST);
    coap_set_mid(msg_send, &msg_send_len, MSG_BUF_LEN, message_id_counter++);
    coap_set_token(msg_send, &msg_send_len, MSG_BUF_LEN, rand(), 2);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)"provision", 9);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)"activate", 8);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)vendor, strlen(vendor));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)model, strlen(model));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)serial_number, strlen(serial_number));
}

coap_pdu_t* get_pdu_download_content()
{
    char dest[BUFSIZE];
    strcpy(dest, "coap://0.0.0.0/provision/download/"); //address is virtual
    strcat(dest, vendor);
    strcat(dest, "/");
    strcat(dest, model);
    strcat(dest, "/");
    strcat(dest, content_id);
    strcat(dest, "?");
    strcat(dest, client_model_cik);
    str payload = { 0, NULL };
    block_flag = 1;
    return get_pdu(dest, COAP_REQUEST_GET, payload);

    msg_send_len = 0; // Clear Message Buffer
    memset(msg_send, 0, msg_send_len);
    coap_set_version(msg_send, &msg_send_len, MSG_BUF_LEN, COAP_V1);
    coap_set_type(msg_send, &msg_send_len, MSG_BUF_LEN, CT_CON);
    coap_set_code(msg_send, &msg_send_len, MSG_BUF_LEN, CC_POST);
    coap_set_mid(msg_send, &msg_send_len, MSG_BUF_LEN, message_id_counter++);
    coap_set_token(msg_send, &msg_send_len, MSG_BUF_LEN, rand(), 2);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)"provision", 9);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)"download", 8);
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)vendor, strlen(vendor));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)model, strlen(model));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)serial_number, strlen(serial_number));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_PATH, (uint8_t*)alias, strlen(alias));
    coap_add_option(msg_send, &msg_send_len, MSG_BUF_LEN, CON_URI_QUERY, (uint8_t*)cik, strlen(cik));

    return EXO_OK;
}

coap_pdu_t* get_pdu_read1p(char* cik, char* alias)
{
    char dest[BUFSIZE];
    strcpy(dest, "coap://0.0.0.0/1a/"); //address is virtual
    strcat(dest, alias);
    strcat(dest, "?");
    strcat(dest, cik);
    str payload = { 0, NULL };
    return get_pdu(dest, COAP_REQUEST_GET, payload);
}

coap_pdu_t* get_pdu_write1p(char* cik, char* alias, char* value)
{
    char dest[BUFSIZE];
    strcpy(dest, "coap://0.0.0.0/1a/"); //address is virtual
    strcat(dest, alias);
    strcat(dest, "?");
    strcat(dest, cik);
    str payload = { strlen(value), (unsigned char*)value };
    return get_pdu(dest, COAP_REQUEST_POST, payload);
}

coap_pdu_t* get_pdu_block_upload(char* cik, char* alias, int length, unsigned char* data)
{
    char dest[BUFSIZE];
    strcpy(dest, "coap://0.0.0.0/1a/"); //address is virtual
    strcat(dest, alias);
    strcat(dest, "?");
    strcat(dest, cik);
    str payload = { length, data };
    block_flag = 1;
    return get_pdu(dest, COAP_REQUEST_PUT, payload);
}

static inline coap_opt_t * get_block(coap_pdu_t *pdu, coap_opt_iterator_t *opt_iter)
{
    coap_opt_filter_t f;

    assert(pdu);
    memset(f, 0, sizeof(coap_opt_filter_t));
    coap_option_setb(f, COAP_OPTION_BLOCK1);
    coap_option_setb(f, COAP_OPTION_BLOCK2);

    coap_option_iterator_init(pdu, opt_iter, f);
    return coap_option_next(opt_iter);
}

inline int check_token(coap_pdu_t *received)
{
    return received->hdr->token_length == the_token.length &&
           memcmp(received->hdr->token, the_token.s, the_token.length) == 0;
}

void message_handler(coap_pdu_t *received)
{
    size_t len;
    unsigned char *databuf = NULL;
    coap_opt_t *block_opt;
    coap_opt_iterator_t opt_iter;

    PRINTF("Receive %d.%02d response.\n\n",
           (received->hdr->code >> 5), received->hdr->code & 0x1F);
    /* check if this is a response to our original request */
    if (!check_token(received)) {
        return;
    }

    coap_get_data(received, &len, &databuf);
    block_opt = get_block(received, &opt_iter);
    coap_check_option(received, COAP_OPTION_SUBSCRIPTION, &opt_iter);

    if ( received->hdr->code == COAP_RESPONSE_CODE(205) ) {
        if (block_opt) {  // block option
            download_size +=  len;
            if (COAP_OPT_BLOCK_MORE(block_opt)) { // has more
                PRINTF("found the M bit, block size is %u, block nr. %u\n",
                       COAP_OPT_BLOCK_SZX(block_opt), coap_opt_block_num(block_opt));
                strcat(download_content, (char*)databuf);
                SET_ACK_TIMESTAMP();
                block.num += 1;
                sent_pdu = get_pdu_download_content(vendor, model, content_id);
                dtls_write(dtls_context, &session, (uint8*)sent_pdu->hdr, sent_pdu->length);
                SET_SEND_TIMESTAMP();
            } else {
                strcat(download_content, (char*)databuf);
                FILE *fp;
                fp=fopen(download_save_file, "wb");
                fwrite(download_content, 1, download_size, fp);
                fclose(fp);
                PRINTF("Downloaded content is saved to file '%s'.\n", download_save_file);
                ready_to_recv = 0;
            }
        } else {   // no block option
            if (databuf)
                PRINTF("payload: '%s'\n", databuf);
            ready_to_recv = 0;
            return;
        }
    } else if ( received->hdr->code == COAP_RESPONSE_CODE(204)) {
        if (databuf)
            PRINTF("payload: '%s'\n", databuf);
        ready_to_recv = 0;
    } else {                   //  other than 2.05, 2.04//
        if (block_opt && received->hdr->code == COAP_RESPONSE_CODE(231)) { // block option
            if (COAP_OPT_BLOCK_MORE(block_opt)) { // has more
                PRINTF("found the M bit, block size is %u, block nr. %u\n",
                       COAP_OPT_BLOCK_SZX(block_opt), coap_opt_block_num(block_opt));
                SET_ACK_TIMESTAMP();
                block.num += 1;
                sent_pdu = get_pdu_block_upload(cik, alias, file_size, file_data);
                dtls_write(dtls_context, &session, (uint8*)sent_pdu->hdr, sent_pdu->length);
                SET_SEND_TIMESTAMP();
            }
        } else { //not block option
            if (databuf)
                PRINTF("payload: '%s'\n", databuf);
            ready_to_recv = 0;
        }
    }
}

/* This function is the "key store" for tinyDTLS. It is called to
 * retrieve a key for the given identiy within this particular
 * session. */
int get_key(struct dtls_context_t *ctx,
            const session_t *session,
            const unsigned char *id, size_t id_len,
            const dtls_key_t **result)
{
    static const dtls_key_t psk = {
        .type = DTLS_KEY_PSK,
        .key.psk.id = (unsigned char *)"Client_identity",
        .key.psk.id_length = 15,
        .key.psk.key = (unsigned char *)"ex0CoAPs",
        .key.psk.key_length = 9
    };
    *result = &psk;
    return 0;
}

int handle_event(struct dtls_context_t *ctx, session_t *session,
                 dtls_alert_level_t level, unsigned short code)
{
    if  (code == DTLS_EVENT_CONNECTED)
        dtls_connected = 1;
    return 0;
}

int read_from_server(struct dtls_context_t *ctx,
                     session_t *session, uint8 *data, size_t len)
{
    //printf ("Server message:\n");
    //size_t i;
    //for (i = 0; i < len; i++)
    //    printf("%02x ", data[i]);
    //printf("\n");
    coap_pdu_t* received_pdu = coap_new_pdu();
    if (coap_pdu_parse(data, len, received_pdu)) {
        message_handler(received_pdu);
    } else
        PRINTF("Invalid CoAP message!");

    return 0;
}

int send_to_peer(struct dtls_context_t *ctx,
                 session_t *session, uint8 *data, size_t len)
{
    int fd = *(int *)dtls_get_app_data(ctx);
    return sendto(fd, data, len, MSG_DONTWAIT,
                  &session->addr.sa, session->size);
}

int dtls_handle_read(struct dtls_context_t *ctx)
{
    int fd;
    session_t session;
    static uint8 buf[BUFSIZE];
    int len;

    fd = *(int *)dtls_get_app_data(ctx);

    if (!fd)
        return -1;

    memset(&session, 0, sizeof(session_t));
    session.size = sizeof(session.addr);
    len = recvfrom(fd, buf, BUFSIZE, 0,
                   &session.addr.sa, &session.size);
    if (len < 0) {
        perror("recvfrom");
        return -1;
    } else {
    }
    return dtls_handle_message(ctx, &session, buf, len);
}

int resolve_address(const char *server, struct sockaddr *dst)
{
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    static char addrstr[256];
    int error;

    memset(addrstr, 0, sizeof(addrstr));
    if (server && strlen(server) > 0)
        memcpy(addrstr, server, strlen(server));
    else
        memcpy(addrstr, "localhost", 9);

    memset ((char *)&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    error = getaddrinfo(addrstr, "", &hints, &res);

    if (error != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
        return error;
    }
    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {

        switch (ainfo->ai_family) {
        case AF_INET6:
        case AF_INET:
            memcpy(dst, ainfo->ai_addr, ainfo->ai_addrlen);
            return ainfo->ai_addrlen;
        default:
            ;
        }
    }
    freeaddrinfo(res);
    return -1;
}

/*---------------------------------------------------------------------------*/

static dtls_handler_t cb = {
    .write = send_to_peer,
    .read  = read_from_server,
    .event = handle_event,
    .get_key = get_key
};
void get_file_content(char* file_name, unsigned int* size, unsigned char** content)
{
    FILE *fh = fopen(file_name, "rw");
    if ( fh == NULL ) {
        perror(file_name);
        return;
    }
    fseek(fh, 0, SEEK_END);
    *size = ftell(fh);
    rewind(fh);
    *content = NULL;
    *content = (unsigned char*)malloc(*size);
    if ( *size != fread(*content, *size, 1, fh) )
        return;
    fclose(fh);
    return;
}

int main(int argc, char **argv)
{
    //dtls_context_t *dtls_context = NULL;
    fd_set rfds;
    struct timeval timeout;
    int sock, result;
    int on = 1;
    int res;

    dtls_init();
    memset(&session, 0, sizeof(session_t));

    /* resolve destination address where server should be sent */
    res = resolve_address(COAPS_SRV, &session.addr.sa);

    if (res < 0) {
        PRINTF("failed to resolve address\n");
        exit(-1);
    }
    session.size = res;
    session.addr.sin.sin_port = htons(COAPS_SRV_PORT);

    sock = socket(session.addr.sa.sa_family, SOCK_DGRAM, 0);
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    dtls_context = dtls_new_context(&sock);

    if (!dtls_context) {
        PRINTF("cannot create context\n");
        exit(-1);
    }

    dtls_set_handler(dtls_context, &cb);
    dtls_connect(dtls_context, &session);

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        result = select(sock+1, &rfds, 0, 0, &timeout);

        if (result < 0) {   // error
            if (errno != EINTR)
                perror("select");
        } else if (result == 0) { // timeout
            if (last_sent.out > 0 && last_sent.ack == 0) {
                if ((int)time(NULL) - last_sent.out > TIMEOUT) { // TIMEOUT
                    if (last_sent.retry <= MAX_RETRY) {
                        dtls_write(dtls_context, &session, last_sent.data, sent_pdu->length);
                        SET_SEND_TIMESTAMP();
                    } else {
                        PRINTF("Failed: reach retry limit");
                        break;
                    }
                }
            }
        } else {      // ok
            if (FD_ISSET(sock, &rfds)) {
                dtls_handle_read(dtls_context);
            }
        }
        if (dtls_connected && !ready_to_recv) {
            if (test_cases & TEST_WRITE) {
                sent_pdu = get_pdu_write1p(cik ,alias, value_to_write);
                PRINTF("Write data '%s' to '%s'..\n", value_to_write, alias);
                dtls_write(dtls_context, &session, (uint8*)sent_pdu->hdr, sent_pdu->length);
                test_cases -= TEST_WRITE;
                ready_to_recv = 1;
                continue;
            }
            if (test_cases & TEST_READ) {
                sent_pdu = get_pdu_read1p(cik ,alias);
                PRINTF("Read data from alias '%s'..\n", alias);
                dtls_write(dtls_context, &session, (uint8*)sent_pdu->hdr, sent_pdu->length);
                test_cases -= TEST_READ;
                ready_to_recv = 1;
                continue;
            }
        }
        if (!test_cases && !ready_to_recv)
            break;
    }
    dtls_free_context(dtls_context);
    exit(0);
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

void coap_pretty_print(uint8_t* pkt, size_t len)
{
  size_t i;
  uint8_t *ptr;
  int32_t opt_num, j, k;

  if(coap_validate_pkt(pkt, len) == CS_OK){
      printf(" ------ Valid CoAP Packet (%zi) ------ \n", len);
      printf("Type: %i\n",coap_get_type(pkt, len));
      printf("Code: %i.%02i\n", coap_get_code_class(pkt, len), coap_get_code_detail(pkt, len));
      j = coap_get_option_count(pkt, len);
      for(i = 0; i < j; i++){
        k = coap_get_option(pkt, len, i, &opt_num, &ptr);

        printf("Option: %i\n", opt_num);
        printf(" Value: %.*s (%i)\n", k, ptr, k);
      }
      j = coap_get_payload(pkt, len, &ptr);
      printf("Value: %.*s (%i)\n", j, ptr, j);
    }else{
      printf(" ------ Non-CoAP Message (%zi) ------ \n", len);
      hex_dump(pkt, len);
    }
}