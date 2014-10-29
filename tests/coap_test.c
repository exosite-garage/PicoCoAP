#include <stdio.h>
#include <string.h>
#include "minunit.h"
#include "../src/coap.h"

int tests_run = 0;


void coap_pretty_print(coap_pdu *pdu);
void hex_dump(char* bytes, size_t len);

static char * test_math() {
	mu_assert("[ERROR] 2+2 != 4", 2+2 == 4);
	return 0;
}

static char * test_msg_empty_con_getters() {
	uint8_t ref_bin[] = {64,0,0,0};
	coap_pdu msg_ref = {ref_bin, 4, 4};

	mu_assert("[ERROR] Empty CON failed validation.",
	          coap_validate_pkt(&msg_ref) == CE_NONE);

	mu_assert("[ERROR] Empty CON version decoded wrong.",
	          coap_get_version(&msg_ref) == COAP_V1);

	mu_assert("[ERROR] Empty CON type decoded wrong.",
	          coap_get_type(&msg_ref) == CT_CON);

	mu_assert("[ERROR] Empty CON code decoded wrong.",
	          coap_get_code(&msg_ref) == CC_EMPTY);

	mu_assert("[ERROR] Empty CON code class decoded wrong.",
	          coap_get_code_class(&msg_ref) == 0);

	mu_assert("[ERROR] Empty CON code detail decoded wrong.",
	          coap_get_code_detail(&msg_ref) == 0);

	return 0;
}

static char * test_msg_empty_con_setters() {
	uint8_t ref_bin[] = {64,0,0,0};
	uint8_t test_bin[4];
	coap_pdu msg_ref = {ref_bin, 4, 4};
	coap_pdu msg_test = {test_bin, 0, 4};

	mu_assert("[ERROR] Empty CON failed to init.",
	          coap_init_pdu(&msg_test) == CE_NONE);

	mu_assert("[ERROR] Empty CON failed to set version.",
	          coap_set_version(&msg_test, COAP_V1) >= 0);

	mu_assert("[ERROR] Empty CON failed to set type.",
	          coap_set_type(&msg_test, CT_CON) >= 0);

	mu_assert("[ERROR] Empty CON failed to set code.",
	          coap_set_code(&msg_test, CC_EMPTY) >= 0);

	mu_assert("[ERROR] Empty CON failed to set message ID.",
	          coap_set_mid(&msg_test, 0) >= 0);

	mu_assert("[ERROR] Empty CON failed to set token.",
	          coap_set_token(&msg_test, 0, 0) == CE_NONE);

	mu_assert("[ERROR] Empty CON length set wrong.",
	          msg_test.len == msg_ref.len);

	mu_assert("[ERROR] Empty CON failed to encode.",
	          memcmp(msg_test.buf, msg_ref.buf, msg_ref.len) == 0);

	return 0;
}

static char * test_msg_get_con_getters() {
	uint8_t ref_bin[] = {0x40,0x01,0x00,0x37,0xb2,0x31,0x61,0x04,0x74,0x65,
	                     0x6d,0x70,0x4d,0x1b,0x61,0x33,0x32,0x63,0x38,0x35,
	                     0x62,0x61,0x39,0x64,0x64,0x61,0x34,0x35,0x38,0x32,
	                     0x33,0x62,0x65,0x34,0x31,0x36,0x32,0x34,0x36,0x63,
	                     0x66,0x38,0x62,0x34,0x33,0x33,0x62,0x61,0x61,0x30,
	                     0x36,0x38,0x64,0x37};
	coap_pdu msg_ref = {ref_bin, 54, 54};
	coap_option option;

	mu_assert("[ERROR] GET CON failed validation.",
	          coap_validate_pkt(&msg_ref) == CE_NONE);

	mu_assert("[ERROR] GET CON version decoded wrong.",
	          coap_get_version(&msg_ref) == COAP_V1);

	mu_assert("[ERROR] GET CON type decoded wrong.",
	          coap_get_type(&msg_ref) == CT_CON);

	mu_assert("[ERROR] GET CON code decoded wrong.",
	          coap_get_code(&msg_ref) == CC_GET);

	mu_assert("[ERROR] GET CON code class decoded wrong.",
	          coap_get_code_class(&msg_ref) == 0);

	mu_assert("[ERROR] GET CON code detail decoded wrong.",
	          coap_get_code_detail(&msg_ref) == 1);

	option = coap_get_option(&msg_ref, NULL);
	mu_assert("[ERROR] GET CON option zero length was wrong.",
	          option.len == 2);
	mu_assert("[ERROR] GET CON option zero number was wrong.",
	          option.num == CON_URI_PATH);
	mu_assert("[ERROR] GET CON option zero value was wrong.",
	          memcmp(option.val, ref_bin+5, option.len) == 0);

	option = coap_get_option(&msg_ref, &option);
	mu_assert("[ERROR] GET CON option one length was wrong.",
	          option.len == 4);
	mu_assert("[ERROR] GET CON option one number was wrong.",
	          option.num == CON_URI_PATH);
	mu_assert("[ERROR] GET CON option one value was wrong.",
	          memcmp(option.val, ref_bin+8, option.len) == 0);

	option = coap_get_option(&msg_ref, &option);
	mu_assert("[ERROR] GET CON option two length was wrong.",
	          option.len == 40);
	mu_assert("[ERROR] GET CON option two number was wrong.",
	          option.num == CON_URI_QUERY);
	mu_assert("[ERROR] GET CON option two value was wrong.",
	          memcmp(option.val, ref_bin+14, option.len) == 0);

	return 0;
}

static char * test_msg_get_con_setters() {
	uint8_t ref_bin[] = {0x40,0x01,0x00,0x37,0xb2,0x31,0x61,0x04,0x74,0x65,
	                     0x6d,0x70,0x4d,0x1b,0x61,0x33,0x32,0x63,0x38,0x35,
	                     0x62,0x61,0x39,0x64,0x64,0x61,0x34,0x35,0x38,0x32,
	                     0x33,0x62,0x65,0x34,0x31,0x36,0x32,0x34,0x36,0x63,
	                     0x66,0x38,0x62,0x34,0x33,0x33,0x62,0x61,0x61,0x30,
	                     0x36,0x38,0x64,0x37};
	coap_pdu msg_ref = {ref_bin, 54, 54};

	uint8_t test_bin[54];
	coap_pdu msg_test = {test_bin, 0,54};

	mu_assert("[ERROR] Empty CON failed to init.",
	          coap_init_pdu(&msg_test) == CE_NONE);

	mu_assert("[ERROR] GET CON failed to set version.",
	          coap_set_version(&msg_test, COAP_V1) >= 0);

	mu_assert("[ERROR] GET CON failed to set type.",
	          coap_set_type(&msg_test, CT_CON) >= 0);

	mu_assert("[ERROR] GET CON failed to set code.",
	          coap_set_code(&msg_test, CC_GET) >= 0);

	mu_assert("[ERROR] GET CON failed to set message ID.",
	          coap_set_mid(&msg_test, 0x37) >= 0);

	mu_assert("[ERROR] GET CON failed to set token.",
	          coap_set_token(&msg_test, 0, 0) >= 0);

	mu_assert("[ERROR] GET CON failed to add first path option.",
	          coap_add_option(&msg_test, CON_URI_PATH, ref_bin+5, 2) == CE_NONE);

	mu_assert("[ERROR] GET CON failed to add second path option.",
	          coap_add_option(&msg_test, CON_URI_PATH, ref_bin+8, 4) == CE_NONE);

	mu_assert("[ERROR] GET CON failed to add query option.",
	          coap_add_option(&msg_test, CON_URI_QUERY, ref_bin+14, 40) == CE_NONE);

	mu_assert("[ERROR] GET CON length set wrong.",
	          msg_test.len == 54);

	mu_assert("[ERROR] GET CON failed to encode.",
	          memcmp(msg_ref.buf, msg_test.buf, 54) == 0);

	return 0;
}

static char * test_msg_get_con_setters_out_order() {
	uint8_t ref_bin[] = {0x44,0x01,0x00,0x37,0xff,0xff,0xff,0xff,0xb2,0x31,
		                 0x61,0x04,0x74,0x65,0x6d,0x70,0x4d,0x1b,0x61,0x33,
		                 0x32,0x63,0x38,0x35,0x62,0x61,0x39,0x64,0x64,0x61,
		                 0x34,0x35,0x38,0x32,0x33,0x62,0x65,0x34,0x31,0x36,
		                 0x32,0x34,0x36,0x63,0x66,0x38,0x62,0x34,0x33,0x33,
		                 0x62,0x61,0x61,0x30,0x36,0x38,0x64,0x37};
	coap_pdu msg_ref = {ref_bin, 58, 58};

	uint8_t test_bin[64];
	coap_pdu msg_test = {test_bin, 0, 64};

	//memset(test_bin, 0, 64);

	mu_assert("[ERROR] Empty CON failed to init.",
	          coap_init_pdu(&msg_test) == CE_NONE);

	mu_assert("[ERROR] GET CON failed to set version. (Out of Order)",
	          coap_set_version(&msg_test, COAP_V1) >= 0);

	mu_assert("[ERROR] GET CON failed to set type. (Out of Order)",
	          coap_set_type(&msg_test, CT_CON) >= 0);

	mu_assert("[ERROR] GET CON failed to set code. (Out of Order)",
	          coap_set_code(&msg_test, CC_GET) >= 0);

	mu_assert("[ERROR] GET CON failed to set message ID. (Out of Order)",
	          coap_set_mid(&msg_test, 0x37) >= 0);

	mu_assert("[ERROR] GET CON failed to set token. (Out of Order)",
	          coap_set_token(&msg_test, 0xFFFFFFFF, 4) >= 0);

	mu_assert("[ERROR] GET CON failed to add first path option. (Out of Order)",
	          coap_add_option(&msg_test, CON_URI_PATH, ref_bin+9, 2) == CE_NONE);

	mu_assert("[ERROR] GET CON failed to add second path option. (Out of Order)",
	          coap_add_option(&msg_test, CON_URI_PATH, ref_bin+12, 4) == CE_NONE);

	mu_assert("[ERROR] GET CON failed to add query option. (Out of Order)",
	          coap_add_option(&msg_test, CON_URI_QUERY, ref_bin+18, 40) == CE_NONE);

	mu_assert("[ERROR] GET CON length set wrong. (Out of Order)",
	          msg_test.len == 58);

	mu_assert("[ERROR] GET CON failed to encode. (Out of Order)",
	          memcmp(msg_test.buf, msg_ref.buf, 58) == 0);

	return 0;
}

static char * test_msg_post_con_setters() {
	uint8_t ref_bin[] = {0x40,0x02,0x00,0x37,0xb2,0x31,0x61,0x04,0x74,0x65,
	                     0x6d,0x70,0x4d,0x1b,0x61,0x33,0x32,0x63,0x38,0x35,
	                     0x62,0x61,0x39,0x64,0x64,0x61,0x34,0x35,0x38,0x32,
	                     0x33,0x62,0x65,0x34,0x31,0x36,0x32,0x34,0x36,0x63,
	                     0x66,0x38,0x62,0x34,0x33,0x33,0x62,0x61,0x61,0x30,
	                     0x36,0x38,0x64,0x37,0xFF,0x39,0x39};
	coap_pdu msg_ref = {ref_bin, 57, 57};

	uint8_t test_bin[57];
	coap_pdu msg_test = {test_bin, 0, 57};

	mu_assert("[ERROR] Empty CON failed to init.",
	          coap_init_pdu(&msg_test) == CE_NONE);

	mu_assert("[ERROR] POST CON failed to set version.",
	          coap_set_version(&msg_test, COAP_V1) >= 0);

	mu_assert("[ERROR] POST CON failed to set type.",
	          coap_set_type(&msg_test, CT_CON) >= 0);

	mu_assert("[ERROR] POST CON failed to set code.",
	          coap_set_code(&msg_test, CC_POST) >= 0);

	mu_assert("[ERROR] POST CON failed to set message ID.",
	          coap_set_mid(&msg_test, 0x37) >= 0);

	mu_assert("[ERROR] POST CON failed to set token.",
	          coap_set_token(&msg_test, 0, 0) >= 0);

	mu_assert("[ERROR] POST CON failed to add first path option.",
	          coap_add_option(&msg_test, CON_URI_PATH, ref_bin+5, 2) == CE_NONE);

	mu_assert("[ERROR] POST CON failed to add second path option.",
	          coap_add_option(&msg_test, CON_URI_PATH, ref_bin+8, 4) == CE_NONE);

	mu_assert("[ERROR] POST CON failed to add query option.",
	          coap_add_option(&msg_test, CON_URI_QUERY, ref_bin+14, 40) == CE_NONE);

	mu_assert("[ERROR] POST CON failed to add payload.",
	          coap_set_payload(&msg_test, ref_bin+55, 2) == CE_NONE);

	mu_assert("[ERROR] POST CON length set wrong.",
	          msg_test.len == 57);

	mu_assert("[ERROR] POST CON failed to encode.",
	          memcmp(msg_ref.buf, msg_test.buf, 57) == 0);

	return 0;
}

static char * test_msg_content_ack_getters() {
	uint8_t ref_bin[] = {0x61,0x45,0xEE,0xCC,0xA2,0xFF,0x35,0x36};
	coap_pdu msg_ref = {ref_bin, 8, 8};

	coap_payload payload;

	mu_assert("[ERROR] CONTENT ACK failed validation.",
	          coap_validate_pkt(&msg_ref) == CE_NONE);

	mu_assert("[ERROR] CONTENT ACK version decoded wrong.",
	          coap_get_version(&msg_ref) == COAP_V1);

	mu_assert("[ERROR] CONTENT ACK type decoded wrong.",
	          coap_get_type(&msg_ref) == CT_ACK);

	mu_assert("[ERROR] CONTENT ACK code decoded wrong.",
	          coap_get_code(&msg_ref) == CC_CONTENT);

	mu_assert("[ERROR] CONTENT ACK code class decoded wrong.",
	          coap_get_code_class(&msg_ref) == 2);

	mu_assert("[ERROR] CONTENT ACK code detail decoded wrong.",
	          coap_get_code_detail(&msg_ref) == 5);

	payload = coap_get_payload(&msg_ref);
	mu_assert("[ERROR] CONTENT ACK payload length was wrong.",
	          payload.len == 2);
	mu_assert("[ERROR] CONTENT ACK payload value was wrong.",
	          memcmp(payload.val, ref_bin+6, 2) == 0);

	return 0;
}

// Helpers
void hex_dump(char* bytes, size_t len)
{
  size_t i, j;
  for (i = 0; i < len; i+=16){
    printf("  0x%.3zx    ", i);
    for (j = 0; j < 16; j++){
      if (i+j < len)
        printf("%.2hhx ", bytes[i+j]);
      else
        printf("%s ", "--");
    }
    printf("   %.*s\n", (int)(16 > len-i ? len-i : 16), bytes+i);
  }
}

void coap_pretty_print(coap_pdu *pdu)
{
  if (coap_validate_pkt(pdu) == 0){
    printf("Found Valid Coap Packet\n");
  }

  hex_dump((char*)pdu->buf, pdu->len);
}

static char * all_tests() {
	// Make Sure the Tests Are Working
	mu_run_test(test_math);

	// Actually Run the Real Tests
	mu_run_test(test_msg_empty_con_getters);
	mu_run_test(test_msg_empty_con_setters);
	mu_run_test(test_msg_get_con_getters);
	mu_run_test(test_msg_get_con_setters);
	mu_run_test(test_msg_content_ack_getters);
	mu_run_test(test_msg_get_con_setters_out_order);
	mu_run_test(test_msg_post_con_setters);
	return 0;
}

int main(int argc, char **argv) {
	char *result = all_tests();
	if (result != 0) {
		printf("%s\n", result);
	}
	else {
		printf("ALL TESTS PASSED\n");
	}
	printf("Tests run: %d\n", tests_run);

	return result != 0;
}

