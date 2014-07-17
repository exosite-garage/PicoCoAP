#include <stdio.h>
#include <string.h>
#include "minunit.h"
#include "../src/coap.h"

int tests_run = 0;


void coap_pretty_print(uint8_t* pkt, size_t len);
void hex_dump(char* bytes, size_t len);

static char * test_math() {
	mu_assert("[ERROR] 2+2 != 4", 2+2 == 4);
	return 0;
}

static char * test_msg_empty_con_getters() {
	uint8_t msg_bin_ref[] = {64,0,0,0};

	mu_assert("[ERROR] Empty CON failed validation.",
	          coap_validate_pkt(msg_bin_ref, 4) == CS_OK);

	mu_assert("[ERROR] Empty CON version decoded wrong.",
	          coap_get_version(msg_bin_ref, 4) == COAP_V1);

	mu_assert("[ERROR] Empty CON type decoded wrong.",
	          coap_get_type(msg_bin_ref, 4) == CT_CON);

	mu_assert("[ERROR] Empty CON code decoded wrong.",
	          coap_get_code(msg_bin_ref, 4) == CC_EMPTY);

	mu_assert("[ERROR] Empty CON code class decoded wrong.",
	          coap_get_code_class(msg_bin_ref, 4) == 0);

	mu_assert("[ERROR] Empty CON code detail decoded wrong.",
	          coap_get_code_detail(msg_bin_ref, 4) == 0);

	mu_assert("[ERROR] Empty CON option count was wrong.",
	          coap_get_option_count(msg_bin_ref, 4) == 0);

	return 0;
}

static char * test_msg_empty_con_setters() {
	uint8_t msg_bin_ref[] = {64,0,0,0};
	uint8_t msg_bin_tst[4] = {0,0,0,0};
	size_t msg_len = 0;

	mu_assert("[ERROR] Empty CON failed to set version.",
	          coap_set_version(msg_bin_tst, &msg_len, 4, COAP_V1) >= 0);

	mu_assert("[ERROR] Empty CON failed to set type.",
	          coap_set_type(msg_bin_tst, &msg_len, 4, CT_CON) >= 0);

	mu_assert("[ERROR] Empty CON failed to set code.",
	          coap_set_code(msg_bin_tst, &msg_len, 4, CC_EMPTY) >= 0);

	mu_assert("[ERROR] Empty CON failed to set message ID.",
	          coap_set_mid(msg_bin_tst, &msg_len, 4, 0) >= 0);

	mu_assert("[ERROR] Empty CON failed to set token.",
	          coap_set_token(msg_bin_tst, &msg_len, 4, 0, 0) >= 0);

	mu_assert("[ERROR] Empty CON length set wrong.",
	          msg_len == 4);

	mu_assert("[ERROR] Empty CON failed to encode.",
	          memcmp(msg_bin_ref, msg_bin_tst, 4) == 0);

	return 0;
}

static char * test_msg_get_con_getters() {
	uint8_t msg_bin_ref[] = {0x40,0x01,0x00,0x37,0xb2,0x31,0x61,0x04,0x74,0x65,
	                         0x6d,0x70,0x4d,0x1b,0x61,0x33,0x32,0x63,0x38,0x35,
	                         0x62,0x61,0x39,0x64,0x64,0x61,0x34,0x35,0x38,0x32,
	                         0x33,0x62,0x65,0x34,0x31,0x36,0x32,0x34,0x36,0x63,
	                         0x66,0x38,0x62,0x34,0x33,0x33,0x62,0x61,0x61,0x30,
	                         0x36,0x38,0x64,0x37};
	int32_t option_number, option_length;
	uint8_t *option_value;

	mu_assert("[ERROR] GET CON failed validation.",
	          coap_validate_pkt(msg_bin_ref, sizeof msg_bin_ref) == CS_OK);

	mu_assert("[ERROR] GET CON version decoded wrong.",
	          coap_get_version(msg_bin_ref, sizeof msg_bin_ref) == COAP_V1);

	mu_assert("[ERROR] GET CON type decoded wrong.",
	          coap_get_type(msg_bin_ref, sizeof msg_bin_ref) == CT_CON);

	mu_assert("[ERROR] GET CON code decoded wrong.",
	          coap_get_code(msg_bin_ref, sizeof msg_bin_ref) == CC_GET);

	mu_assert("[ERROR] GET CON code class decoded wrong.",
	          coap_get_code_class(msg_bin_ref, sizeof msg_bin_ref) == 0);

	mu_assert("[ERROR] GET CON code detail decoded wrong.",
	          coap_get_code_detail(msg_bin_ref, sizeof msg_bin_ref) == 1);

	mu_assert("[ERROR] GET CON option count was wrong.",
	          coap_get_option_count(msg_bin_ref, sizeof msg_bin_ref) == 3);

	option_length = coap_get_option(msg_bin_ref, sizeof msg_bin_ref, 0, &option_number, &option_value);
	mu_assert("[ERROR] GET CON option zero length was wrong.",
	          option_length == 2);
	mu_assert("[ERROR] GET CON option zero number was wrong.",
	          option_number == CON_URI_PATH);
	mu_assert("[ERROR] GET CON option zero value was wrong.",
	          memcmp(option_value, msg_bin_ref+5, option_length) == 0);

	option_length = coap_get_option(msg_bin_ref, sizeof msg_bin_ref, 1, &option_number, &option_value);
	mu_assert("[ERROR] GET CON option one length was wrong.",
	          option_length == 4);
	mu_assert("[ERROR] GET CON option one number was wrong.",
	          option_number == CON_URI_PATH);
	mu_assert("[ERROR] GET CON option one value was wrong.",
	          memcmp(option_value, msg_bin_ref+8, option_length) == 0);

	option_length = coap_get_option(msg_bin_ref, sizeof msg_bin_ref, 2, &option_number, &option_value);
	mu_assert("[ERROR] GET CON option two length was wrong.",
	          option_length == 40);
	mu_assert("[ERROR] GET CON option two number was wrong.",
	          option_number == CON_URI_QUERY);
	mu_assert("[ERROR] GET CON option two value was wrong.",
	          memcmp(option_value, msg_bin_ref+14, option_length) == 0);

	return 0;
}

static char * test_msg_get_con_setters() {
	uint8_t msg_bin_ref[] = {0x40,0x01,0x00,0x37,0xb2,0x31,0x61,0x04,0x74,0x65,
	                         0x6d,0x70,0x4d,0x1b,0x61,0x33,0x32,0x63,0x38,0x35,
	                         0x62,0x61,0x39,0x64,0x64,0x61,0x34,0x35,0x38,0x32,
	                         0x33,0x62,0x65,0x34,0x31,0x36,0x32,0x34,0x36,0x63,
	                         0x66,0x38,0x62,0x34,0x33,0x33,0x62,0x61,0x61,0x30,
	                         0x36,0x38,0x64,0x37};
	uint8_t msg_bin_tst[54];
	size_t msg_len = 0;

	mu_assert("[ERROR] GET CON failed to set version.",
	          coap_set_version(msg_bin_tst, &msg_len, 54, COAP_V1) >= 0);

	mu_assert("[ERROR] GET CON failed to set type.",
	          coap_set_type(msg_bin_tst, &msg_len, 54, CT_CON) >= 0);

	mu_assert("[ERROR] GET CON failed to set code.",
	          coap_set_code(msg_bin_tst, &msg_len, 54, CC_GET) >= 0);

	mu_assert("[ERROR] GET CON failed to set message ID.",
	          coap_set_mid(msg_bin_tst, &msg_len, 54, 0x37) >= 0);

	mu_assert("[ERROR] GET CON failed to set token.",
	          coap_set_token(msg_bin_tst, &msg_len, 54, 0, 0) >= 0);

	mu_assert("[ERROR] GET CON failed to add first path option.",
	          coap_add_option(msg_bin_tst, &msg_len, 54, CON_URI_PATH, msg_bin_ref+5, 2) >= 0);

	mu_assert("[ERROR] GET CON failed to add second path option.",
	          coap_add_option(msg_bin_tst, &msg_len, 54, CON_URI_PATH, msg_bin_ref+8, 4) >= 0);

	mu_assert("[ERROR] GET CON failed to add query option.",
	          coap_add_option(msg_bin_tst, &msg_len, 54, CON_URI_QUERY, msg_bin_ref+14, 40) >= 0);

	mu_assert("[ERROR] GET CON length set wrong.",
	          msg_len == 54);

	mu_assert("[ERROR] GET CON failed to encode.",
	          memcmp(msg_bin_ref, msg_bin_tst, 54) == 0);

	return 0;
}

static char * test_msg_get_con_setters_out_order() {
	uint8_t msg_bin_ref[] = {0x44,0x01,0x00,0x37,0xff,0xff,0xff,0xff,0xb2,0x31,
		                     0x61,0x04,0x74,0x65,0x6d,0x70,0x4d,0x1b,0x61,0x33,
		                     0x32,0x63,0x38,0x35,0x62,0x61,0x39,0x64,0x64,0x61,
		                     0x34,0x35,0x38,0x32,0x33,0x62,0x65,0x34,0x31,0x36,
		                     0x32,0x34,0x36,0x63,0x66,0x38,0x62,0x34,0x33,0x33,
		                     0x62,0x61,0x61,0x30,0x36,0x38,0x64,0x37};
	uint8_t msg_bin_tst[64];
	size_t msg_len = 0;

	memset(msg_bin_tst, 0, 64);

	mu_assert("[ERROR] GET CON failed to set version.",
	          coap_set_version(msg_bin_tst, &msg_len, 64, COAP_V1) >= 0);

	mu_assert("[ERROR] GET CON failed to set type.",
	          coap_set_type(msg_bin_tst, &msg_len, 64, CT_CON) >= 0);

	mu_assert("[ERROR] GET CON failed to set code.",
	          coap_set_code(msg_bin_tst, &msg_len, 64, CC_GET) >= 0);

	mu_assert("[ERROR] GET CON failed to set message ID.",
	          coap_set_mid(msg_bin_tst, &msg_len, 64, 0x37) >= 0);

	mu_assert("[ERROR] GET CON failed to set token.",
	          coap_set_token(msg_bin_tst, &msg_len, 64, 0xFFFFFFFF, 4) >= 0);

	mu_assert("[ERROR] GET CON failed to add first path option. (Out of Order)",
	          coap_add_option(msg_bin_tst, &msg_len, 64, CON_URI_PATH, msg_bin_ref+9, 2) >= 0);

	mu_assert("[ERROR] GET CON failed to add second path option. (Out of Order)",
	          coap_add_option(msg_bin_tst, &msg_len, 64, CON_URI_PATH, msg_bin_ref+12, 4) >= 0);

	mu_assert("[ERROR] GET CON failed to add query option.",
	          coap_add_option(msg_bin_tst, &msg_len, 64, CON_URI_QUERY, msg_bin_ref+18, 40) >= 0);

	mu_assert("[ERROR] GET CON length set wrong.",
	          msg_len == 58);

	mu_assert("[ERROR] GET CON failed to encode.",
	          memcmp(msg_bin_ref, msg_bin_tst, 58) == 0);

	return 0;
}

static char * test_msg_post_con_setters() {
	uint8_t msg_bin_ref[] = {0x40,0x02,0x00,0x37,0xb2,0x31,0x61,0x04,0x74,0x65,
	                         0x6d,0x70,0x4d,0x1b,0x61,0x33,0x32,0x63,0x38,0x35,
	                         0x62,0x61,0x39,0x64,0x64,0x61,0x34,0x35,0x38,0x32,
	                         0x33,0x62,0x65,0x34,0x31,0x36,0x32,0x34,0x36,0x63,
	                         0x66,0x38,0x62,0x34,0x33,0x33,0x62,0x61,0x61,0x30,
	                         0x36,0x38,0x64,0x37,0xFF,0x39,0x39};
	uint8_t msg_bin_tst[57];
	size_t msg_len = 0;

	mu_assert("[ERROR] POST CON failed to set version.",
	          coap_set_version(msg_bin_tst, &msg_len, 57, COAP_V1) >= 0);

	mu_assert("[ERROR] POST CON failed to set type.",
	          coap_set_type(msg_bin_tst, &msg_len, 57, CT_CON) >= 0);

	mu_assert("[ERROR] POST CON failed to set code.",
	          coap_set_code(msg_bin_tst, &msg_len, 57, CC_POST) >= 0);

	mu_assert("[ERROR] POST CON failed to set message ID.",
	          coap_set_mid(msg_bin_tst, &msg_len, 57, 0x37) >= 0);

	mu_assert("[ERROR] POST CON failed to set token.",
	          coap_set_token(msg_bin_tst, &msg_len, 57, 0, 0) >= 0);

	mu_assert("[ERROR] POST CON failed to add first path option.",
	          coap_add_option(msg_bin_tst, &msg_len, 57, CON_URI_PATH, msg_bin_ref+5, 2) >= 0);

	mu_assert("[ERROR] POST CON failed to add second path option.",
	          coap_add_option(msg_bin_tst, &msg_len, 57, CON_URI_PATH, msg_bin_ref+8, 4) >= 0);

	mu_assert("[ERROR] POST CON failed to add query option.",
	          coap_add_option(msg_bin_tst, &msg_len, 57, CON_URI_QUERY, msg_bin_ref+14, 40) >= 0);

	mu_assert("[ERROR] POST CON failed to add query option.",
	          coap_set_payload(msg_bin_tst, &msg_len, 57, msg_bin_ref+55, 2) >= 0);

	mu_assert("[ERROR] POST CON length set wrong.",
	          msg_len == 57);

	mu_assert("[ERROR] POST CON failed to encode.",
	          memcmp(msg_bin_ref, msg_bin_tst, 57) == 0);

	return 0;
}

static char * test_msg_content_ack_getters() {
	uint8_t msg_bin_ref[] = {0x61,0x45,0xEE,0xCC,0xA2,0xFF,0x35,0x36};
	int32_t payload_length;
	uint8_t *payload_value;

	mu_assert("[ERROR] CONTENT ACK failed validation.",
	          coap_validate_pkt(msg_bin_ref, sizeof msg_bin_ref) == CS_OK);

	mu_assert("[ERROR] CONTENT ACK version decoded wrong.",
	          coap_get_version(msg_bin_ref, sizeof msg_bin_ref) == COAP_V1);

	mu_assert("[ERROR] CONTENT ACK type decoded wrong.",
	          coap_get_type(msg_bin_ref, sizeof msg_bin_ref) == CT_ACK);

	mu_assert("[ERROR] CONTENT ACK code decoded wrong.",
	          coap_get_code(msg_bin_ref, sizeof msg_bin_ref) == CC_CONTENT);

	mu_assert("[ERROR] CONTENT ACK code class decoded wrong.",
	          coap_get_code_class(msg_bin_ref, sizeof msg_bin_ref) == 2);

	mu_assert("[ERROR] CONTENT ACK code detail decoded wrong.",
	          coap_get_code_detail(msg_bin_ref, sizeof msg_bin_ref) == 5);

	mu_assert("[ERROR] CONTENT ACK option count was wrong.",
	          coap_get_option_count(msg_bin_ref, sizeof msg_bin_ref) == 0);

	payload_length = coap_get_payload(msg_bin_ref, sizeof msg_bin_ref, &payload_value);
	mu_assert("[ERROR] CONTENT ACK payload length was wrong.",
	          payload_length == 2);
	mu_assert("[ERROR] CONTENT ACK payload value was wrong.",
	          memcmp(payload_value, msg_bin_ref+6, 2) == 0);

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

void coap_pretty_print(uint8_t* pkt, size_t len)
{
  if (coap_validate_pkt(pkt, len) >= 0){
    printf("Found Valid Coap Packet\n");
  }

  hex_dump((char*)pkt, len);
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