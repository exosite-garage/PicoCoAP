///
/// @file	 coap.h
/// @author	 Patrick Barrett <patrickbarrett@exosite.com>
/// @date	 2014-07-10
/// @brief	 CoAP Message Parsing
///
/// @details This file provides functions for parsing and building CoAP message packets
///          using only the actual binary of the message, not needing additional memory
///          for secondary data structures.
///

#ifndef _COAP_H_
#define _COAP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


///
/// Status Codes
///
/// These codes represent the possible errors that functions in this library can
/// return. Note that all errors are < 0.
///
typedef enum coap_status {
	CS_OK = 0,
	CS_INVALID_PACKET = -1,
	CS_BAD_VERSION = -2,
	CS_TOKEN_LENGTH_OUT_OF_RANGE = -3,
	CS_UNKNOWN_CODE = -4,
	CS_TOO_MANY_OPTIONS = -5,
	CS_OUT_OF_ORDER_OPTIONS_LIST = -6,
	CS_INSUFFICIENT_BUFFER = -7,
	CS_FOUND_PAYLOAD_MARKER = -8,
	CS_END_OF_PACKET = -9
} coap_status;

///
/// Protocol Versions
///
/// All known version of the protocol.
///
typedef enum coap_version {
	COAP_V1 = 1
} coap_version;

///
/// Message Types
///
/// The four types of messages possible.
///
typedef enum coap_type {
	CT_CON = 0,
	CT_NON = 1,
	CT_ACK = 2,
	CT_RST = 3
} coap_type;

///
/// Message Codes
///
/// All known message request/response codes.
///
typedef enum coap_code {
	CC_EMPTY = 0,
	CC_GET = 1,
	CC_POST = 2,
	CC_PUT = 3,
	CC_DELETE = 4,
	CC_CREATED = 65,
	CC_DELETED = 66,
	CC_VALID = 67,
	CC_CHANGED = 68,
	CC_CONTENT = 69,
	CC_CONTINUE = 95,
	CC_BAD_REQUEST = 128,
	CC_UNAUTHORIZED = 129,
	CC_BAD_OPTION = 130,
	CC_FORBIDDEN = 131,
	CC_NOT_FOUND = 132,
	CC_METHOD_NOT_ALLOWED = 133,
	CC_NOT_ACCEPTABLE = 134,
	CC_REQUEST_ENTITY_INCOMPLETE = 136,
	CC_PRECONDITION_FAILED = 140,
	CC_REQUEST_ENTITY_TOO_LARGE = 141,
	CC_UNSUPPORTED_CONTENT  = 143,
	CC_INTERNAL_SERVER_ERROR = 160,
	CC_NOT_IMPLEMENTED = 161,
	CC_BAD_GATEWAY = 162,
	CC_SERVICE_UNAVAILABLE = 163,
	CC_GATEWAY_TIMEOUT = 164,
	CC_PROXYING_NOT_SUPPORTED = 165
} coap_code;

///
/// Option Numbers
///
/// All known option numbers.
///
typedef enum coap_option_number {
	CON_IF_MATCH = 1,
	CON_URI_HOST = 3,
	CON_ETAG = 4,
	CON_IF_NONE_MATCH = 5,
	CON_URI_PORT = 7,
	CON_LOCATION_PATH = 8,
	CON_URI_PATH = 11,
	CON_CONTENT_FORMATt = 12,
	CON_MAX_AGE = 14,
	CON_URI_QUERY = 15,
	CON_ACCEPT = 17,
	CON_LOCATION_QUERY = 20,
	CON_PROXY_URI = 35,
	CON_PROXY_SCHEME = 39,
	CON_SIZE1 = 60
} coap_option_number;

///
/// Validate Packet
///
/// Parses the given message to check if it is a valid CoAP packet.
/// @param  [in] pkt     pointer to a buffer containing the message to be validated.
/// @param  [in] pkt_len the length of the message to be validated.
/// @return CS_OK for valid packet or <=0 on error.
/// @see    coap_status
///
int8_t coap_validate_pkt(uint8_t *pkt, size_t pkt_len);

//
// Getters
//

///
/// Get Version
///
/// Extracts the CoAP version from the given message.
/// @param  [in] pkt     pointer to a buffer containing the message to be parsed.
/// @param  [in] pkt_len the length of the message to be parsed.
/// @return version or <=0 on error.
/// @see coap_version
/// @see coap_status
///
int8_t  coap_get_version(uint8_t *pkt, size_t pkt_len);

///
/// Get Message Type
///
/// Extracts the message type from the given message.
/// @param  [in] pkt     pointer to a buffer containing the message to be parsed.
/// @param  [in] pkt_len the length of the message to be parsed.
/// @return type or <=0 on error.
/// @see coap_type
/// @see coap_status
///
int8_t  coap_get_type(uint8_t *pkt, size_t pkt_len);

///
/// Get Message Code
///
/// Extracts the message code from the given message.
/// @param  [in] pkt     pointer to a buffer containing the message to be parsed.
/// @param  [in] pkt_len the length of the message to be parsed.
/// @return code or <=0 on error.
/// @see coap_code
/// @see coap_status
///
int16_t coap_get_code(uint8_t *pkt, size_t pkt_len);

///
/// Get Message ID
///
/// Extracts the message ID from the given message.
/// @param  [in] pkt     pointer to a buffer containing the message to be parsed.
/// @param  [in] pkt_len the length of the message to be parsed.
/// @return mid or <=0 on error.
/// @see coap_status
///
int32_t coap_get_mid(uint8_t *pkt, size_t pkt_len);

///
/// Get Message Token
///
/// Extracts the token from the given message.
/// @param  [in]  pkt     pointer to a buffer containing the message to be parsed.
/// @param  [in]  pkt_len the length of the message to be parsed.
/// @param  [out] token   pointer to where the token should be stored.
/// @return token length or <=0 on error.
/// @see coap_status
///
int8_t  coap_get_token(uint8_t *pkt, size_t pkt_len, uint64_t* token);

///
/// Get Option Count
///
/// Extracts the number of options in the given message.
/// @param  [in]  pkt     pointer to a buffer containing the message to be parsed.
/// @param  [in]  pkt_len the length of the message to be parsed.
/// @return option count or <=0 on error.
/// @see coap_status
///
int32_t coap_get_option_count(uint8_t *pkt, size_t pkt_len);

///
/// Get Option
///
/// Extracts the option with the given index in the given message.
/// @param  [in]  pkt       pointer to a buffer containing the message to be parsed.
/// @param  [in]  pkt_len   the length of the message to be parsed.
/// @param  [in]  opt_index the index of the option to get.
/// @param  [out] opt_num   pointer to where the option number should be stored.
/// @param  [out] value     pointer to where the pointer to the value should be stored. Note that
///                         the returned pointer is only valid while the pkt buffer remains intact.
/// @return option value length or <=0 on error.
/// @see coap_status
///
int32_t coap_get_option(uint8_t *pkt, size_t pkt_len, size_t opt_index, int32_t *opt_num, uint8_t **value);

///
/// Get Option
///
/// Extracts the option with the given index in the given message.
/// @param  [in]  pkt       pointer to a buffer containing the message to be parsed.
/// @param  [in]  pkt_len   the length of the message to be parsed.
/// @param  [out] value     pointer to where the pointer to the payload should be stored. Note that
///                         the returned pointer is only valid while the pkt buffer remains intact.
/// @return payload length or <=0 on error.
/// @see coap_status
///
int32_t coap_get_payload(uint8_t *pkt, size_t pkt_len, uint8_t **value);

///
/// Get Message Code Class
///
/// Gets the class portion of the message code.
/// @param  [in]  pkt       pointer to a buffer containing the message to be parsed.
/// @param  [in]  pkt_len   the length of the message to be parsed.
/// @see    coap_get_code
///
static inline uint8_t coap_get_code_class(uint8_t *pkt, size_t pkt_len) { return coap_get_code(pkt, pkt_len) >> 5; }

///
/// Get Message Code Detail
///
/// Gets the detail portion of the message code.
/// @param  [in]  pkt       pointer to a buffer containing the message to be parsed.
/// @param  [in]  pkt_len   the length of the message to be parsed.
/// @see    coap_get_code
///
static inline uint8_t coap_get_code_detail(uint8_t *pkt, size_t pkt_len) { return coap_get_code(pkt, pkt_len) & 0x1F; }

///
/// Internal Method
///
int32_t coap_decode_option(uint8_t *opt_start_ptr, size_t pkt_len, int32_t *option_number, uint8_t **value);

//
// Setters
//

///
/// Set Version
///
/// Sets the version number header field.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      ver      version to set. Must be COAP_V1.
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
/// @see coap_version
///
int8_t coap_set_version(uint8_t *pkt, size_t *pkt_len, size_t max_size, coap_version ver);

///
/// Set Message Type
///
/// Sets the message type header field.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      mtype    type to set.
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
/// @see coap_type
///
int8_t coap_set_type(uint8_t *pkt, size_t *pkt_len, size_t max_size, coap_type mtype);

///
/// Set Message Code
///
/// Sets the message type header field.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      code     code to set.
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
/// @see coap_code
///
int8_t coap_set_code(uint8_t *pkt, size_t *pkt_len, size_t max_size, coap_code code);

///
/// Set Message ID
///
/// Sets the message ID header field.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      mid      message ID to set.
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
///
int8_t coap_set_mid(uint8_t *pkt, size_t *pkt_len, size_t max_size, uint16_t mid);

///
/// Set Message Token
///
/// Sets the message token header field.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      token    token value to set.
/// @param  [in]      len      token length to set. (0-8)
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
///
int8_t coap_set_token(uint8_t *pkt, size_t *pkt_len, size_t max_size, uint64_t token, uint8_t len);

///
/// Add Message Option
///
/// Adds an option to the existing message. Options SHOULD be added in order of
/// option number. In the case of multiple options of the same type, they are 
/// sorted in the order that they are added.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      opt_num  the option number (type).
/// @param  [in]      opt_val  a pointer to the option value. Value is copied
///                            and may be modified after calling this function.
/// @param  [in]      opt_len  the length of the option value.
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
///
int8_t coap_add_option(uint8_t *pkt, size_t *pkt_len, size_t max_size, int32_t opt_num, uint8_t* opt_val, uint16_t opt_len);

///
/// Add Message Option
///
/// Sets the payload of the given message to the value in `payload`.
/// @param  [in]      pkt      pointer to a buffer containing the message.
/// @param  [in,out]  pkt_len  the length of the message.
/// @param  [in]      max_size the length of the buffer.
/// @param  [in]      pl_val   a pointer to the payload. Payload is copied
///                            and may be modified after calling this function.
/// @param  [in]      pl_len   the length of the option value.
/// @return CS_OK on success or <=0 on error.
/// @see coap_status
///
int8_t coap_set_payload(uint8_t *pkt, size_t *pkt_len, size_t max_size, uint8_t *pl_val, size_t pl_len);

//
// Internal
//

///
/// Internal Method
///
int8_t coap_adjust_option_deltas(uint8_t *opts, size_t *opts_len, size_t max_len, int32_t offset);

///
/// Internal Method
///
int8_t coap_build_option_header(uint8_t *buf, size_t max_len, int32_t opt_delta, int32_t opt_len);

///
/// Internal Method
///
int8_t coap_compute_option_header_len(int32_t opt_delta, int32_t opt_len);

#ifdef __cplusplus
}
#endif

#endif /*_COAP_H_*/