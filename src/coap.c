#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "coap.h"


//
// Getters
//

// returns >=0 for valid or <0 for invalid
int8_t coap_validate_pkt(uint8_t *pkt, size_t pkt_len)
{
	int8_t token_length;
	int i;

	if (pkt_len < 4)
		return CS_INVALID_PACKET;

	// Check Version
	if (coap_get_version(pkt, pkt_len) != 1)
		return CS_INVALID_PACKET;

	// Check Message Type
	if (coap_get_type(pkt, pkt_len) < 0)
		return CS_INVALID_PACKET;

	// Check TKL
	token_length = coap_get_token(pkt, pkt_len, 0);
	if (token_length > 8 || token_length < 0)
		return CS_INVALID_PACKET;

	// Check Code
	if (coap_get_code(pkt, pkt_len) < 0)
		return CS_INVALID_PACKET;

	// Check MID
	if (coap_get_mid(pkt, pkt_len) < 0)
		return CS_INVALID_PACKET;

	// Check Options
	i = 0;
	for (i = coap_get_option_count(pkt, pkt_len) - 1; i > 0; i--){
		if (coap_get_option(pkt, pkt_len, i, 0, 0) < 0)
			return CS_INVALID_PACKET;
	}

	return CS_OK;
}

// returns version (1) or <0 for error
int8_t coap_get_version(uint8_t *pkt, size_t pkt_len)
{
	// Check that we were given enough packet.
	if (pkt_len < 1)
		return CS_INVALID_PACKET;

	return pkt[0] >> 6;
}

// returns type or <0 for error
int8_t coap_get_type(uint8_t *pkt, size_t pkt_len)
{
	// Check that we were given enough packet.
	if (pkt_len < 1)
		return CS_INVALID_PACKET;

	return (pkt[0] >> 4) & 0x03;
}

// returns code or <0 for error
int16_t coap_get_code(uint8_t *pkt, size_t pkt_len)
{
	// Check that we were given enough packet.
	if (pkt_len < 2)
		return CS_INVALID_PACKET;

	return pkt[1];
}

//returns mid or <0 for error
int32_t coap_get_mid(uint8_t *pkt, size_t pkt_len)
{
	// Check that we were given enough packet.
	if (pkt_len < 4)
		return CS_INVALID_PACKET;

	return (pkt[2] << 8) & pkt[3];
}

// returns len (0-8) or <0 for error
int8_t coap_get_token(uint8_t *pkt, size_t pkt_len, uint64_t* token)
{
	uint8_t token_length, i;

	// Make sure we have at least the byte with TKL.
	if (pkt_len < 1)
		return CS_INVALID_PACKET;

	// Extract TKL.
	token_length = pkt[0] & 0x0F;

	// Check token length for spec.
	if (token_length > 8)
		return CS_INVALID_PACKET;

	// Check that we were given enough packet.
	if (pkt_len < 4 + token_length)
		return CS_INVALID_PACKET;

	// If token doesn't point to null, set token.
	if (token != 0){
		*token = 0;
		for (i = 0; i < token_length; i++){
			*token = (*token << 8) & pkt[4+i];
		}
	}

	return token_length;
}

// returns number of options or <0 for error
int32_t coap_get_option_count(uint8_t *pkt, size_t pkt_len)
{
	int32_t ret, i = 0;

	do {
		ret = coap_get_option(pkt, pkt_len, i, 0, 0);
		if (ret == CS_FOUND_PAYLOAD_MARKER || ret == CS_END_OF_PACKET)
			return i;
		else if (ret < 0)
			return ret;

		i++;
	} while (1);
}

// returns opt_len or <0 for error
int32_t coap_get_option(uint8_t *pkt, size_t pkt_len, size_t opt_index, int32_t *opt_num, uint8_t **value)
{
	uint8_t *vptr;
	int8_t token_length;
	size_t i, offset;
	int32_t option_number, option_length;

	token_length = coap_get_token(pkt, pkt_len, 0);
	if (token_length < 0)
		return token_length;

	offset = 4 + token_length;
	option_number = 0;

	for (i = 0; i <= opt_index; i++){
		if (pkt[offset] == 0xFF)
			return CS_FOUND_PAYLOAD_MARKER;

		if (pkt_len-offset == 0)
			return CS_END_OF_PACKET;

		option_length = coap_decode_option(pkt+offset, pkt_len-offset, &option_number, &vptr);
		if (option_length < 0)
			return CS_INVALID_PACKET;

		// Add this option header and value length to offset.
		offset += (vptr - (pkt+offset)) + option_length;
	}

	if (opt_num != 0){
		*opt_num = option_number;
	}

	if (value != 0)
		*value = vptr;

	return option_length;
}


//
// Decoding Functions (Intended for Internal Use)
//

// returns opt_len or <0 for error
int32_t coap_decode_option(uint8_t *pkt_ptr, size_t pkt_len, int32_t *option_number, uint8_t **value)
{
	uint8_t *ptr = pkt_ptr;
	uint16_t delta, length;

	// Check for end of Packet
	if (pkt_len == 0){
		return CS_END_OF_PACKET;
	}

	// Check for Payload Marker
	if (*ptr == 0xFF){
		*pkt_ptr += 1;
		return CS_FOUND_PAYLOAD_MARKER;
	}

	// Get Base Delta and Length
	delta = *ptr >> 4;
	length = *ptr & 0x0F;
	ptr++;

	// Check for and Get Extended Delta
	if (delta < 13) {
		delta = delta;
	}else if (delta == 13) {
		delta = *ptr + 13;
		ptr += 1;
	}else if (delta == 14) {
		delta = (*ptr << 8) + *(ptr+1) + 269;
		ptr += 2;
	}else{
		return CS_INVALID_PACKET;
	}

	// Check for and Get Extended Length
	if (length < 13) {
		length = length;
	}else if (length == 13) {
		length = *ptr + 13;
		ptr += 1;
	}else if (length == 14) {
		length = (*ptr << 8) + *(ptr+1) + 269;
		ptr += 2;
	}else{
		return CS_INVALID_PACKET;
	}

	if (option_number != NULL)
		*option_number += delta;

	if (value != NULL)
		*value = ptr;

	return length;
}


int32_t coap_get_payload(uint8_t *pkt, size_t pkt_len, uint8_t **value)
{
	uint8_t *opt_val;
	int32_t opt_len = 0;
	size_t opt_count;

	// Find Last Option
	opt_count = coap_get_option_count(pkt, pkt_len);
	if (opt_count < 1)
		opt_val = pkt + 4 + coap_get_token(pkt, pkt_len, 0);
	else
		opt_len = coap_get_option(pkt, pkt_len, opt_count-1, 0, &opt_val);

	if (pkt_len == (opt_val + opt_len) - pkt)
		return 0; // No Payload

	if (opt_val[opt_len] != 0xFF)
		return CS_INVALID_PACKET;

	if (value != 0)
		*value = opt_val + opt_len + 1;

	return pkt_len - ((opt_val + opt_len + 1) - pkt);

}


//
// Setters
//

// returns >=0 on success or <0 for error
int8_t coap_set_version(uint8_t *pkt, size_t *pkt_len, size_t max_len, coap_version ver)
{
	// Check that we were given enough packet.
	if (max_len < 1)
		return CS_INSUFFICIENT_BUFFER;

	pkt[0] = (ver << 6) | (pkt[0] & ~(2 << 6));

	if (*pkt_len < 1)
		*pkt_len = 1;

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_set_type(uint8_t *pkt, size_t *pkt_len, size_t max_len, coap_type mtype)
{
	// Check that we were given enough packet.
	if (max_len < 1)
		return CS_INSUFFICIENT_BUFFER;

	pkt[0] = (mtype << 4) | (pkt[0] & ~(2 << 4));

	if (*pkt_len < 1)
		*pkt_len = 1;

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_set_code(uint8_t *pkt, size_t *pkt_len, size_t max_len, coap_code code)
{
	// Check that we were given enough packet.
	if (max_len < 2)
		return CS_INSUFFICIENT_BUFFER;

	pkt[1] = code;

	if (*pkt_len < 2)
		*pkt_len = 2;

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_set_mid(uint8_t *pkt, size_t *pkt_len, size_t max_len, uint16_t mid)
{
	// Check that we were given enough packet.
	if (max_len < 4)
		return CS_INSUFFICIENT_BUFFER;

	pkt[2] = mid >> 8;
	pkt[3] = mid & 0xFF;

	if (*pkt_len < 4)
		*pkt_len = 4;

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_set_token(uint8_t *pkt, size_t *pkt_len, size_t max_len, uint64_t token, uint8_t tkl)
{
	uint8_t i;
	int8_t ctkl = 0;

	// Check that we were given enough buffer.
	if (max_len < 4 + tkl)
		return CS_INSUFFICIENT_BUFFER;

	// Check token length for spec.
	if (tkl > 8)
		return CS_INVALID_PACKET;

	// Check if we may need to make or take room.
	if (*pkt_len > 4){
		// Find Current Token Length
		ctkl = coap_get_token(pkt, *pkt_len, 0);
		if (ctkl < 0)
			return ctkl;

		// Check that we were given enough buffer.
		if (max_len < *pkt_len + (tkl - ctkl))
			return CS_INSUFFICIENT_BUFFER;

		// Move rest of packet to make room or take empty space.
		memmove(pkt + 4 + tkl, pkt + 4 + ctkl, *pkt_len - 4 - ctkl);
	}

	// Set TKL in packet.
	pkt[0] = (tkl) | (pkt[0] & 0xF0);

	// Set token.
	for (i = 0; i < tkl; i++){
		pkt[4+tkl-i-1] = (token >> (8*i)) & 0xFF;
	}

	*pkt_len += tkl - ctkl;

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_add_option(uint8_t *pkt, size_t *pkt_len, size_t max_len, int32_t opt_num, uint8_t* value, uint16_t opt_len)
{
	uint8_t *pkt_ptr, *fopt_val, nopt_hdr_len;
	int8_t token_length;
	int32_t fopt_num, fopt_len, lopt_num;
	size_t opts_len;

	// Find end of header/start of options.
	token_length = coap_get_token(pkt, *pkt_len, 0);
	if (token_length < 0)
		return token_length;

	// Set pointer to "zeroth option's value" which is really first option header.
	fopt_val = pkt + 4 + token_length; // ptr to start of options
	fopt_len = 0;

	// Option number delta starts at zero.
	fopt_num = 0;

	// Find insertion point
	do{
		pkt_ptr = fopt_val + fopt_len;
		lopt_num = fopt_num;
		fopt_len = coap_decode_option(pkt_ptr, (*pkt_len)-(pkt_ptr-pkt), &fopt_num, &fopt_val);
	}while (fopt_len >= 0 && fopt_num <= opt_num && (pkt_ptr-pkt) + fopt_len < *pkt_len);

	// Build New Header
	nopt_hdr_len = coap_compute_option_header_len(opt_num - lopt_num, opt_len);


	// Check that we were given enough buffer.
	if (max_len < *pkt_len + nopt_hdr_len + opt_len)
		return CS_INSUFFICIENT_BUFFER;

	// Check if we're adding an option in the middle of a packet.
	// But seriously, don't do this.
	if (*pkt_len != pkt_ptr- pkt){
		// Slide packet tail to make room.
		memmove(pkt_ptr + nopt_hdr_len + opt_len, pkt_ptr, *pkt_len - (pkt_ptr - pkt));
		*pkt_len += nopt_hdr_len + opt_len;

		// Find Current Length of Remaining Options
		opts_len = *pkt_len - (pkt_ptr-pkt);

		// Adjust the option deltas for the rest of the options.
		coap_adjust_option_deltas(pkt_ptr + nopt_hdr_len + opt_len, &opts_len, max_len - (pkt_ptr - pkt), lopt_num - opt_num);

		// Update Total Packet Length
		*pkt_len += opts_len - (*pkt_len - (pkt_ptr-pkt));
	}else{
		// Update Packet Length
		*pkt_len = *pkt_len + nopt_hdr_len + opt_len;
	}

	// Insert the Header
	coap_build_option_header(pkt_ptr, nopt_hdr_len, opt_num - lopt_num, opt_len);

	// Insert the Value
	memcpy(pkt_ptr + nopt_hdr_len, value, opt_len);

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_set_payload(uint8_t *pkt, size_t *pkt_len, size_t max_len, uint8_t *value, size_t payload_len){
	uint8_t *pkt_ptr, *fopt_val;
	int8_t token_length;
	int32_t fopt_num, fopt_len;

	// Find end of header.
	token_length = coap_get_token(pkt, *pkt_len, 0);
	if (token_length < 0)
		return token_length;


	// Set pointer to "zeroth option's value" which is really first option header.
	fopt_val = pkt + 4 + token_length;
	fopt_len = 0;

	// Option number delta starts at zero.
	fopt_num = 0;

	// Find insertion point
	do{
		pkt_ptr = fopt_val + fopt_len;
		fopt_len = coap_decode_option(pkt_ptr, (*pkt_len)-(pkt_ptr-pkt), &fopt_num, &fopt_val);
	}while (fopt_len >= 0 && (pkt_ptr-pkt) + fopt_len < *pkt_len);

	if (fopt_len == CS_END_OF_PACKET){
		// Check that we were given enough buffer.
		if (max_len < *pkt_len + payload_len + 1)
			return CS_INSUFFICIENT_BUFFER;

		*(pkt_ptr++) = 0xFF;
	}else if (fopt_len == CS_FOUND_PAYLOAD_MARKER){
		// Check that we were given enough buffer.
		if (max_len < *pkt_len + payload_len)
			return CS_INSUFFICIENT_BUFFER;	
	}else{
		return fopt_len;
	}

	return CS_OK;
}

// returns >=0 on success or <0 for error
int8_t coap_adjust_option_deltas(uint8_t *opts_start, size_t *opts_len, size_t max_len, int32_t offset)
{
	uint8_t *ptr, *fopt_val;
	int32_t fopt_num, fopt_len, nopt_num;
	int8_t nhdr_len, fhdr_len;

	fopt_val = opts_start;
	fopt_len = 0;
	fopt_num = 0;

	do{
		ptr = fopt_val + fopt_len;
		if (ptr - opts_start  > *opts_len)
			break;

		fopt_len = coap_decode_option(ptr, *opts_len-(ptr-opts_start), &fopt_num, &fopt_val);

		if (fopt_len < 0)
			break;

		// New Option Number
		nopt_num = fopt_num + offset;

		// Find the length of the found header.
		fhdr_len = fopt_val - ptr;

		// Compute the length of the new header.
		nhdr_len = coap_compute_option_header_len(nopt_num, fopt_len);

		// Make/Take room for new header size
		if (fhdr_len != nhdr_len){
			if (max_len < *opts_len + (nhdr_len - fhdr_len))
				return CS_INSUFFICIENT_BUFFER;

			memmove(fopt_val + (nhdr_len - fhdr_len), fopt_val, fopt_len);

			// Adjust Options Length
			*opts_len += (nhdr_len - fhdr_len);
		}

		// Write New Header
		nhdr_len = coap_build_option_header(ptr, nhdr_len, nopt_num, fopt_len);

	}while (1);

	return CS_OK;

}

// returns header length (>=0) on success or <0 for error
int8_t coap_build_option_header(uint8_t *buf, size_t max_len, int32_t opt_delta, int32_t opt_len)
{
	uint8_t *ptr, base_num, base_len;

	if (max_len < 1)
		return CS_INSUFFICIENT_BUFFER;

	ptr = buf+1;

	if (opt_delta < 13) {
		base_num = opt_delta;
	}else if (opt_delta >= 13) {
		if (max_len < ptr-buf + 1)
			return CS_INSUFFICIENT_BUFFER;

		base_num = 13;
		*(ptr++) = opt_delta - 13;
	}else if (opt_delta >= 269) {
		if (max_len < ptr-buf + 2)
			return CS_INSUFFICIENT_BUFFER;

		base_num = 14;
		*(ptr++) = (opt_delta - 269) >> 8;
		*(ptr++) = (opt_delta - 269) & 0xFF;
	}

	if (opt_len < 13) {
		base_len = opt_len;
	}else if (opt_len >= 13) {
		if (max_len < ptr-buf + 1)
			return CS_INSUFFICIENT_BUFFER;

		base_len = 13;
		*(ptr++) = opt_len - 13;
	}else if (opt_len >= 269) {
		if (max_len < ptr-buf + 2)
			return CS_INSUFFICIENT_BUFFER;

		base_len = 14;
		*(ptr++) = (opt_len - 269) >> 8;
		*(ptr++) = (opt_len - 269) & 0xFF;
	}

	buf[0] = (base_num << 4) | base_len;


	// Return the length of the new header.
	return ptr-buf;

}

// returns header length (>=0) on success or <0 for error
int8_t coap_compute_option_header_len(int32_t opt_delta, int32_t opt_len)
{
	int8_t len = 1;

	if (opt_delta < 13) {
	}else if (opt_delta >= 13) {
		len += 1;
	}else if (opt_delta >= 269) {
		len += 2;
	}

	if (opt_len < 13) {
	}else if (opt_len >= 13) {
		len += 1;
	}else if (opt_len >= 269) {
		len += 2;
	}

	return len;

}