/*
 * decrypt.h
 *
 *  Created on: 2021¦~3¤ë3¤é
 *      Author: user
 */

#include <lwip/arch.h>


#ifndef DECRYPT_H_
#define DECRYPT_H_

typedef unsigned char byte;

void generate_key(byte *R, u16_t len, byte *ecc_pub_key);
int read_control_byte(byte* data, u16_t length);
byte xor_byte(byte* data, u16_t i);
byte reverse_subbyte(byte* d);
void reverse_shift_row(byte* data, u16_t length);
void reverse_mix_column(byte* data, u16_t length);
void split_package(byte* data ,u16_t data_size);
void init_key(byte *ecc_pri_key, byte *ecc_pub_key);
int check_hmac(byte* data, u16_t len, byte* sig);
void ecc_generate_key(void);
void decrypt(byte* data, u16_t length);
void udp_send_message_to_client(byte *data, u16_t len);
void tcp_send_message_to_server(byte *data, u16_t len);







#endif /* DECRYPT_H_ */
