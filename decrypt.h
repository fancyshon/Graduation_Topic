/*
 * decrypt.h
 *
 *  Created on: 2021¦~3¤ë3¤é
 *      Author: user
 */

#ifndef DECRYPT_H_
#define DECRYPT_H_

typedef unsigned char byte;

void generate_key(void);
byte xor_byte(byte* data, int i);
byte reverse_subbyte(byte* d);
void reverse_shift_row(byte* data, int length);
void reverse_mix_column(byte* data, int length);
void split_package(int data_size, byte* data);

void decrypt(byte* data, int length);


#endif /* DECRYPT_H_ */
