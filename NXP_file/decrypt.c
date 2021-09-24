/*
 * decrypt.c
 *
 *  Created on: 2021¦~3¤ë3¤é
 *      Author: user
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "decrypt.h"
#include "lwip/api.h"
#include "hmac_sha2.h"
#include "ECC/uECC.h"



static int count = 0;

static byte *key;
static byte *h_key;
static const struct uECC_Curve_t *curve;
static byte* ecc_key;
static byte* ecc_key_sha256;

static byte inv_S[256] = { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };



byte* get_key(void)
{
	return key;
}
byte* get_h_key(void)
{
	return h_key;
}
byte* get_ecc_key(void)
{
	return ecc_key;
}
byte* get_ecc_key_sha256(void)
{
	return ecc_key_sha256;
}

void generate_key(byte *R, u16_t len, byte *ecc_pri_key)
{
	ecc_key = (byte*)malloc(64*sizeof(byte));

	curve = uECC_secp256k1();
	uECC_shared_secret(R, ecc_pri_key, ecc_key, curve);

	ecc_key_sha256 = (byte*)malloc(32*sizeof(byte));
	sha256(ecc_key, 64, ecc_key_sha256);
	int i;
	for(i = 0;i < 16;i++)
	{
		key[i] = ecc_key_sha256[i];
	}
	for(i = 0;i < 16;i++)
	{
		h_key[i] = ecc_key_sha256[i+16];
	}
}


void init_key(byte* ecc_pri_key,byte* ecc_pub_key)
{
	if(count == 0)
	{
		count++;
		key = (byte*)malloc(16 * sizeof(byte));
		int i;
		int key_count = 0;

		for(i = 0;i < 16;i++)
		{
			key[i] = (byte)key_count;
			key_count += 1;
		}
		h_key = (byte*)malloc(16 * sizeof(byte));
		for(i = 0;i < 16;i++)
		{
			h_key[i] = (byte)1;
		}


	}
}

int read_control_byte(byte* data, u16_t length)
{
	int read = 0;
	read = (int)data[0];

	return read;

}

//True return 1, false return 0
int check_hmac(byte* data, u16_t len, byte* sig)
{

	byte *hmac_array = (byte*)malloc(32 * sizeof(byte));
	memcpy(hmac_array, data + len - 32, 32);
	hmac_sha256(h_key, 16, data + 1, len - 32 - 1, sig, 32);

	int i;
	for(i = 0;i < 32;i++)
	{
		if(hmac_array[i] != sig[i])
		{
			free(hmac_array);
			return 1;
		}
	}
	free(hmac_array);

	return 0;

}



byte xor_byte(byte* data, u16_t i)
{
	return data[0] ^ key[i];
}

byte reverse_subbyte(byte* d)
{
	int i = (int)d[0];
	return inv_S[i];
}

void reverse_shift_row(byte* data, u16_t length)
{
	/*
	 * 0123
	 * 4567
     * 89AB
     * CDEF
	 */

	//Right Shift
	byte* temp_data;
	temp_data = (byte* )malloc(sizeof(byte) * length);
	memcpy(temp_data, data,  length);
	int i;
	for(i = 0;i < length;i++)
	{
		switch(i)
		{
		case 4:
			data[i] = temp_data[7];
			break;
		case 5:
			data[i] = temp_data[4];
			break;
		case 6:
			data[i] = temp_data[5];
			break;
		case 7:
			data[i] = temp_data[6];
			break;
		case 8:
			data[i] = temp_data[10];
			break;
		case 9:
			data[i] = temp_data[11];
			break;
		case 10:
			data[i] = temp_data[8];
			break;
		case 11:
			data[i] = temp_data[9];
			break;
		case 12:
			data[i] = temp_data[13];
			break;
		case 13:
			data[i] = temp_data[14];
			break;
		case 14:
			data[i] = temp_data[15];
			break;
		case 15:
			data[i] = temp_data[12];
			break;
		}
	}
	free(temp_data);
}


void reverse_mix_column(byte* data, u16_t length)
{

}

void decrypt(byte* data, u16_t length)
{


	int i,j;
	//Round 10 ~ 1
	for(i = 0;i < 10;i++)
	{
		if(i == 0)
		{
			for(j = 0;j < length;j++)
			{
				data[j] = xor_byte(data + j, j);
				data[j] = reverse_subbyte(data + j);
			}
			reverse_shift_row(data, length);
		}
		else
		{
			reverse_mix_column(data, length);
			for(j = 0;j < length;j++)
			{
				data[j] = xor_byte(data + j, j);
				data[j] = reverse_subbyte(data + j);
			}
			reverse_shift_row(data, length);
		}
	}

	//Round 0
	for(i = 0;i < length;i++)
	{
		data[i] = xor_byte(data + i, i);
	}

}

void split_package( byte* data, u16_t data_size)
{

	u16_t data_length = data_size / sizeof(byte);

	int i;

	if(data_length == 256)
	{
		u16_t offset = 0;
		for(i = 0;i < 16;i++)
		{
			decrypt(data + offset, 16);
			offset += 16;
		}
	}
	else
	{
		u16_t remain_length = data_length;
		u16_t offset = 0;
		while(1)
		{
			if(remain_length < 16 && remain_length != 0)
			{
				byte* new_data = (byte*)malloc(16* sizeof(byte));
				for(i = 0;i < 16;i++)
				{
					if(i < remain_length)
					{
						new_data[i] = data[offset + i];
					}
					else
					{
						new_data[i] = 0;
					}
				}
				decrypt(new_data, 16);

				for(i = 0;i < remain_length;i++)
				{
					data[offset+i] = new_data[i];
				}

				free(new_data);
				break;
			}
			else
			{
				decrypt(data + offset, 16);
				offset += 16;
				remain_length -= 16;
			}
		}
	}

}





