/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "tcpecho.h"
#include "decrypt.h"
#include "lwip/igmp.h"
#include "lwip/sockets.h"
#include "lwip/opt.h"
#include "lwip/tcp.h"
#include <string.h>
#include <stdio.h>
#include "ECC/uECC.h"

#if LWIP_NETCONN

#include "lwip/sys.h"
#include "lwip/api.h"

/*-----------------------------------------------------------------------------------*/

//Client 10.1.1.2 12345
//Server 10.1.1.2 54321
static struct netconn *server_conn;
static int server_connected = 0;
static struct netconn *client_conn;
static int client_connected = 0;

static byte* key_packet;
static uint8_t *ecc_pri_key;
static uint8_t *ecc_pub_key;
static const struct uECC_Curve_t *curve;



static void
tcpecho_thread_client(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 54321);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 7);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */
  netconn_listen(conn);
  init_key(ecc_pri_key,ecc_pub_key);


  while (1) {

    /* Grab new connection. */
    err = netconn_accept(conn, &client_conn);
    client_connected = 1;

    /* Process the new connection. */
    if (err == ERR_OK) {
      struct netbuf *buf;
        byte *data;
        u16_t len;

        while ((err = netconn_recv(client_conn, &buf)) == ERR_OK) {
          do {
            netbuf_data(buf, &data, &len);

            if(server_connected == 1)
            {
              switch(read_control_byte(data, len))
              {
              case 0:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                  break;
              case 1:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                  break;
              case 2:
                  err = netconn_write(server_conn, data, len, NETCONN_COPY);
                  break;
              case 3:
                curve = uECC_secp256k1();
                ecc_pub_key = (byte*)malloc(64 * sizeof(byte));
                ecc_pri_key = (byte*)malloc(32 * sizeof(byte));
                uECC_make_key(ecc_pub_key, ecc_pri_key, curve);
                //Send ECC Public Key

                key_packet = (byte*)malloc(65*sizeof(byte));
                key_packet[0] = 1;
                int i;
                for(i = 0;i < 64;i++)
                {
                  key_packet[i+1] = ecc_pub_key[i];
                }

                err = netconn_write(server_conn, key_packet, 65, NETCONN_COPY);
                free(key_packet);
                break;
              case 4:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 5:
                err = netconn_write(server_conn, data, len, NETCONN_COPY);
                break;
              case 6:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 7:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 9:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              }


            }


           } while (/*netbuf_next(buf) >= 0*/ 0);
                  netbuf_delete(buf);
        }
        netconn_close(client_conn);
        netconn_delete(client_conn);
        client_connected = 0;
    }

  }
}

static void
tcpecho_thread_server(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 12345);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 7);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */
  netconn_listen(conn);
  init_key(ecc_pri_key,ecc_pub_key);


  while (1) {

    /* Grab new connection. */
    err = netconn_accept(conn, &server_conn);
    server_connected = 1;

    /* Process the new connection. */
    if (err == ERR_OK) {
      struct netbuf *buf;
        byte *data;
        u16_t len;

        while ((err = netconn_recv(server_conn, &buf)) == ERR_OK) {
          do {
            netbuf_data(buf, &data, &len);
            byte *sig = (byte*)malloc(32 *sizeof(byte));

            if(client_connected == 1)
            {
              switch(read_control_byte(data, len))
              {
              case 0:
                //Check Mac

                if(check_hmac(data, len, sig) == 1)
                {
                  //Mac Error
                  data[0] = '9';
                  err = netconn_write(client_conn, data, len, NETCONN_COPY);
                }
                else
                {
                  split_package((data + 1), len - 1 -32);
                  err = netconn_write(client_conn, data, len, NETCONN_COPY);
                }
                  break;
              case 1:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                  break;
              case 2:
                  err = netconn_write(client_conn, data, len, NETCONN_COPY);
                  break;
              case 3:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 4:
                generate_key(data+1, 64, ecc_pri_key);
                break;
              case 5:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 6:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 7:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;
              case 9:
                err = netconn_write(client_conn, data, len, NETCONN_COPY);
                break;

              }


            }
            free(sig);

           } while (/*netbuf_next(buf) >= 0*/ 0);
                  netbuf_delete(buf);
        }
        netconn_close(server_conn);
        netconn_delete(server_conn);
        server_connected = 0;
    }

  }
}

static void
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);

  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 8888);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 7);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */
  netconn_listen(conn);
  //init_key(ecc_pri_key, ecc_pub_key);


  while (1) {

    /* Grab new connection. */
    err = netconn_accept(conn, &newconn);


    /* Process the new connection. */
    if (err == ERR_OK) {
      struct netbuf *buf;
        void *data;
        u16_t len;

        while ((err = netconn_recv(newconn, &buf)) == ERR_OK) {
          do {
            netbuf_data(buf, &data, &len);

            err = netconn_write(newconn, data, len, NETCONN_COPY);


           } while (netbuf_next(buf) >= 0);
                  netbuf_delete(buf);
        }
        netconn_close(newconn);
        netconn_delete(newconn);
    }

  }
}
/*-----------------------------------------------------------------------------------*/
void
tcpecho_init(void)
{
  sys_thread_new("tcpecho_thread_server", tcpecho_thread_server, NULL, DEFAULT_THREAD_STACKSIZE, tskIDLE_PRIORITY + 1 +1);
  sys_thread_new("tcpecho_thread_client", tcpecho_thread_client, NULL, DEFAULT_THREAD_STACKSIZE, tskIDLE_PRIORITY + 1 +2);
  sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, tskIDLE_PRIORITY + 1 +1);
}
/*-----------------------------------------------------------------------------------*/

#endif /* LWIP_NETCONN */
