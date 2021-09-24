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

#include "lwip/igmp.h"
#include "lwip/opt.h"
#include "lwip/udp.h"
#include "lwip/sockets.h"
#include "udpecho.h"
#include "decrypt.h"
#include <string.h>
#include <stdio.h>

#if LWIP_NETCONN

#include "lwip/api.h"
#include "lwip/sys.h"

/*-----------------------------------------------------------------------------------*/
static char buffer[4096];



static void
udpecho_thread(void *arg)
{
  struct netconn *conn;
  struct netbuf *buf;
  err_t err;
  LWIP_UNUSED_ARG(arg);

#if LWIP_IPV6
  conn = netconn_new(NETCONN_UDP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 12345);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_UDP);
  netconn_bind(conn, IP_ADDR_ANY, 12345);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("udpecho: invalid conn", (conn != NULL), return;);

  while (1) {
    err = netconn_recv(conn, &buf);
    if (err == ERR_OK) {
      if(netbuf_copy(buf, buffer, sizeof(buffer)) != buf->p->tot_len) {
        LWIP_DEBUGF(LWIP_DBG_ON, ("netbuf_copy failed\n"));
      }

      /*  no need netconn_connect here, since the netbuf contains the address */
      else
      {
#if LWIP_IPV6
      if (buf->p->tot_len == 24 && !strncmp(&buffer[0], "MLD6", 4))
      {
        /*Already set the IP address of the group using IP address contain in the message*/
        ip_addr_t gaddr;
        IP_ADDR6(&gaddr, *((u32_t*)(&buffer[8])), *((u32_t*)(&buffer[12])), *((u32_t*)(&buffer[16])), *((u32_t*)(&buffer[20])));

        if (!strncmp(&buffer[4], "JOIN", 4)) /*if message is join*/
        {
          err = netconn_join_leave_group(conn, &gaddr, IP_ADDR_ANY, NETCONN_JOIN);  /*called join group function with group include in the message */
          if(err != ERR_OK)
          {
            LWIP_DEBUGF(LWIP_DBG_ON, ("function netconn_join_leave_group failed %d\n", (int)err));
          }
        }
        if (!strncmp(&buffer[4], "LEAV", 4)) /*if message is leav*/
        {
          err = netconn_join_leave_group(conn, &gaddr,IP_ADDR_ANY, NETCONN_LEAVE);   /*called leave, group function with group include in the message */
          if(err != ERR_OK)
          {
            LWIP_DEBUGF(LWIP_DBG_ON, ("function netconn_join_leave_group failed %d\n", (int)err));
          }
        }
      }
#endif /*LWIP_IPV6*/
#if LWIP_IGMP
     if (buf->p->tot_len == 12 && !strncmp(&buffer[0], "IGMP", 4))
     {
        /*Already set the IP address of the group using IP address contain in the message*/
        ip_addr_t gaddr;
        IP_ADDR4(&gaddr, buffer[8], buffer[9], buffer[10], buffer[11]);
        if (!strncmp(&buffer[4], "JOIN", 4)) /*if message is join*/
        {
          err = netconn_join_leave_group(conn,&gaddr,IP_ADDR_ANY,NETCONN_JOIN);  /*called join group function with group include in the message */
          if(err != ERR_OK)
          {
            LWIP_DEBUGF(LWIP_DBG_ON, ("function igmp_joingroup failed %d\n", (int)err));
          }
        }
        if (!strncmp(&buffer[4], "LEAV", 4)) /*if message is leav*/
        {
          err = netconn_join_leave_group(conn,&gaddr,IP_ADDR_ANY,NETCONN_LEAVE);   /*called leave, group function with group include in the message */
          if(err != ERR_OK)
          {
                          LWIP_DEBUGF(LWIP_DBG_ON, ("function igmp_leavegroup failed %d\n", (int)err));
          }
        }
      }
#endif /*LWIP_IGMP*/
        //buffer[buf->p->tot_len] = '\0';

        int s;
        int ret;
        int buffer_length = buf->p->tot_len;
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_len = sizeof(addr);
        addr.sin_family = 2;
        addr.sin_port = 12345;
        ip4addr_aton((const char*)"10.1.1.2", &addr.sin_addr);
        s = lwip_socket(2, 2, 0);

        byte *data;
        int data_size = buffer_length;
        data = (byte*)malloc(data_size);
        memcpy(data, &buffer , data_size);
        split_package(data_size, data);



        ret = lwip_sendto(s, data, data_size, 0, (struct sockaddr*)&addr, sizeof(addr));
        ret = lwip_close(s);

        free(data);

        /*
        buf->port = 12345;
        ip4addr_aton((const char*)"10.1.1.2", &buf->addr);
        err = netconn_send(conn, buf);
        */






			if(err != ERR_OK)
			{
			  LWIP_DEBUGF(LWIP_DBG_ON, ("netconn_send failed: %d\n", (int)err));
			}
			else
			{
			  LWIP_DEBUGF(LWIP_DBG_ON, ("got %s\n", buffer));
        }
      }

      netbuf_delete(buf);
    }
  }
}

/*-----------------------------------------------------------------------------------*/
void
udpecho_init(void)
{
  sys_thread_new("udpecho_thread", udpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}

#endif /* LWIP_NETCONN */
