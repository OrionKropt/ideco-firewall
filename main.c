
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>

typedef uint16_t port;

enum protocol {TCP = 6, UDP = 17};

struct data_base
{
  
};

struct packet
{
  struct in_addr ip_src;
  struct in_addr ip_des;
  port port_src;
  port port_des;
  enum  protocol prot;
};


uint8_t read_packet(struct packet* pack);

uint32_t get_bin_ip(const char* str); 

char* get_standart_ip(const uint32_t ip);

int main(void)
{
  struct packet pack = {0};
  read_packet(&pack);
  return 0;
}


uint8_t read_packet(struct packet  *pack)
{
  
  uint8_t buf[4] ={0};
  
  scanf("%hhu.%hhu.%hhu.%hhu", &buf[0], &buf[1], &buf[2], &buf[3]);
  
  pack->ip_src.s_addr |= ((uint32_t) (buf[0] << 24));
  pack->ip_src.s_addr |= ((uint32_t) (buf[1] << 16));
  pack->ip_src.s_addr |= ((uint32_t) (buf[2] << 8));
  pack->ip_src.s_addr |= (uint32_t) buf[3];

  scanf("%hhu.%hhu.%hhu.%hhu", &buf[0], &buf[1], &buf[2], &buf[3]);
  
  pack->ip_des.s_addr |= ((uint32_t) (buf[0] << 24));
  pack->ip_des.s_addr |= ((uint32_t) (buf[1] << 16));
  pack->ip_des.s_addr |= ((uint32_t) (buf[2] << 8));
  pack->ip_des.s_addr |= (uint32_t) buf[3];

  scanf("%hhu %hhu %hhu", &buf[0], &buf[1], &buf[2]);

  pack->port_src = buf[0];
  pack->port_des = buf[1];
  pack->prot = buf[2]; 

  return 0;
}

