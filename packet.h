#pragma once

#include <netinet/in.h>

enum protocol {UNDEFINED = 0, TCP = 6, UDP = 17 };

struct packet
{
  struct in_addr ip_src;
  struct in_addr ip_des;
  uint32_t mask_src;
  uint32_t mask_des;
  in_port_t port_src;
  in_port_t port_des;
  enum  protocol prot;
};

 
