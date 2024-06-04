#pragma once

#include <stdint.h>
#include "packet.h"

enum response {
  UNDEFINED_RESPONSE = 0,
  ACCEPT = 1,
  DROP
};

struct rule
{
  struct in_addr ip_src;
  struct in_addr ip_des;
  enum  protocol prot;
  uint32_t mask_src;
  uint32_t mask_des;
  enum response resp;
};

struct node
{
  struct node* next;
  struct rule rl;  
};

void push_back(struct node **head, const struct rule *rl);
