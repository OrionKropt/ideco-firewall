#pragma once
#include "packet.h"

enum response {
  UNDEFINED_RESPONSE = 0,
  ACCEPT = 1,
  DROP
};

struct rule
{
  struct packet pack;
  enum response resp;
};

struct node
{
  struct node* next;
  struct rule rl;  
};

void push_back(struct node **head, const struct rule *rl);
