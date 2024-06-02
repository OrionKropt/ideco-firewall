#pragma once
#include "packet.h"

struct rule
{
  struct packet pack;
  char response[16];
};

struct node
{
  struct node* next;
  struct rule rl;  
};

void push_back(struct node **head, const struct rule *rl);
