#include "list.h"
#include <stdlib.h>

#include <stdio.h>
void push_back(struct node **head, const struct rule *rl)
{
  if (*head == NULL)
  {
    printf("new head\n");
    *head = malloc(sizeof(struct node));
    (*head)->rl = *rl;
    (*head)->next = NULL;
    return;
  }
  
  struct node *temp = *head;
  while (temp->next != NULL)
  {
    temp = temp->next;
  }
  
  
    temp->next = malloc(sizeof(struct node));
    temp->next->rl = *rl;
    temp->next->next = NULL;
}
