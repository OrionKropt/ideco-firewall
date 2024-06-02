#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>

#include "packet.h"
#include "list.h"



uint8_t read_packet(struct packet* pack);

uint32_t get_bin_ip(const char* str); 

void get_standart_ip(const uint32_t ip, char *ch_ip);

enum protocol pars_type_protocol(const char* prot);

struct node* read_data_base_from_file();

int main(void)
{
  struct node* data_base;
  
//  struct packet pack = {0};
  
  data_base = read_data_base_from_file();
  if (data_base == NULL)
  {
    printf("Can't read data_base\n");
    return 0;
  }

  struct node *temp = data_base;
  char* str = malloc(sizeof(char) * 32);
  printf("%s\n", data_base->next->rl.response);
  while (temp != NULL)
  {
    get_standart_ip(temp->rl.pack.ip_src.s_addr, str);
    
    printf("%s %s\n", str, temp->rl.response);
        
    temp = temp->next;
  }


  //read_packet(&pack);
  //printf("%d\n", pack.mask_src);
  //printf("%d\n", pack.mask_des);
  return 0;
}


uint8_t read_packet(struct packet  *pack)
{
  
  uint8_t u8_buf[8] = {0};  
  uint32_t u32_buf[4] = {0};
  scanf("%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[0] << 24));
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[1] << 16));
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[2] << 8));
  pack->ip_src.s_addr |= (uint32_t) u8_buf[3];
  pack->mask_src |= (uint32_t) (~pack->mask_src) << (32 - u8_buf[4]);
  

  memset(u8_buf, 0, sizeof(uint8_t) * 8);
  scanf("%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[0] << 24));
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[1] << 16));
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[2] << 8));
  pack->ip_des.s_addr |= (uint32_t) u8_buf[3];
  pack->mask_des |= (uint32_t) (~pack->mask_des) << (32 - u8_buf[4]);
  
  scanf("%u %u %u", &u32_buf[0], &u32_buf[1], &u32_buf[2]);

  pack->port_src = u32_buf[0];
  pack->port_des = u32_buf[1];
  pack->prot = u32_buf[2]; 

  return 0;
}

void get_standart_ip(const uint32_t ip, char *ch_ip)
{
  uint8_t buf[4];
  
  buf[0] = (uint8_t) (ip >> 24);
  buf[1] = (uint8_t) (ip >> 16);
  buf[2] = (uint8_t) (ip >> 8);
  buf[3] = (uint8_t) (ip); 
  sprintf(ch_ip, "%hhu.%hhu.%hhu.%hhu", buf[0], buf[1], buf[2], buf[3]);
  
}

enum protocol pars_type_protocol(const char* prot)
{
  if (!strcmp(prot, "tcp")) return TCP;
  
  else if (!strcmp(prot, "udp")) return UDP;

  else return UNDEFINED;
}

struct node* read_data_base_from_file()
{
  struct node* head = NULL;
  struct rule* rl = NULL;
  FILE* f = fopen("data_base.txt", "r");
  if (f == NULL)
  {
    printf("Can't open file data_base.txt\n");
    return NULL;
  }
  
  uint8_t u8_buf[8] = {0};  
  char buf[8];
  uint8_t new_rl = 1;
  while (fscanf(f, "%s", buf) != EOF)
  {
   //printf("%s\n", buf);
    if (new_rl)
      {
        rl = malloc(sizeof(struct rule));
        new_rl = 0;
      }
    if (!strcmp(buf, "src:"))
    {
      
  fscanf(f, "%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  
    rl->pack.ip_src.s_addr |= ((uint32_t) (u8_buf[0] << 24));
    rl->pack.ip_src.s_addr |= ((uint32_t) (u8_buf[1] << 16));
    rl->pack.ip_src.s_addr |= ((uint32_t) (u8_buf[2] << 8));
    rl->pack.ip_src.s_addr |= ((uint32_t) u8_buf[3]);
    rl->pack.mask_src |= (uint32_t) (~rl->pack.mask_src) << (32 - u8_buf[4]);
    }
    else if (!strcmp(buf, "dst:"))
    {
      
  fscanf(f, "%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  
    rl->pack.ip_des.s_addr |= ((uint32_t) (u8_buf[0] << 24));
    rl->pack.ip_des.s_addr |= ((uint32_t) (u8_buf[1] << 16));
    rl->pack.ip_des.s_addr |= ((uint32_t) (u8_buf[2] << 8));
    rl->pack.ip_des.s_addr |= ((uint32_t) u8_buf[3]);
    
    rl->pack.mask_des |= (uint32_t) (~rl->pack.mask_des) << (32 - u8_buf[4]);
    }
    
    else if (!strcmp(buf, "proto:"))
    {
      fscanf(f, "%s", buf);
      rl->pack.prot = pars_type_protocol(buf);
    }
    else if (!strcmp(buf, "=>"))
    {
      fscanf(f, "%s", buf);
      strcpy(rl->response,  buf);
      new_rl = 1;
      push_back(&head, rl);
      //printf("%s\n", rl->response);
    }
 } 
  printf("%s\n", head->next->rl.response);

  fclose(f);
  return head;
}
