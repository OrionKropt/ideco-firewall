#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>

#include "packet.h"
#include "list.h"



uint8_t read_packet(struct packet* pack, uint8_t is_read_file, FILE *f);

uint8_t cheack_packet(const struct packet* pack, const struct rule* rl);

void print_packet(const struct packet *pack);

char* get_standart_ip(const uint32_t ip);

enum protocol pars_type_protocol(const char* prot);

struct node* read_data_base_from_file();

int main(int argc, char** argv)
{
  struct node* data_base;
  uint8_t is_read_file = 0;
  struct packet *pack = NULL;
  FILE* f = NULL;

  data_base = read_data_base_from_file();
  if (data_base == NULL)
  {
    printf("Can't read data_base\n");
    return 0;
  }

  if (argc > 1)
  {
    if(!strcmp(argv[1], "file"))
      is_read_file = 1;
  }

  if (is_read_file)
  {
    f = fopen("tests.txt", "r");
    if (f == NULL)
    {
      printf("Can't open tests.txt\n");
      return 0;
    }
    char ch[8];
    fscanf(f, "%s", ch);
  }

  pack = malloc(sizeof(struct packet));
  memset(pack, 0, sizeof(struct packet));
  
  while (read_packet(pack, is_read_file, f))
  {
    uint8_t is_drop = 1;
    struct node *temp = data_base;

    print_packet(pack);
    
    while (temp != NULL)
    {
      if (cheack_packet(pack, &temp->rl))
      {
        printf("%s\n", temp->rl.response);
        is_drop = 0;
        break;
      }
      temp = temp->next;
    }
    
    if (is_drop)  printf("DRPOP\n");

    memset(pack, 0, sizeof(struct packet));
  }

  if (is_read_file)
    fclose(f);
  return 0;
}


uint8_t read_packet(struct packet  *pack, uint8_t is_read_file, FILE* f)
{
  uint8_t u8_buf[8] = {0};  
  uint32_t u32_buf[4] = {0};
  
  if (is_read_file)
    fscanf(f, "%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  else
    scanf("%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);

  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[0] << 24));
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[1] << 16));
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[2] << 8));
  pack->ip_src.s_addr |= (uint32_t) u8_buf[3];
  pack->mask_src |= (uint32_t) (~pack->mask_src) << (32 - u8_buf[4]);
  
  memset(u8_buf, 0, sizeof(uint8_t) * 8);

  if (is_read_file)
    fscanf(f, "%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  else
    scanf("%hhu.%hhu.%hhu.%hhu/%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3], &u8_buf[4]);
  
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[0] << 24));
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[1] << 16));
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[2] << 8));
  pack->ip_des.s_addr |= (uint32_t) u8_buf[3];
  pack->mask_des |= (uint32_t) (~pack->mask_des) << (32 - u8_buf[4]);

   if (is_read_file)
   {
      if (fscanf(f, "%u %u %u", &u32_buf[0], &u32_buf[1], &u32_buf[2]) == EOF)
      return 0;   
   }
   else
   {
      scanf("%u %u %u", &u32_buf[0], &u32_buf[1], &u32_buf[2]);
      if (u32_buf[2] == 0) return 0;
   }
  pack->port_src = u32_buf[0];
  pack->port_des = u32_buf[1];
  pack->prot = u32_buf[2]; 

  return 1;
}


uint8_t cheack_packet(const struct packet* pack, const struct rule* rl)
{
  if (rl->pack.ip_src.s_addr)
  {
     if ((rl->pack.ip_src.s_addr & rl->pack.mask_src) != (pack->ip_src.s_addr & pack->mask_src))
      return 0;
  }
  
  if (rl->pack.ip_des.s_addr)
  {
    if ((rl->pack.ip_des.s_addr & rl->pack.mask_des) != (pack->ip_des.s_addr & pack->mask_des))
      return 0;
  }

  if (rl->pack.prot)
  {
    if (rl->pack.prot != pack->prot)
      return 0;
  }
   
  return 1;
}

void print_packet(const struct packet *pack)
{
  char* ip_src = get_standart_ip((pack->ip_src.s_addr));
  char* ip_des = get_standart_ip((pack->ip_des.s_addr));
  uint8_t mask_src = __builtin_popcount(pack->mask_src);
  uint8_t mask_des = __builtin_popcount(pack->mask_des);
  
  printf("packet: %s", ip_src);
  if (mask_src != 32)
    printf("/%hhu ", mask_src);
  else printf(" ");
  
  printf("%s", ip_des);
  if (mask_des != 32)
    printf("/%hhu ", mask_des);
  else printf(" ");
  
  printf("%d => ", pack->prot);
  free(ip_src);
  free(ip_des);
}

char* get_standart_ip(const uint32_t ip)
{
  char *ch_ip = malloc(sizeof(char) * 32);
  uint8_t buf[4];
  
  buf[0] = (uint8_t) (ip >> 24);
  buf[1] = (uint8_t) (ip >> 16);
  buf[2] = (uint8_t) (ip >> 8);
  buf[3] = (uint8_t) (ip); 
  sprintf(ch_ip, "%hhu.%hhu.%hhu.%hhu", buf[0], buf[1], buf[2], buf[3]);
  return ch_ip;
}

enum protocol pars_type_protocol(const char* prot)
{
  if (!strcmp(prot, "tcp")) return TCP;
  
  else if (!strcmp(prot, "udp")) return UDP;

  else if (!strcmp(prot, "ftp")) return FTP;

  else if (!strcmp(prot, "ntp")) return NTP;

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
    memset(u8_buf, 0, 8);
    
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
    }
 } 
  

  fclose(f);
  return head;
}
