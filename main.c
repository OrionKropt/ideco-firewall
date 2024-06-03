#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <string.h>

#include "packet.h"
#include "list.h"



uint8_t read_packet(struct packet *pack, FILE *f);
uint8_t check_packet(const struct packet* pack, const struct rule* rl);
void print_packet(const struct packet *pack);
void verdict(char *str, enum response resp); 
void ip_to_str(char *str, const uint32_t ip);
enum protocol parse_type_protocol(const char* prot);
enum response parse_verdict(const char* verd);
struct node* read_data_base_from_file();

int main(int argc, char** argv)
{
  struct node* data_base;
  char *verd = malloc(sizeof(char) * 16);
  struct packet *pack = NULL;
  FILE* f = stdin;
  
  data_base = read_data_base_from_file();

  if (data_base == NULL)
  {
    printf("Can't read database\n");
    return 0;
  }

  if (argc > 1)
  {
    if(!strcmp(argv[1], "file"))
      {
        f = fopen("tests.txt", "r");
        if (f == NULL)
        {
          printf("Can't open file tests.txt: %s\n", strerror(errno));
          return 0;
        }
      }
  }

  pack = malloc(sizeof(struct packet));
  memset(pack, 0, sizeof(struct packet));
  
  while (read_packet(pack, f))
  {
    uint8_t is_drop = 1;
    struct node *temp = data_base;
    
    print_packet(pack);
    
    while (temp != NULL)
    {
      if (check_packet(pack, &temp->rl))
      {
        verdict(verd, temp->rl.resp);
        printf("%s\n", verd);
        is_drop = 0;
        break;
      }
      temp = temp->next;
    }
    
    if (is_drop)  printf("DRPOP\n");
    memset(pack, 0, sizeof(struct packet));
 }

  if (f != stdin)
    fclose(f);
  
  return 0;
}


uint8_t read_packet(struct packet  *pack, FILE *f)
{
  uint8_t u8_buf[4] = {0};  
  uint32_t u32_buf[4] = {0};
  int8_t res = 0;
  res = fscanf(f, "%hhu.%hhu.%hhu.%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3]);
       
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[0] << 24));
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[1] << 16));
  pack->ip_src.s_addr |= ((uint32_t) (u8_buf[2] << 8));
  pack->ip_src.s_addr |= (uint32_t) u8_buf[3];
  
  memset(u8_buf, 0, sizeof(uint8_t) * 4);

  res = fscanf(f, "%hhu.%hhu.%hhu.%hhu", &u8_buf[0], &u8_buf[1], &u8_buf[2], &u8_buf[3]);
     
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[0] << 24));
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[1] << 16));
  pack->ip_des.s_addr |= ((uint32_t) (u8_buf[2] << 8));
  pack->ip_des.s_addr |= (uint32_t) u8_buf[3];

  res = fscanf(f, "%u %u %u", &u32_buf[0], &u32_buf[1], &u32_buf[2]);

  if (res == EOF)
    return 0;   
  
  pack->port_src = u32_buf[0];
  pack->port_des = u32_buf[1];
  pack->prot = u32_buf[2]; 

  return 1;
}


uint8_t check_packet(const struct packet* pack, const struct rule* rl)
{
  if (rl->pack.ip_src.s_addr)
  {
     if ((rl->pack.ip_src.s_addr & rl->pack.mask_src) != pack->ip_src.s_addr)
      return 0;
  }
  
  if (rl->pack.ip_des.s_addr)
  {
    if ((rl->pack.ip_des.s_addr & rl->pack.mask_des) != pack->ip_des.s_addr)
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
  char ip_src[32] = {0};
  char ip_des[32] = {0};
 
  ip_to_str(ip_src, pack->ip_src.s_addr);
  ip_to_str(ip_des, pack->ip_des.s_addr);
  
  printf("packet: %s %s %d => ", ip_src, ip_des, pack->prot);
}

void verdict(char *str, enum response resp)
{
  if (resp == ACCEPT) strcpy(str, "ACCEPT");
  else if (resp == DROP) strcpy(str, "DROP");
  else strcpy(str, "UNDEFINED RESPONSE");
}

void ip_to_str(char *str, const uint32_t ip)
{
  uint8_t buf[4];
  buf[0] = (uint8_t) (ip >> 24);
  buf[1] = (uint8_t) (ip >> 16);
  buf[2] = (uint8_t) (ip >> 8);
  buf[3] = (uint8_t) (ip); 
  sprintf(str, "%hhu.%hhu.%hhu.%hhu", buf[0], buf[1], buf[2], buf[3]);
}

enum protocol parse_type_protocol(const char* prot)
{
  if (!strcmp(prot, "tcp")) return TCP;
  if (!strcmp(prot, "udp")) return UDP;
  if (!strcmp(prot, "ftp")) return FTP;
  if (!strcmp(prot, "ntp")) return NTP;
  return UNDEFINED;
}

enum response parse_verdict(const char* verd)
{
  if (!strcmp(verd, "ACCEPT")) return ACCEPT;
  if (!strcmp(verd, "DROP")) return DROP;
  return UNDEFINED_RESPONSE;  
}

struct node* read_data_base_from_file()
{
  struct node* head = NULL;
  struct rule* rl = NULL;
  FILE* f = fopen("data_base.txt", "r");
 
  if (f == NULL)
  {
    printf("Can't open file data_base.txt: %s\n", strerror(errno));
    return NULL;
  }
  
  uint8_t u8_buf[8] = {0};  
  char buf[8] = {0};
  uint8_t new_rl = 1;

  while (fscanf(f, "%s", buf) != EOF)
  {
    memset(u8_buf, 0, sizeof(uint8_t) * 8);
    
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
      rl->pack.prot = parse_type_protocol(buf);
    }
    else if (!strcmp(buf, "=>"))
    {
      fscanf(f, "%s", buf);
      rl->resp = parse_verdict(buf);    
      new_rl = 1;
      push_back(&head, rl);
    }
 } 
  
  fclose(f);
  return head;
}
