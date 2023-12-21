#include <stdint.h>

uint8_t myethaddr[] = {0x08, 0x00, 0x27, 0x87, 0x22, 0x2c};
uint8_t myipaddr[] = {10, 0, 2, 4};

uint8_t myrouterip[] = {10, 0, 2, 1};
uint8_t *myroutereth;
uint8_t mynetmask[] = {255, 255, 255, 0};

uint8_t *targetip;
uint8_t *targeteth;

uint8_t defarpip[] = {10, 0, 2, 1};
uint8_t defpingip[] = {140, 127, 208, 18};

uint8_t defdnsip[] = {8, 8, 8, 8};
char* defdnsquery = "www.google.com.tw";

uint16_t tcp_filter_port = 0x0050; // port 80

uint8_t start_attack = 0x00;