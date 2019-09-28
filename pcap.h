#pragma once

// header size
#define DATALINK_HEADER_SIZE 14

u_char * DataLinkLayer(const u_char * packet);
u_char * NetworkLayer(const u_char * packet);
