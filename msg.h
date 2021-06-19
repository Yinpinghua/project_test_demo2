#ifndef msg_h__
#define msg_h__

#include <string>

enum MSG_OFFSET
{
	BODY_OFFSET =0,
	CMD_OFFSET =4,
	HEADER_OFFSET = 6,
};

typedef uint32_t Body_Size;
typedef uint16_t Cmd_size;
typedef uint32_t Ip_type;

#endif // msg_h__
