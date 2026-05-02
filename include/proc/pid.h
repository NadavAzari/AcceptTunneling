#ifndef PROC_PID_H
#define PROC_PID_H

#include <stdint.h>
#include <sys/types.h>

pid_t proc_pid_for_port(uint16_t port);

#endif
