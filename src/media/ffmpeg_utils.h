// Copyright (c) 2016 Alexandr Topilski. All rights reserved.

#pragma once

#define ERROR_RESULT_VALUE -1
#define SUCCESS_RESULT_VALUE 1

#define CALC_FFMPEG_VERSION(a,b,c) ( a<<16 | b<<8 | c )

typedef enum log_level_t {
    LOG_MSG = 0,
    LOG_WARNING,
    LOG_ERROR,
    LOG_CRITICAL_ERROR
} log_level_t;

void set_log_level(log_level_t level);
void debug_msg(const char *format, ...);
void debug_warning(const char *format, ...);
void debug_error(const char *format, ...);
void debug_critical_error(const char *format, ...);
void debug_critical_notify(const char *format, ...);
void debug_perror(const char *function, int err);
void debug_perror_arg(const char *function, const char *arg, int err);
void debug_av_perror(const char* function, int err);
