// Copyright (c) 2016 Alexandr Topilski. All rights reserved.

#include "log.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>

#ifdef WIN32
int vasprintf (char **str, const char *fmt, va_list args) {
  int size = 0;
  va_list tmpa;

  // copy
  va_copy(tmpa, args);

  // apply variadic arguments to
  // sprintf with format to get size
  size = vsnprintf(NULL, size, fmt, tmpa);

  // toss args
  va_end(tmpa);

  // return -1 to be compliant if
  // size is less than 0
  if (size < 0) { return -1; }

  // alloc with size plus 1 for `\0'
  *str = (char *) malloc(size + 1);

  // return -1 to be compliant
  // if pointer is `NULL'
  if (NULL == *str) { return -1; }

  // format string with original
  // variadic arguments and set new size
  size = vsprintf(*str, fmt, args);
  return size;
}
int asprintf (char **str, const char *fmt, ...) {
  int size = 0;
  va_list args;
  // init variadic argumens
  va_start(args, fmt);
  // format and get size
  size = vasprintf(str, fmt, args);
  // toss args
  va_end(args);
  return size;
}
#endif

namespace {

const char * log_text[] = {
  "MSG",
  "WARNING",
  "ERROR",
  "CRITICAL_ERROR"
};

fasto::log_level_t g_level = fasto::LOG_WARNING;

void dprintva(FILE * file, fasto::log_level_t level, const char * format, va_list ap) {
  struct tm stm;
  time_t etime;
  char buf[16] = {0};

  time(&etime);
#ifdef WIN32
  stm = *localtime(&etime);
#else
  localtime_r(&etime, &stm);
#endif
  strftime(buf, sizeof(buf), "%d-%b@%T", &stm);

  char * ret = NULL;
  const char * level_str = log_text[level];
  int res = asprintf(&ret, "[%s] %s : %s", level_str, buf, format);
  DCHECK_NE(res, -1);
  vfprintf(file, ret, ap);
  free(ret);
}

}  // namespace

namespace fasto {

void set_log_level(log_level_t level) {
  g_level = level;
}

void debug_msg(const char *format, ...) {
  if (g_level <= LOG_MSG) {
    va_list ap;
    va_start(ap, format);
    dprintva(stdout, LOG_MSG, format, ap);
    va_end(ap);
  }
}

void debug_warning(const char *format, ...) {
  if (g_level <= LOG_WARNING) {
    va_list ap;
    va_start(ap, format);
    dprintva(stdout, LOG_WARNING, format, ap);
    va_end(ap);
  }
}

void debug_error(const char *format, ...) {
  if (g_level <= LOG_ERROR) {
    va_list ap;
    va_start(ap, format);
    dprintva(stdout, LOG_ERROR, format, ap);
    va_end(ap);
  }
}

void debug_critical_error(const char *format, ...) {
  if (g_level <= LOG_CRITICAL_ERROR) {
    va_list ap;
    va_start(ap, format);
    dprintva(stdout, LOG_CRITICAL_ERROR, format, ap);
    va_end(ap);
  }
}

void debug_critical_notify(const char *format, ...) {
  if (g_level <= LOG_CRITICAL_ERROR) {
    va_list ap;
    va_start(ap, format);
    dprintva(stdout, LOG_CRITICAL_ERROR, format, ap);
    va_end(ap);
  }
}

void debug_perror(const char* function, int err) {
  char* strer = strerror(err);
  debug_error("Function: %s, %s\n", function, strer);
}

void debug_perror_arg(const char* function, const char* arg, int err) {
  char* strer = strerror(err);
  debug_error("Function %s with args %s failed: %s\n", function, arg, strer);
}

}  // namespace fasto
