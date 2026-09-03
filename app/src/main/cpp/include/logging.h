#pragma once

#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <errno.h>
#include <string>

#ifndef LOG_TAG
#define LOG_TAG "Demo"
#endif

#ifndef NDEBUG
#define LOGD(...) logging::log(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGV(...) logging::log(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#else
#define LOGD(...)
#define LOGV(...)
#endif
#define LOGI(...) logging::log(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) logging::log(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) logging::log(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGF(...) logging::log(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
#define PLOGE(fmt, args...)                                                    \
  LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))

namespace logging {
// In-process capture so a caller (e.g. integrity.cpp) can return the raw detection
// log to the UI. Every log() below appends to it, so a caller that wants a single
// run's log must clear() first -- and one that never reads it lets it grow.
inline std::string &capture() {
  static std::string buf;
  return buf;
}
inline void log(int prio, const char *tag, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  char line[2048];
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  __android_log_print(prio, tag, "%s", line);
  capture().append(line).append("\n");
}
} // namespace logging
