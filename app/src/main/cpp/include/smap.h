#pragma once

#include <stdio.h>
#include <string>
#include <unistd.h>

namespace StatsMap {
struct SmapsEntry {
  int64_t size_kb = -1;
  int64_t private_dirty_kb = -1;
  int64_t swap_kb = -1;
  std::string pathname;
};
struct SmapsParserState {
  bool parsed_header = false;
  SmapsEntry current_entry{};
};

template <typename T> static bool ParseSmaps(FILE *f, T callback);
static inline const char *FindNthToken(const char *line, size_t n, size_t size);

template <typename T>
static bool ParseSmapsLine(char *line, size_t size, SmapsParserState *state,
                           T callback);

SmapsEntry DetectInjection(std::string lib);
} // namespace StatsMap
