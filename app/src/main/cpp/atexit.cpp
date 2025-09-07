#include "atexit.hpp"

#include "elf_util.h"
#include "logging.h"

template <typename T>
inline T *getExportedFieldPointer(const SandHook::ElfImg &libc,
                                  const char *name) {
  auto *addr = reinterpret_cast<T *>(libc.getSymbAddress(name));

  return addr == nullptr ? nullptr : addr;
}

namespace Atexit {

bool AtexitArray::append_entry(const AtexitEntry &entry) {
  if (size_ >= capacity_ && !expand_capacity())
    return false;

  size_t idx = size_++;

  set_writable(true, idx, 1);
  array_[idx] = entry;
  ++total_appends_;
  set_writable(false, idx, 1);

  return true;
}
// Extract an entry and return it.
AtexitEntry AtexitArray::extract_entry(size_t idx) {
  AtexitEntry result = array_[idx];

  set_writable(true, idx, 1);
  array_[idx] = {};
  ++extracted_count_;
  set_writable(false, idx, 1);

  return result;
}

void AtexitArray::recompact() {
  if (!needs_recompaction()) {
    LOGD("needs_recompaction returns false");
    // return;
  }

  set_writable(true, 0, size_);

  // Optimization: quickly skip over the initial non-null entries.
  size_t src = 0, dst = 0;
  while (src < size_ && array_[src].fn != nullptr) {
    ++src;
    ++dst;
  }

  // Shift the non-null entries forward, and zero out the removed entries at the
  // end of the array.
  for (; src < size_; ++src) {
    const AtexitEntry entry = array_[src];
    array_[src] = {};
    if (entry.fn != nullptr) {
      array_[dst++] = entry;
    }
  }

  // If the table uses fewer pages, clean the pages at the end.
  size_t old_bytes = page_end_of_index(size_);
  size_t new_bytes = page_end_of_index(dst);
  if (new_bytes < old_bytes) {
    madvise(reinterpret_cast<char *>(array_) + new_bytes, old_bytes - new_bytes,
            MADV_DONTNEED);
  }

  set_writable(false, 0, size_);

  size_ = dst;
  extracted_count_ = 0;
}

// Use mprotect to make the array writable or read-only. Returns true on
// success. Making the array read-only could protect against either
// unintentional or malicious corruption of the array.
void AtexitArray::set_writable(bool writable, size_t start_idx,
                               size_t num_entries) {
  if (array_ == nullptr)
    return;

  const size_t start_byte = page_start_of_index(start_idx);
  const size_t stop_byte = page_end_of_index(start_idx + num_entries);
  const size_t byte_len = stop_byte - start_byte;

  const int prot = PROT_READ | (writable ? PROT_WRITE : 0);
  if (mprotect(reinterpret_cast<char *>(array_) + start_byte, byte_len, prot) !=
      0) {
    PLOGE("mprotect failed on atexit array: %m");
  }
}

// Approximately double the capacity. Returns true if successful (no overflow).
// AtexitEntry is smaller than a page, but this function should still be correct
// even if AtexitEntry were larger than one.
bool AtexitArray::next_capacity(size_t capacity, size_t *result) {
  if (capacity == 0) {
    *result = page_end(sizeof(AtexitEntry)) / sizeof(AtexitEntry);
    return true;
  }
  size_t num_bytes;
  if (__builtin_mul_overflow(page_end_of_index(capacity), 2, &num_bytes)) {
    PLOGE("__cxa_atexit: capacity calculation overflow");
    return false;
  }
  *result = num_bytes / sizeof(AtexitEntry);
  return true;
}

bool AtexitArray::expand_capacity() {
  size_t new_capacity;
  if (!next_capacity(capacity_, &new_capacity))
    return false;
  const size_t new_capacity_bytes = page_end_of_index(new_capacity);

  set_writable(true, 0, capacity_);

  bool result = false;
  void *new_pages;
  if (array_ == nullptr) {
    new_pages = mmap(nullptr, new_capacity_bytes, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  } else {
    // mremap fails if the source buffer crosses a boundary between two VMAs.
    // When a single array element is modified, the kernel should split then
    // rejoin the buffer's VMA.
    new_pages = mremap(array_, page_end_of_index(capacity_), new_capacity_bytes,
                       MREMAP_MAYMOVE);
  }
  if (new_pages == MAP_FAILED) {
    PLOGE("__cxa_atexit: mmap/mremap failed to allocate %zu bytes: %m",
          new_capacity_bytes);
  } else {
    result = true;
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, new_pages, new_capacity_bytes,
          "atexit handlers");
    array_ = static_cast<AtexitEntry *>(new_pages);
    capacity_ = new_capacity;
  }
  set_writable(false, 0, capacity_);
  return result;
}

AtexitArray *findAtexitArray() {
  SandHook::ElfImg libc("libc.so");
  auto p_array = getExportedFieldPointer<AtexitEntry *>(libc, "_ZL7g_array.0");
  auto p_size = getExportedFieldPointer<size_t>(libc, "_ZL7g_array.1");
  auto p_extracted_count =
      getExportedFieldPointer<size_t>(libc, "_ZL7g_array.2");
  auto p_capacity = getExportedFieldPointer<size_t>(libc, "_ZL7g_array.3");
  auto p_total_appends =
      getExportedFieldPointer<uint64_t>(libc, "_ZL7g_array.4");

  if (p_array == nullptr || p_size == nullptr || p_extracted_count == nullptr ||
      p_capacity == nullptr || p_total_appends == nullptr) {
    LOGD("failed to find exported g_array fields in memory");
    return nullptr;
  }

  return reinterpret_cast<AtexitArray *>(p_array);
}

} // namespace Atexit
