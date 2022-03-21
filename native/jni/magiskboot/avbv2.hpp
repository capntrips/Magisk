#pragma once

#define AVB2_INVALID     (1 << 1)
#define AVB2_UNSUPPORTED (1 << 2)
#define AVB2_INVALID_KEY (1 << 3)

int avbv2_verify_sign(const char *image, const char *key, bool rw);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/test/avb_unittest_util.h#35
// Encodes |len| bytes of |data| as a lower-case hex-string.
std::string mem_to_hexstring(const uint8_t* data, size_t len);
