#pragma once

#include <libavb/libavb.h>

#define AVB2_INVALID     (1 << 1)
#define AVB2_UNSUPPORTED (1 << 2)
#define AVB2_INVALID_KEY (1 << 3)

int avbv2_verify_sign(const char *image, const char *key, bool rw);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/test/avb_unittest_util.h#35
// Encodes |len| bytes of |data| as a lower-case hex-string.
std::string mem_to_hexstring(const uint8_t* data, size_t len);

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.h#55
bool NibbleValue(const char& c, uint8_t* value);

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.h#57
bool HexToBytes(uint8_t* bytes, size_t bytes_len, const std::string& hex);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_descriptor.h#67
/* Copies |src| to |dest|, byte-unswapping fields in the
 * process if needed.
 *
 * Data following the struct is not copied.
 */
void avb_descriptor_byteunswap(const AvbDescriptor* src, AvbDescriptor* dest);

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hashtree_descriptor.h#85
/* Copies |src| to |dest|, byte-unswapping fields in the
 * process if needed.
 *
 * Data following the struct is not validated nor copied.
 */
void avb_hashtree_descriptor_byteunswap(const AvbHashtreeDescriptor* src, AvbHashtreeDescriptor* dest);