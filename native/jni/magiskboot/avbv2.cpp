#include <functional>
#include <memory>

#include <cstring>
#include <inttypes.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <utils.hpp>

#include "avbv2.hpp"
#include "testkeys.hpp"
#include "scopedrsa.hpp"
#include "android_pubkey.h"

int avbv2_commands(int argc, char *argv[]) {
    char *boot = argv[0];
    ++argv;
    --argc;

    std::string_view action(argv[0]);
    if (action == "verify") {
        return avbv2_verify_sign(boot, nullptr, false);
    } else if (action == "sign") {
        if (argc > 1) {
            return avbv2_verify_sign(boot, argv[1], true);
        } else {
            return avbv2_verify_sign(boot, nullptr, true);
        }
    } else {
        return 1;
    }
}

int avbv2_verify_sign(const char *image, const char *key, bool rw) {
    mmap_data vbmeta(image, rw);
    const uint8_t* header_block = vbmeta.buf;
    AvbVBMetaImageHeader vbmeta_header;
    size_t vbmeta_length;
    const uint8_t* authentication_block;
    const uint8_t* hash;
    const uint8_t* signature;
    const uint8_t* auxiliary_block;
    const uint8_t* public_key_data;
    AvbHashtreeDescriptor* dlkm_desc_orig;
    AvbHashtreeDescriptor dlkm_desc;
    const uint8_t* dlkm_salt;
    const uint8_t* dlkm_digest;
    bool mismatch = false;
    uint64_t actual_image_size = 44224512;
    uint64_t actual_tree_size = 352256;
    uint64_t actual_fec_size = 360448;
    std::string actual_dlkm_digest = "84091e9b829a79fadeb80599e4d78bcbcef0353ce72aa432f5c05f7125105cf6";
    uint8_t actual_hash[SHA512_DIGEST_LENGTH];
    uint32_t actual_hash_length;
    uint8_t actual_signature[AVB_RSA8192_NUM_BYTES];
    uint32_t actual_signature_length;

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_vbmeta_image.c#63
    /* Ensure magic is correct. */
    if (avb_safe_memcmp(header_block, AVB_MAGIC, AVB_MAGIC_LEN) != 0) {
        fprintf(stderr, "! Header magic is incorrect\n");
        return AVB2_INVALID;
    }
    avb_vbmeta_image_header_to_host_byte_order((AvbVBMetaImageHeader*)(header_block), &vbmeta_header);

    vbmeta_length = sizeof(AvbVBMetaImageHeader) + vbmeta_header.authentication_data_block_size + vbmeta_header.auxiliary_data_block_size;

    authentication_block = header_block + sizeof(AvbVBMetaImageHeader);
    auxiliary_block = authentication_block + vbmeta_header.authentication_data_block_size;
    if (vbmeta_header.algorithm_type == AVB_ALGORITHM_TYPE_NONE || vbmeta_header.algorithm_type > AVB_ALGORITHM_TYPE_SHA512_RSA8192) {
        printf("Ignoring algorithm type (%u)\n", vbmeta_header.algorithm_type);
    }
    hash = authentication_block + vbmeta_header.hash_offset;
    signature = authentication_block + vbmeta_header.signature_offset;
    public_key_data = auxiliary_block + vbmeta_header.public_key_offset;

    ScopedRSA pubkey(public_key_data, vbmeta_header.public_key_size);
    if (!pubkey.is_initialized()) {
        printf("Ignoring public_key_data size (%lu)\n", vbmeta_header.public_key_size);
    }

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#940
    size_t num_descriptors;
    size_t n;
    bool dlkm_found = false;
    const AvbDescriptor** descriptors = descriptors = avb_descriptor_get_all(header_block, vbmeta_length, &num_descriptors);
    for (n = 0; n < num_descriptors; n++) {
        // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hash_descriptor.c#34
        AvbDescriptor desc;
        if (!avb_descriptor_validate_and_byteswap(descriptors[n], &desc)) {
            fprintf(stderr, "! Descriptor is invalid\n");
            return AVB2_INVALID;
        }
        switch (desc.tag) {
            case AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: {
                // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#996
                AvbChainPartitionDescriptor chain_desc;
                const uint8_t* desc_partition_name;

                if (!avb_chain_partition_descriptor_validate_and_byteswap((AvbChainPartitionDescriptor*)descriptors[n], &chain_desc)) {
                    fprintf(stderr, "! Chain partition descriptor is invalid\n");
                    return AVB2_INVALID;
                }

                desc_partition_name = (const uint8_t*)descriptors[n] + sizeof(AvbChainPartitionDescriptor);

                char desc_partition_name_str[chain_desc.partition_name_len + 1];
                memset(desc_partition_name_str, 0, sizeof desc_partition_name_str);
                memcpy(desc_partition_name_str, desc_partition_name, chain_desc.partition_name_len);
                printf("Ignoring chain partition descriptor (%s)\n", desc_partition_name_str);
            } break;
            case AVB_DESCRIPTOR_TAG_HASH: {
                // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#302
                AvbHashDescriptor hash_desc;
                const uint8_t* desc_partition_name;

                if (!avb_hash_descriptor_validate_and_byteswap((AvbHashDescriptor*)descriptors[n], &hash_desc)) {
                    fprintf(stderr, "! Hash descriptor is invalid\n");
                    return AVB2_INVALID;
                }

                desc_partition_name = (const uint8_t*)descriptors[n] + sizeof(AvbHashDescriptor);

                char desc_partition_name_str[hash_desc.partition_name_len + 1];
                memset(desc_partition_name_str, 0, sizeof desc_partition_name_str);
                memcpy(desc_partition_name_str, desc_partition_name, hash_desc.partition_name_len);
                printf("Ignoring hash descriptor (%s)\n", desc_partition_name_str);
            } break;
            case AVB_DESCRIPTOR_TAG_HASHTREE: {
                // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#1121
                AvbHashtreeDescriptor hashtree_desc;
                const uint8_t* desc_partition_name;
                if (!avb_hashtree_descriptor_validate_and_byteswap((AvbHashtreeDescriptor*)descriptors[n], &hashtree_desc)) {
                    fprintf(stderr, "! Hashtree descriptor is invalid\n");
                    return AVB2_INVALID;
                }

                desc_partition_name = (const uint8_t*)descriptors[n] + sizeof(AvbHashtreeDescriptor);

                if (hashtree_desc.partition_name_len == 11 && strncmp((const char*)desc_partition_name, "vendor_dlkm", hashtree_desc.partition_name_len) == 0) {
                    dlkm_desc_orig = (AvbHashtreeDescriptor*)descriptors[n];
                    dlkm_desc = hashtree_desc;
                    dlkm_found = true;

                    dlkm_salt = desc_partition_name + hashtree_desc.partition_name_len;
                    dlkm_digest = dlkm_salt + hashtree_desc.salt_len;
                } else {
                    char desc_partition_name_str[hashtree_desc.partition_name_len + 1];
                    memset(desc_partition_name_str, 0, sizeof desc_partition_name_str);
                    memcpy(desc_partition_name_str, desc_partition_name, hashtree_desc.partition_name_len);
                    printf("Ignoring hashtree descriptor (%s)\n", desc_partition_name_str);
                }
            } break;
            case AVB_DESCRIPTOR_TAG_PROPERTY: {} break;
            default: {
                printf("Ignoring descriptor (%lu)\n", desc.tag);
            } break;
        }
    }
    if (!dlkm_found) {
        fprintf(stderr, "! vendor_dlkm descriptor missing\n");
        return AVB2_INVALID;
    }

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_slot_verify.c#388
    SHA256_CTX sha256_ctx;
    SHA512_CTX sha512_ctx;
    //if (avb_strcmp((const char*)dlkm_desc.hash_algorithm, "sha256") != 0 && avb_strcmp((const char*)dlkm_desc.hash_algorithm, "sha512") != 0) {
    if (avb_strcmp((const char*)dlkm_desc.hash_algorithm, "sha256") != 0) {
        fprintf(stderr, "! Invalid hash algorithm\n");
        return AVB2_INVALID;
    }

    if (dlkm_desc.image_size != dlkm_desc.tree_offset) {
        fprintf(stderr, "! Unexpected vendor_dlkm hashtree descriptor format\n");
        return AVB2_INVALID;
    }
    if (dlkm_desc.image_size + dlkm_desc.tree_size != dlkm_desc.fec_offset) {
        fprintf(stderr, "! Unexpected vendor_dlkm hashtree descriptor format\n");
        return AVB2_INVALID;
    }
    if (dlkm_desc.root_digest_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "! vendor_dlkm root digest length mismatch\n");
        return AVB2_INVALID;
    }
    if (dlkm_desc.image_size != actual_image_size) {
        if (!rw) {
            fprintf(stderr, "vendor_dlkm image size mismatch\n");
            fprintf(stderr, "expected image size: %lu\n", dlkm_desc.image_size);
            fprintf(stderr, "actual image size:   %lu\n", actual_image_size);
        }
        mismatch = true;
    } else if (!rw) {
        printf("vendor_dlkm image size verified\n");
    }
    if (dlkm_desc.tree_size != actual_tree_size) {
        if (!rw) {
            fprintf(stderr, "vendor_dlkm tree size mismatch\n");
            fprintf(stderr, "expected tree size: %lu\n", dlkm_desc.tree_size);
            fprintf(stderr, "actual tree size:   %lu\n", actual_tree_size);
        }
        mismatch = true;
    } else if (!rw) {
        printf("vendor_dlkm tree size verified\n");
    }
    if (dlkm_desc.fec_size != actual_fec_size) {
        if (!rw) {
            fprintf(stderr, "vendor_dlkm fec size mismatch\n");
            fprintf(stderr, "expected fec size: %lu\n", dlkm_desc.fec_size);
            fprintf(stderr, "actual fec size:   %lu\n", actual_fec_size);
        }
        mismatch = true;
    } else if (!rw) {
        printf("vendor_dlkm fec size verified\n");
    }
    if (mem_to_hexstring(dlkm_digest, dlkm_desc.root_digest_len) != actual_dlkm_digest) {
        if (!rw) {
            fprintf(stderr, "vendor_dlkm root digest mismatch\n");
            fprintf(stderr, "expected root digest: %s\n", mem_to_hexstring(dlkm_digest, dlkm_desc.root_digest_len).c_str());
            fprintf(stderr, "actual root digest:   %s\n", actual_dlkm_digest.c_str());
        }
        mismatch = true;
    } else if (!rw) {
        printf("vendor_dlkm root digest verified\n");
    }

    // https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_vbmeta_image.c#176
    switch (vbmeta_header.algorithm_type) {
        case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
        case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
        case AVB_ALGORITHM_TYPE_SHA256_RSA8192:
            SHA256_Init(&sha256_ctx);
            SHA256_Update(&sha256_ctx, header_block, sizeof(AvbVBMetaImageHeader));
            SHA256_Update(&sha256_ctx, auxiliary_block, vbmeta_header.auxiliary_data_block_size);
            SHA256_Final(actual_hash, &sha256_ctx);
            actual_hash_length = SHA256_DIGEST_LENGTH;
            break;
        case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
        case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
        case AVB_ALGORITHM_TYPE_SHA512_RSA8192:
            SHA512_Init(&sha512_ctx);
            SHA512_Update(&sha512_ctx, header_block, sizeof(AvbVBMetaImageHeader));
            SHA512_Update(&sha512_ctx, auxiliary_block, vbmeta_header.auxiliary_data_block_size);
            SHA512_Final(actual_hash, &sha512_ctx);
            actual_hash_length = SHA512_DIGEST_LENGTH;
            break;
        default:
            fprintf(stderr, "! Unknown algorithm\n");
            return AVB2_INVALID;
    }

    if (vbmeta_header.hash_size != actual_hash_length) {
        fprintf(stderr, "! Hash size mismatch\n");
        return AVB2_INVALID;
    }
    if (avb_memcmp(hash, actual_hash, actual_hash_length) != 0) {
        if (!rw) {
            fprintf(stderr, "Hash mismatch\n");
            fprintf(stderr, "expected hash: %s\n", mem_to_hexstring(hash, vbmeta_header.hash_size).c_str());
            fprintf(stderr, "actual hash:   %s\n", mem_to_hexstring(actual_hash, actual_hash_length).c_str());
        }
        mismatch = true;
    } else if (!rw) {
        printf("Hash verified\n");
    }

    actual_signature_length = pubkey.size();

    if (vbmeta_header.signature_size != actual_signature_length) {
        fprintf(stderr, "! Signature size mismatch\n");
        return AVB2_INVALID;
    }
    if (!pubkey.verify(
        hash, vbmeta_header.hash_size,
        signature, vbmeta_header.signature_size
    )) {
        if (!rw) {
            fprintf(stderr, "Signature mismatch\n");
        }
        mismatch = true;
    } else if (!rw) {
        printf("Signature verified\n");
    }

    if (mismatch && rw) {
        std::string privkey_string;
        int hash_nid;

        ScopedRSA *privkey = nullptr;
        if (key != nullptr) {
            struct stat st;
            if (stat(key, &st) != 0) {
                fprintf(stderr, "! Key does not exist, creating ...\n");
                int bits;
                switch (vbmeta_header.algorithm_type) {
                    case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
                    case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
                        bits = 2048;
                        break;
                    case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
                    case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
                        bits = 4096;
                        break;
                    case AVB_ALGORITHM_TYPE_SHA256_RSA8192:
                    case AVB_ALGORITHM_TYPE_SHA512_RSA8192:
                        bits = 8192;
                        break;
                }
                privkey = new ScopedRSA(bits);
                if (privkey->toPath(key) != 0) {
                    fprintf(stderr, "! Key saved to %s\n", key);
                } else {
                    fprintf(stderr, "! Failed to save key\n");
                }
            } else {
                privkey = ScopedRSA::fromPath(key);
                if (privkey == nullptr || !privkey->is_initialized()) {
                    fprintf(stderr, "! Bad or missing key\n");
                    return AVB2_INVALID_KEY;
                }
            }
        } else {
            switch (vbmeta_header.algorithm_type) {
                case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
                case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
                    privkey_string = testkey_rsa2048;
                    break;
                case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
                case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
                    privkey_string = testkey_rsa4096;
                    break;
                case AVB_ALGORITHM_TYPE_SHA256_RSA8192:
                case AVB_ALGORITHM_TYPE_SHA512_RSA8192:
                    privkey_string = testkey_rsa8192;
                    break;
            }
            privkey = new ScopedRSA(privkey_string.c_str());
        }

        if (privkey->size() != actual_signature_length) {
            fprintf(stderr, "! Key size mismatch\n");
            return AVB2_INVALID_KEY;
        }

        uint8_t new_public_key_data[privkey->encoded_size()];
        privkey->encode(new_public_key_data, privkey->encoded_size());
        if (avb_memcmp(public_key_data, new_public_key_data, privkey->encoded_size()) != 0) {
            avb_memcpy((void *)public_key_data, new_public_key_data, privkey->encoded_size());
        }

        bool descriptor_modified = false;
        if (dlkm_desc.image_size != actual_image_size) {
            dlkm_desc.image_size = actual_image_size;
            descriptor_modified = true;
        }
        if (dlkm_desc.tree_size != actual_tree_size) {
            dlkm_desc.tree_offset = actual_image_size;
            dlkm_desc.tree_size = actual_tree_size;
            descriptor_modified = true;
        }
        if (dlkm_desc.fec_size != actual_fec_size) {
            dlkm_desc.fec_offset = actual_image_size + actual_tree_size;
            dlkm_desc.fec_size = actual_fec_size;
            descriptor_modified = true;
        }
        if (descriptor_modified) {
            avb_hashtree_descriptor_byteunswap((const AvbHashtreeDescriptor*)&dlkm_desc, dlkm_desc_orig);
        }
        if (mem_to_hexstring(dlkm_digest, dlkm_desc.root_digest_len) != actual_dlkm_digest) {
            uint8_t actual_dlkm_digest_bytes[actual_dlkm_digest.length() / 2];
            HexToBytes((uint8_t*)actual_dlkm_digest_bytes, sizeof actual_dlkm_digest_bytes, actual_dlkm_digest);
            avb_memcpy((void *)dlkm_digest, actual_dlkm_digest_bytes, sizeof actual_dlkm_digest_bytes);
        }

        switch (vbmeta_header.algorithm_type) {
            case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
            case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
            case AVB_ALGORITHM_TYPE_SHA256_RSA8192:
                SHA256_Init(&sha256_ctx);
                SHA256_Update(&sha256_ctx, header_block, sizeof(AvbVBMetaImageHeader));
                SHA256_Update(&sha256_ctx, auxiliary_block, vbmeta_header.auxiliary_data_block_size);
                SHA256_Final(actual_hash, &sha256_ctx);
                hash_nid = NID_sha256;
                break;
            case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
            case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
            case AVB_ALGORITHM_TYPE_SHA512_RSA8192:
                SHA512_Init(&sha512_ctx);
                SHA512_Update(&sha512_ctx, header_block, sizeof(AvbVBMetaImageHeader));
                SHA512_Update(&sha512_ctx, auxiliary_block, vbmeta_header.auxiliary_data_block_size);
                SHA512_Final(actual_hash, &sha512_ctx);
                hash_nid = NID_sha512;
                break;
        }

        privkey->sign(hash_nid, actual_hash, actual_hash_length, actual_signature);

        avb_memcpy((void *)hash, actual_hash, actual_hash_length);

        avb_memcpy((void *)signature, actual_signature, actual_signature_length);
        printf("- Boot AVBv2 signed\n");

        mismatch = false;
    } else if (!mismatch) {
        if (!rw) {
            printf("\nAll tests passed\n");
        } else {
            printf("- Boot already AVBv2 signed\n");
        }
    }

    return mismatch ? AVB2_INVALID : 0;
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/test/avb_unittest_util.cc#29
std::string mem_to_hexstring(const uint8_t* data, size_t len) {
  std::string ret;
  char digits[17] = "0123456789abcdef";
  for (size_t n = 0; n < len; n++) {
    ret.push_back(digits[data[n] >> 4]);
    ret.push_back(digits[data[n] & 0x0f]);
  }
  return ret;
}

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.cpp#32
bool NibbleValue(const char& c, uint8_t* value) {
    switch (c) {
        case '0' ... '9':
            *value = c - '0';
            break;
        case 'a' ... 'f':
            *value = c - 'a' + 10;
            break;
        case 'A' ... 'F':
            *value = c - 'A' + 10;
            break;
        default:
            return false;
    }
    return true;
}

// https://android.googlesource.com/platform/system/core/+/refs/tags/android-12.0.0_r12/fs_mgr/libfs_avb/util.cpp#52
bool HexToBytes(uint8_t* bytes, size_t bytes_len, const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return false;
    }
    if (hex.size() / 2 > bytes_len) {
        return false;
    }
    for (size_t i = 0, j = 0, n = hex.size(); i < n; i += 2, ++j) {
        uint8_t high;
        if (!NibbleValue(hex[i], &high)) {
            return false;
        }
        uint8_t low;
        if (!NibbleValue(hex[i + 1], &low)) {
            return false;
        }
        bytes[j] = (high << 4) | low;
    }
    return true;
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_descriptor.c#29
void avb_descriptor_byteunswap(const AvbDescriptor* src, AvbDescriptor* dest) {
    dest->tag = avb_htobe64(src->tag);
    dest->num_bytes_following = avb_htobe64(src->num_bytes_following);
}

// https://android.googlesource.com/platform/external/avb/+/refs/tags/android-12.0.0_r12/libavb/avb_hashtree_descriptor.c#28
void avb_hashtree_descriptor_byteunswap(const AvbHashtreeDescriptor* src, AvbHashtreeDescriptor* dest) {
    avb_memcpy(dest, src, sizeof(AvbHashtreeDescriptor));
    avb_descriptor_byteunswap((const AvbDescriptor*)src, (AvbDescriptor*)dest);
    dest->dm_verity_version = avb_htobe32(dest->dm_verity_version);
    dest->image_size = avb_htobe64(dest->image_size);
    dest->tree_offset = avb_htobe64(dest->tree_offset);
    dest->tree_size = avb_htobe64(dest->tree_size);
    dest->data_block_size = avb_htobe32(dest->data_block_size);
    dest->hash_block_size = avb_htobe32(dest->hash_block_size);
    dest->fec_num_roots = avb_htobe32(dest->fec_num_roots);
    dest->fec_offset = avb_htobe64(dest->fec_offset);
    dest->fec_size = avb_htobe64(dest->fec_size);
    dest->partition_name_len = avb_htobe32(dest->partition_name_len);
    dest->salt_len = avb_htobe32(dest->salt_len);
    dest->root_digest_len = avb_htobe32(dest->root_digest_len);
    dest->flags = avb_htobe32(dest->flags);
}