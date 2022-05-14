#include <openssl/sha.h>
#include <utils.hpp>

#include "magiskboot.hpp"
#include "compress.hpp"

using namespace std;

static void usage(char *arg0) {
    fprintf(stderr,
R"EOF(MagiskBoot - Boot Image Modification Tool

Usage: %s <action> [args...]

Supported actions:
  avbv2 <vbmetaimg> <action> [args...]
    Do AVBv2 related actions to <vbmetaimg>
    Supported commands:
      verify
        Verify AVBb2 hashes and signature
        Return values:
        0:valid    2:invalid    4:unsupported
      sign [privkey]
        Updates AVBv2 hashes and signature using [privkey] or testkey
        Return values:
        0:valid    1:syntax error    2:invalid    4:unsupported    8:key error)EOF", arg0);

    fprintf(stderr, "\n\n");
    exit(1);
}

int main(int argc, char *argv[]) {
    cmdline_logging();
    umask(0);

    if (argc < 2)
        usage(argv[0]);

    // Skip '--' for backwards compatibility
    string_view action(argv[1]);
    if (str_starts(action, "--"))
        action = argv[1] + 2;

    if (argc > 3 && action == "avbv2") {
        int status = avbv2_commands(argc - 2, argv + 2);
        if (status == 1)
            usage(argv[0]);
        else
            return status;
    } else {
        usage(argv[0]);
    }

    return 0;
}
