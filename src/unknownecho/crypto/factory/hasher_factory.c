#include <unknownecho/crypto/factory/hasher_factory.h>
#include <unknownecho/errorHandling/stacktrace.h>

ue_hasher *ue_hasher_sha256_create() {
    ue_hasher *h;

    if (!(h = ue_hasher_create())) {
        ue_stacktrace_push_msg("Failed to create ue_hasher");
        return NULL;
    }

    if (!(ue_hasher_init(h, "SHA-256"))) {
        ue_stacktrace_push_msg("Failed to initialize ue_hasher with SHA-256 algorithm");
        ue_hasher_destroy(h);
        return NULL;
    }

    return h;
}

ue_hasher *ue_hasher_default_create() {
    return ue_hasher_sha256_create();
}
