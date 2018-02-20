#ifndef UNKNOWNECHO_TLS_KEYSTORE_MANAGER_H
#define UNKNOWNECHO_TLS_KEYSTORE_MANAGER_H

#include <unknownecho/model/manager/tls_keystore_manager_struct.h>
#include <unknownecho/model/entity/tls_keystore.h>
#include <unknownecho/bool.h>
#include <unknownecho/network/api/tls/tls_method.h>

ue_tls_keystore_manager *ue_tls_keystore_manager_init(char *ca_cert_path, char *cert_file, char *key_file, ue_tls_method *method, char *passphrase, char *password);

void ue_tls_keystore_manager_uninit(ue_tls_keystore_manager *manager);

ue_tls_keystore *ue_tls_keystore_manager_get_keystore(ue_tls_keystore_manager *manager);

bool ue_tls_keystore_manager_verify_peer(ue_tls_keystore_manager *manager);

#endif
