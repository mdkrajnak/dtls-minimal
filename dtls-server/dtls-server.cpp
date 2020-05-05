/*
 * Based on server.cc, a minimal CoAP server by Olaf Bergman.
 * https://github.com/obgm/libcoap-minimal
 */

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sstream>
#include <unistd.h>

#include <coap2/coap.h>
#include "common.hpp"

// C++ friendly substitute for coap_log()
#define coapLog(level, ...) do { \
  if ((level) <= coap_get_log_level()) \
     coap_log_impl((level), __VA_ARGS__); \
} while(0)

static void usage() {
    printf("Usage:\n");
    printf("    dtls-server [-h] [-a <address>] [-p <port>]\n");
    printf("\n");
    printf("    -h            Print help and exit.\n");
    printf("    -a <address>  Bind coap to the specified network address, default localhost.\n");
    printf("    -p <port>     Bind coap to the specified port, default 5684,\n");
    printf("    -c <certfile> A self signed certificate for securing the DTLS connection\n");
}

static int getopts(int argc, char** argv, const char** address, const char** port, const char** certfile) {
    int c;
    int iserror = 0;
    while ((c = getopt (argc, argv, "ha:p:c:")) != -1) {
      switch (c)
      {
        case 'a':
          *address = optarg;
          break;
        case 'c':
          *certfile = optarg;
          break;
        case 'p':
          *port = optarg;
          break;
        case 'h':
          usage();
          iserror = -1;
          break;
        case '?':
          if (optopt == 'a') {
            fprintf (stderr, "Option -%c requires an argument.\n", optopt);
          }
          else if (isprint (optopt)) {
            fprintf (stderr, "Unknown option `-%c'.\n", optopt);
          }
          else {
            fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
          }
          iserror = -1;
          break;
        default:
          iserror = -1;
          break;
        }
    }
    return iserror;
}

/**
 * A CoAP handler that sends a response that is a copy of the payload included in the request.
 *
 * @brief Echo the request payload.
 * @param pdu
 * @param response
 */
static void echo_handler(
    coap_context_t* /*context*/,
    struct coap_resource_t* /*resource*/,
    coap_session_t* /*session*/,
    coap_pdu_t* pdu,
    coap_binary_t* /*token*/,
    coap_string_t* /*query*/,
    coap_pdu_t* response) {
    size_t len;
    uint8_t* data;
    response->code = COAP_RESPONSE_CODE(205);
    coap_show_pdu(LOG_INFO, pdu);
    coap_get_data(pdu, &len, &data);

    coap_add_data(response, len, data);
}

/**
 * A CoAP handler that shutsdown this server.
 *
 * @brief Shutdown the server.
 * @param pdu
 * @param response
 */
static void shutdown_handler(
    coap_context_t* context,
    struct coap_resource_t* /*resource*/,
    coap_session_t* /*session*/,
    coap_pdu_t* pdu,
    coap_binary_t* /*token*/,
    coap_string_t* /*query*/,
    coap_pdu_t* response
) {
    response->code = COAP_RESPONSE_CODE(205);
    coap_show_pdu(LOG_INFO, pdu);
    bool* running = reinterpret_cast<bool*>(coap_get_app_data(context));
    *running = false;
}

static int verify_cn_callback(
    const char *cn,
    const uint8_t *asn1_public_cert,
    size_t asn1_length,
    coap_session_t *session,
    unsigned depth,
    int validated,
    void *arg
) {
    (void)asn1_public_cert;
    (void)asn1_length;
    (void)session;
    (void)validated;
    (void)arg;

    coapLog(LOG_INFO, "CN '%s' presented by client (%s)\n",
             cn, depth ? "CA" : "Certificate");
    return 1;
}

static coap_dtls_key_t* verify_sni_callback(const char *sni, void *arg) {
    static coap_dtls_key_t dtls_key;
    const char* certfile = reinterpret_cast<const char*>(arg);

    /* Just use the defined keys for now */
    memset (&dtls_key, 0, sizeof(dtls_key));
    dtls_key.key_type = COAP_PKI_KEY_PEM;
    dtls_key.key.pem.public_cert = certfile;
    dtls_key.key.pem.private_key = certfile;
    dtls_key.key.pem.ca_file = certfile;
    if (sni[0]) {
        coapLog(LOG_INFO, "SNI '%s' requested\n", sni);
    }
    else {
        coapLog(LOG_DEBUG, "SNI not requested\n");
    }
    return &dtls_key;
}

/*
 * Set up PKI encryption information
 */
static coap_dtls_pki_t* setup_pki_parameters(coap_dtls_pki_t* dtls_pki, const char *my_cert) {
    /* See coap_tls_library(3) */
    if (!coap_dtls_is_supported())
        return nullptr;

    memset (dtls_pki, 0, sizeof (*dtls_pki));

    dtls_pki->version                 = COAP_DTLS_PKI_SETUP_VERSION;
    dtls_pki->verify_peer_cert        = 1;
    dtls_pki->require_peer_cert       = 0;
    dtls_pki->allow_self_signed       = 1;
    dtls_pki->allow_expired_certs     = 1;
    dtls_pki->cert_chain_validation   = 1;
    dtls_pki->cert_chain_verify_depth = 2;
    dtls_pki->check_cert_revocation   = 1;
    dtls_pki->allow_no_crl            = 1;
    dtls_pki->allow_expired_crl       = 1;
    dtls_pki->validate_cn_call_back   = verify_cn_callback;
    dtls_pki->cn_call_back_arg        = nullptr;
    dtls_pki->validate_sni_call_back  = verify_sni_callback;
    dtls_pki->sni_call_back_arg       = const_cast<char*>(my_cert);
    dtls_pki->additional_tls_setup_call_back = nullptr;
    dtls_pki->client_sni              = nullptr;
    dtls_pki->pki_key.key_type        = COAP_PKI_KEY_PEM;
    dtls_pki->pki_key.key.pem.ca_file = my_cert;
    dtls_pki->pki_key.key.pem.public_cert = my_cert;
    dtls_pki->pki_key.key.pem.private_key = my_cert;

    return dtls_pki;
}

/**
 * Main entry point.
 *
 * @brief main entry point.
 * @return
 */
int main(int argc, char** argv) {
    static coap_dtls_pki_t dtls_pki;
    coap_address_t dst;
    bool running = true;
    const char* address = "localhost";
    const char* port = "5684";
    const char* certfile = "selfsigned.pem";

    if (getopts(argc, argv, &address, &port, &certfile) < 0) exit(-1);

    coap_startup();
    coap_set_log_level(LOG_DEBUG);

    /* Check the request address. */
    if (resolve_address(address, port, &dst) < 0) {
        coapLog(LOG_CRIT, "failed to resolve address %s\n", address);
        return EXIT_FAILURE;
    }

    /* Create CoAP context and endpoint. */
    coap_context_t* ctx = coap_new_context(nullptr);
    if (!ctx) {
        coapLog(LOG_CRIT, "failed to create coap_context_t\n");
        coap_cleanup();
        return EXIT_FAILURE;
    }

    /* Setup PKI Information */
    if (!setup_pki_parameters(&dtls_pki, certfile)) {
        coapLog(LOG_CRIT, "failed to set pki parameters\n");
        coap_free_context(ctx);
        return EXIT_FAILURE;
    }

    if (!coap_context_set_pki(ctx, &dtls_pki)) {
        coapLog(LOG_CRIT, "failed to set pki context\n");
        coap_free_context(ctx);
        return EXIT_FAILURE;
    }

    /* Pass in local data pointer. */
    coap_set_app_data(ctx, &running);

    /* Create the endpoint. */
    coap_endpoint_t* endpoint = coap_new_endpoint(ctx, &dst, COAP_PROTO_DTLS);
    if (!endpoint) {
        coapLog(LOG_EMERG, "cannot initialize endpoint\n");
        coap_free_context(ctx);
        coap_cleanup();
        return EXIT_FAILURE;
    }

    // Add resources.
    coap_str_const_t* echo_name = coap_make_str_const("Echo");
    coap_resource_t* echo = coap_resource_init(echo_name, 0);
    coap_register_handler(echo, COAP_REQUEST_POST, echo_handler);
    coap_add_resource(ctx, echo);

    coap_str_const_t* shutdown_name = coap_make_str_const("Shutdown");
    coap_resource_t* shutdown = coap_resource_init(shutdown_name, 0);
    coap_register_handler(shutdown, COAP_REQUEST_POST, shutdown_handler);
    coap_add_resource(ctx, shutdown);

    // running is set to false if a client POSTs to the Shutdown resource.
    while (running) {
        coap_run_once(ctx, 0);
    }

    coap_free_context(ctx);
    coap_cleanup();

    return EXIT_SUCCESS;
}
