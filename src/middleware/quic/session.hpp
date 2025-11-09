// Copyright (C) 2025, Moritz Scheer

#pragma once

#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>
#include <openssl/base.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "../../utils/types.hpp"
#include "../../utils/uvarint.hpp"

namespace faim
{
namespace networking
{
namespace quic
{

/* -------------------------------------------- MACRO DECLARATIONS -------------------------------------------------- */

// Protocol versions and ALPN
#define NGTCP2_PROTO_VER_D15 0xff00000fu
#define NGTCP2_ALPN_D15 "\x5hq-15"

// Packet length limits
#define NGTCP2_MAX_PKTLEN_IPV4 1252u
#define NGTCP2_MAX_PKTLEN_IPV6 1232u

// Windowing and handshake
#define MAX_WINDOW 1u
#define MAX_STREAM_WINDOW 0u
#define HANDSHAKE_TIMEOUT UINT64_MAX
#define NO_PMTUD 0u
#define ACK_THRESH 2u
#define MAX_TX_UDP_PAYLOAD_SIZE 1u
#define NO_TX_UDP_PAYLOAD_SIZE_SHAPING 1u

// Stream and transport parameters
#define MAX_STREAM_DATA_BIDI_LOCAL (256 * 1024) // 256 KB
#define INITIAL_MAX_STREAM_DATA_BIDI_LOCAL (128 * 1024)
#define INITIAL_MAX_STREAM_DATA_BIDI_REMOTE (128 * 1024)
#define INITIAL_MAX_STREAM_DATA_UNI (128 * 1024) // fill as needed
#define INITIAL_MAX_DATA (1024 * 1024)
#define INITIAL_MAX_STREAMS_BIDI 100u
#define INITIAL_MAX_STREAMS_UNI 50u
#define MAX_IDLE_TIMEOUT 0u
#define ACTIVE_CONNECTION_ID_LIMIT 7u

#define SECRET secret
#define SECRET_LEN 32

#define TIMEOUT (3600 * NGTCP2_SECONDS)
#define RETRY_TIMEOUT (10 * NGTCP2_SECONDS)

// Versions supported
#define NUM_SUPPORTED_VERSIONS 3u

/* ------------------------------------------ VARIABLES DECLARATIONS ------------------------------------------------ */

//
//
//
static ngtcp2_ccerr app_error;

//
//
//
static inline std::array<uint32_t, 2> supported_versions;

//
//
//
static inline uint8_t secret[SECRET_LEN];

//
//
//
static inline ngtcp2_settings *default_settings;

//
//
//
static inline ngtcp2_transport_params *default_params;

//
//
//
static inline SSL_CTX *ssl_ctx;

//
//
//
extern ngtcp2_callbacks callbacks;

/* ------------------------------------------- FUNCTION DECLARATIONS ------------------------------------------------ */

//
//
//
int setup();

//
//
//
void cleanup();

//
//
//
int create_session(connection *conn, uint64_t &version, ngtcp2_path *path, ngtcp2_cid *odcid, ngtcp2_cid *dcid,
                   ngtcp2_cid *scid, uvarint_t &token, ngtcp2_token_type &token_type, uint64_t &timestamp);

//
//
//
void delete_session(ngtcp2_conn *conn);

void update_timer(connection *conn);

//
//
//
int update_timer(connection *conn, uint64_t &ts, uint8_t &action);

/* ------------------------------------------------------------------------------------------------------------------ */

}; // namespace quic
}; // namespace networking
}; // namespace faim
