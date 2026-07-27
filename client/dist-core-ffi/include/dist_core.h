/*
 * dist-core — shared TUF verifier, C ABI.
 *
 * This is the interface the JavaScript, Python, C# and C/C++ bindings call
 * through (see docs/PLAN.md decision D2). Verification is implemented once,
 * behind this boundary; a binding contains no verification logic, so a defect
 * in one cannot weaken the signature check for another.
 *
 * Conventions
 * -----------
 *  - Every function returns DistStatus. DIST_OK is zero.
 *  - No allocation crosses this boundary. Results are written into storage the
 *    caller owns, so there is no free function to pair incorrectly and no
 *    allocator mismatch between languages. The one exception is DistVerifier,
 *    which is created by dist_verifier_new* and released by dist_verifier_free.
 *  - Byte buffers are pointer plus length. They are never assumed to be
 *    NUL-terminated.
 *  - Strings are NUL-terminated and must be valid UTF-8; they are copied, not
 *    retained.
 *  - Nothing unwinds out of these functions. An internal panic is caught and
 *    reported as DIST_PANIC; a handle that returns it must be treated as
 *    unusable and freed.
 *
 * Thread safety
 * -------------
 * A DistVerifier must not be used from two threads at once. Callers sharing
 * one must serialise access themselves.
 */

#ifndef DIST_CORE_H
#define DIST_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Longest release version string the ABI carries, including the NUL. */
#define DIST_VERSION_CAPACITY 64

typedef enum {
    DIST_OK = 0,
    /* A required pointer argument was null. */
    DIST_NULL_ARGUMENT = 1,
    /* Metadata refused: bad signature, threshold, rollback or expiry. */
    DIST_REJECTED = 2,
    /* No trusted metadata describes the requested target. */
    DIST_UNKNOWN_TARGET = 3,
    /* Metadata verified but did not carry what the client needs. */
    DIST_MALFORMED = 4,
    /* Payload length did not match the signed description. */
    DIST_LENGTH = 5,
    /* Payload digest did not match the signed description. */
    DIST_DIGEST = 6,
    /* The system clock is before the Unix epoch. */
    DIST_CLOCK = 7,
    /* A string was not valid UTF-8, or a target path was unsafe. */
    DIST_INVALID_ARGUMENT = 8,
    /* A value did not fit its fixed-size field. */
    DIST_OVERFLOW = 9,
    /* A panic was caught at the boundary. The handle is unusable. */
    DIST_PANIC = 10
} DistStatus;

/* Opaque verifier handle. */
typedef struct DistVerifier DistVerifier;

/* A verified target description. Fixed size; the caller owns the storage. */
typedef struct {
    uint64_t length;                          /* signed payload length      */
    uint8_t  sha256[32];                      /* signed SHA-256 digest      */
    uint32_t rollout_pct;                     /* signed rollout, 0..=100    */
    uint8_t  mandatory;                       /* non-zero if security-critical */
    uint8_t  version[DIST_VERSION_CAPACITY];  /* NUL-padded release version */
} DistTargetInfo;

/*
 * Create a verifier from a trusted root shipped with the application.
 *
 * The root is embedded rather than fetched, so there is no trust-on-first-use
 * window. Returns NULL on failure; if `status` is non-NULL the reason is
 * written to it. Release with dist_verifier_free.
 */
DistVerifier *dist_verifier_new(const uint8_t *root, size_t root_len,
                                DistStatus *status);

/*
 * As dist_verifier_new, but with a fixed notion of "now" in seconds since the
 * Unix epoch. For tests, and for callers with a trusted external clock.
 */
DistVerifier *dist_verifier_new_at(const uint8_t *root, size_t root_len,
                                   uint64_t unix_seconds, DistStatus *status);

/* Release a verifier. NULL is accepted and ignored. */
void dist_verifier_free(DistVerifier *handle);

/*
 * Feed fetched metadata in TUF's required order: timestamp, snapshot, targets,
 * then each delegated role. Each call verifies signatures, thresholds, version
 * ordering and expiry before accepting anything.
 */
DistStatus dist_verifier_update_timestamp(DistVerifier *handle,
                                          const uint8_t *raw, size_t raw_len);
DistStatus dist_verifier_update_snapshot(DistVerifier *handle,
                                         const uint8_t *raw, size_t raw_len);
DistStatus dist_verifier_update_targets(DistVerifier *handle,
                                        const uint8_t *raw, size_t raw_len);
DistStatus dist_verifier_update_delegated_targets(DistVerifier *handle,
                                                  const char *role,
                                                  const uint8_t *raw,
                                                  size_t raw_len);

/*
 * Version of snapshot named by the trusted timestamp, and version of a targets
 * role named by the trusted snapshot.
 *
 * A repository with consistent snapshots serves metadata as
 * <version>.<role>.json, so a client must know a role's version before it can
 * fetch it, and it learns that from the role above. Fetching an unversioned
 * alias instead reintroduces the mismatched-set race that consistent snapshots
 * exist to prevent: a cache serving one role from one publish and another role
 * from the next.
 *
 * The numbers come from verified metadata, never from a filename or an
 * unsigned response. Both return DIST_MALFORMED if the role above has not been
 * accepted yet, or if the snapshot does not describe the requested role.
 *
 * Pass "targets" for the top-level role, or a delegated name like "app-editor".
 */
DistStatus dist_verifier_snapshot_version(const DistVerifier *handle,
                                          uint32_t *out);
DistStatus dist_verifier_targets_version(const DistVerifier *handle,
                                         const char *role, uint32_t *out);

/*
 * Resolve a target path against trusted metadata.
 *
 * The path is validated segment by segment first, so a delegated role cannot
 * smuggle a traversal component through a pattern TUF would otherwise accept.
 * Returns DIST_UNKNOWN_TARGET if no trusted role is permitted to describe it.
 */
DistStatus dist_verifier_target(const DistVerifier *handle, const char *path,
                                DistTargetInfo *out);

/*
 * Check downloaded bytes against a verified description.
 *
 * Call this on the bytes as they sit on disk, immediately before installing.
 * Verifying only at download time leaves a window in which the staged file can
 * be swapped.
 */
DistStatus dist_verify_payload(const DistTargetInfo *info,
                               const uint8_t *payload, size_t payload_len);

/*
 * Decide whether this install is inside a staged rollout. Writes 0 or 1.
 *
 * The client decides for itself from signed metadata, so there is no
 * per-client server decision for a network attacker to manipulate.
 */
DistStatus dist_in_rollout(const char *install_id, const char *app_id,
                           uint32_t rollout_pct, uint8_t *out);

/* Library version, static and NUL-terminated. */
const char *dist_core_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* DIST_CORE_H */
