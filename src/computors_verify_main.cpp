// computors_verify — standalone verifier for a Qubic Computors list.
//
// Reads the raw Computors payload of a BroadcastComputors message on stdin
// (epoch + 676 public keys + arbitrator signature, exactly as a node sends it)
// and decides whether the list was signed by the given arbitrator identity.
//
// Mirrors Qubic Core's processBroadcastComputors (src/qubic.cpp): reject any
// list containing a zeroed public key, then verify the SchnorrQ signature over
// K12(payload minus signature) against the arbitrator public key. This makes
// the fetched computor keyset self-authenticating: a malicious or compromised
// node cannot hand the mock service a substituted key list.
//
// Usage:
//     computors_verify --arbitrator <60-char identity>  < computors_payload.bin
//
//   The identity's 4-character checksum is validated (round-trip through
//   getIdentity), so a mistyped arbitrator identity fails loudly instead of
//   deriving a wrong key.
//
// Output (stdout): one JSON line, e.g. {"valid":true,"epoch":218}
// Exit code: 0 if valid, 1 if invalid, 2 on usage/IO error.

#define NO_UEFI 1

#include "four_q.h"
#include "kangaroo_twelve.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

static constexpr int NUMBER_OF_COMPUTORS = 676;
static constexpr int SIGNATURE_SIZE = 64;
static constexpr int IDENTITY_CHARS = 60;

// Computors payload (network_messages/computors.h): epoch + publicKeys + signature.
static constexpr size_t SIGNED_SIZE = 2 + (size_t)NUMBER_OF_COMPUTORS * 32; // covered by the signature
static constexpr size_t PAYLOAD_SIZE = SIGNED_SIZE + SIGNATURE_SIZE;        // 21698

static std::vector<unsigned char> readAll(FILE* f)
{
    std::vector<unsigned char> buf;
    unsigned char tmp[65536];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
        buf.insert(buf.end(), tmp, tmp + n);
    return buf;
}

static void fail(const char* reason, unsigned epoch)
{
    printf("{\"valid\":false,\"epoch\":%u,\"reason\":\"%s\"}\n", epoch, reason);
    exit(1);
}

int main(int argc, char** argv)
{
    const char* arbitrator = nullptr;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--arbitrator") == 0 && i + 1 < argc)
            arbitrator = argv[++i];
    }
    if (!arbitrator || std::strlen(arbitrator) != IDENTITY_CHARS)
    {
        fprintf(stderr, "usage: computors_verify --arbitrator <60-char identity> < computors_payload.bin\n");
        return 2;
    }

    // Derive the arbitrator public key and validate the identity's checksum by
    // re-encoding the key and comparing all 60 characters.
    unsigned char arbitratorPublicKey[32];
    if (!getPublicKeyFromIdentity((const unsigned char*)arbitrator, arbitratorPublicKey))
    {
        fprintf(stderr, "computors_verify: arbitrator identity has invalid characters\n");
        return 2;
    }
    CHAR16 roundTrip[61];
    getIdentity(arbitratorPublicKey, roundTrip, false);
    for (int i = 0; i < IDENTITY_CHARS; ++i)
    {
        if ((char)roundTrip[i] != arbitrator[i])
        {
            fprintf(stderr, "computors_verify: arbitrator identity checksum mismatch\n");
            return 2;
        }
    }

    // Read the raw Computors payload. Tolerate up to 4 trailing padding bytes,
    // as the core does for the framed message (checkPayloadSizeMinMax).
    std::vector<unsigned char> payload = readAll(stdin);
    if (payload.size() < PAYLOAD_SIZE || payload.size() > PAYLOAD_SIZE + 4)
    {
        fprintf(stderr, "computors_verify: payload must be %zu bytes (got %zu)\n",
                PAYLOAD_SIZE, payload.size());
        return 2;
    }

    unsigned short epoch;
    std::memcpy(&epoch, payload.data(), 2);

    // Reject a list containing any zeroed public key, even if correctly signed
    // (mirrors processBroadcastComputors).
    static const unsigned char zero[32] = {0};
    for (int c = 0; c < NUMBER_OF_COMPUTORS; ++c)
    {
        if (std::memcmp(payload.data() + 2 + (size_t)c * 32, zero, 32) == 0)
            fail("zeroed computor public key", epoch);
    }

    // Verify the arbitrator signature over K12(epoch || publicKeys).
    unsigned char digest[32];
    KangarooTwelve(payload.data(), SIGNED_SIZE, digest, 32);
    if (!verify(arbitratorPublicKey, digest, payload.data() + SIGNED_SIZE))
        fail("arbitrator signature invalid", epoch);

    printf("{\"valid\":true,\"epoch\":%u}\n", epoch);
    return 0;
}
