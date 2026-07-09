// make_test_computors — generates an arbitrator-signed Computors payload for
// testing computors_verify and the service's lazy key fetch.
//
// The 676 computor public keys use the SAME deterministic derivation as
// make_test_bundle ("oc-test-seed-<index>"), so a bundle from make_test_bundle
// verifies against the key list embedded in this payload. The arbitrator
// keypair is derived from "oc-test-arbitrator".
//
// Usage:
//     make_test_computors [--epoch N] [--tamper|--zero-key] > computors_payload.bin
//
//   --tamper   : flip one bit in a public key after signing (signature must fail)
//   --zero-key : zero out one public key after signing (zero check must fail)
//
// stderr: prints the arbitrator identity to pass to computors_verify.

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

static void deriveSubseed(const char* name, int index, unsigned char* subseed)
{
    unsigned char seedbuf[32];
    std::memset(seedbuf, 0, sizeof(seedbuf));
    if (index >= 0)
        std::snprintf((char*)seedbuf, sizeof(seedbuf), "%s-%d", name, index);
    else
        std::snprintf((char*)seedbuf, sizeof(seedbuf), "%s", name);
    // Hash is used directly as the subseed (getSubseed expects a 55-char
    // lowercase seed and rejects binary input). Same derivation as make_test_bundle.
    KangarooTwelve(seedbuf, sizeof(seedbuf), subseed, 32);
}

int main(int argc, char** argv)
{
    unsigned short epoch = 150;
    bool tamper = false, zeroKey = false;
    for (int i = 1; i < argc; ++i)
    {
        if (!std::strcmp(argv[i], "--epoch") && i + 1 < argc) epoch = (unsigned short)std::atoi(argv[++i]);
        else if (!std::strcmp(argv[i], "--tamper")) tamper = true;
        else if (!std::strcmp(argv[i], "--zero-key")) zeroKey = true;
    }

    // Payload: epoch (2) + publicKeys (676*32) + signature (64).
    std::vector<unsigned char> payload(2 + (size_t)NUMBER_OF_COMPUTORS * 32 + SIGNATURE_SIZE, 0);
    std::memcpy(payload.data(), &epoch, 2);

    for (int c = 0; c < NUMBER_OF_COMPUTORS; ++c)
    {
        unsigned char subseed[32], priv[32];
        deriveSubseed("oc-test-seed", c, subseed); // same derivation as make_test_bundle
        getPrivateKey(subseed, priv);
        getPublicKey(priv, payload.data() + 2 + (size_t)c * 32);
    }

    // Arbitrator keypair + signature over K12(epoch || publicKeys).
    unsigned char arbSubseed[32], arbPriv[32], arbPub[32];
    deriveSubseed("oc-test-arbitrator", -1, arbSubseed);
    getPrivateKey(arbSubseed, arbPriv);
    getPublicKey(arbPriv, arbPub);

    const size_t signedSize = 2 + (size_t)NUMBER_OF_COMPUTORS * 32;
    unsigned char digest[32];
    KangarooTwelve(payload.data(), signedSize, digest, 32);
    sign(arbSubseed, arbPub, digest, payload.data() + signedSize);

    if (tamper)
        payload[2 + 100 * 32] ^= 0x01; // flip a bit in computor 100's key
    if (zeroKey)
        std::memset(payload.data() + 2 + 200 * 32, 0, 32); // zero computor 200's key

    CHAR16 identity[61];
    getIdentity(arbPub, identity, false);
    char identityAscii[61];
    for (int i = 0; i < 61; ++i)
        identityAscii[i] = (char)identity[i];
    fprintf(stderr, "arbitrator identity: %s\n", identityAscii);

    fwrite(payload.data(), 1, payload.size(), stdout);
    return 0;
}
