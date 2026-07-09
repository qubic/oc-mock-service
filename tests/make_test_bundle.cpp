// make_test_bundle — generate a valid (or deliberately broken) OC authorization
// bundle plus the matching computor-keys file, for testing oc_verify.
//
// Produces, using the SAME vendored crypto oc_verify uses:
//   - a keys file: NUMBER_OF_COMPUTORS * 32 bytes of computor public keys
//   - an OcMachineInvocation bundle on stdout (raw bytes)
//
// Modes:
//   (default)      451 valid signatures  -> oc_verify should ACCEPT (exit 0)
//   --forge-sig    corrupt one signature -> 450 valid -> oc_verify REJECT (exit 1)
//   --short 450    only N signers        -> below quorum -> REJECT
//   --dup          duplicate one signer  -> distinct count below quorum -> REJECT
//
// Usage:
//   make_test_bundle --keys-out keys.bin [--forge-sig|--short N|--dup] > bundle.bin

#define NO_UEFI 1
#include "four_q.h"
#include "kangaroo_twelve.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

static constexpr int      NUMBER_OF_COMPUTORS = 676;
static constexpr int      QUORUM              = NUMBER_OF_COMPUTORS * 2 / 3 + 1; // 451
static constexpr int      SIGNATURE_SIZE      = 64;
static constexpr char     OC_AUTH_DOMAIN_SEPARATOR[13] =
    { 'Q','U','B','I','C','_','O','C','_','A','U','T','H' };

#pragma pack(push, 1)
struct OcMachineInvocationHeader
{
    long long      invocationId;
    unsigned short epoch;
    unsigned short interfaceIndex;
    unsigned short requestSize;
    unsigned short signatureCount;
};
struct SignerEntry
{
    unsigned short computorIndex;
    unsigned char  signature[SIGNATURE_SIZE];
};
struct OcAuthMessageBytes
{
    unsigned char  domainSeparator[13];
    unsigned short epoch;
    unsigned short interfaceIndex;
    long long      invocationId;
    unsigned char  paramsDigest[32];
};
#pragma pack(pop)

int main(int argc, char** argv)
{
    const char* keysOut = nullptr;
    bool forgeSig = false, dup = false;
    int shortN = 0;
    for (int i = 1; i < argc; ++i)
    {
        if (!std::strcmp(argv[i], "--keys-out") && i + 1 < argc) keysOut = argv[++i];
        else if (!std::strcmp(argv[i], "--forge-sig")) forgeSig = true;
        else if (!std::strcmp(argv[i], "--dup")) dup = true;
        else if (!std::strcmp(argv[i], "--short") && i + 1 < argc) shortN = atoi(argv[++i]);
    }
    if (!keysOut) { fprintf(stderr, "need --keys-out\n"); return 2; }

    // Deterministic keypairs: seed = "computor_seed_" + index, hashed to 32 bytes.
    static unsigned char pub[NUMBER_OF_COMPUTORS][32];
    static unsigned char subseed[NUMBER_OF_COMPUTORS][32];
    for (int c = 0; c < NUMBER_OF_COMPUTORS; ++c)
    {
        unsigned char seedbuf[32];
        std::memset(seedbuf, 0, sizeof(seedbuf));
        int n = std::snprintf((char*)seedbuf, sizeof(seedbuf), "oc-test-seed-%d", c);
        (void)n;
        // Use the hash directly as the subseed. (getSubseed is NOT applicable
        // here: it expects a 55-char lowercase seed and rejects binary input.)
        KangarooTwelve(seedbuf, sizeof(seedbuf), subseed[c], 32);
        unsigned char priv[32];
        getPrivateKey(subseed[c], priv);
        getPublicKey(priv, pub[c]);
    }

    // Write keys file.
    {
        FILE* kf = fopen(keysOut, "wb");
        if (!kf) { fprintf(stderr, "cannot open keys-out\n"); return 2; }
        for (int c = 0; c < NUMBER_OF_COMPUTORS; ++c)
            fwrite(pub[c], 1, 32, kf);
        fclose(kf);
    }

    // Build a Mock request (uint64 value).
    unsigned char requestData[8];
    unsigned long long value = 0xC0FFEEULL;
    std::memcpy(requestData, &value, 8);
    const unsigned short requestSize = 8;

    OcMachineInvocationHeader hdr;
    hdr.invocationId   = ((long long)58 << 31) | 128; // tick 58, indexInTick 128
    hdr.epoch          = 150;
    hdr.interfaceIndex = 0; // Mock
    hdr.requestSize    = requestSize;

    int signerCount = shortN ? shortN : QUORUM;
    hdr.signatureCount = (unsigned short)signerCount;

    // authMessage digest.
    unsigned char paramsDigest[32];
    KangarooTwelve(requestData, requestSize, paramsDigest, 32);
    OcAuthMessageBytes msg;
    std::memcpy(msg.domainSeparator, OC_AUTH_DOMAIN_SEPARATOR, 13);
    msg.epoch = hdr.epoch; msg.interfaceIndex = hdr.interfaceIndex;
    msg.invocationId = hdr.invocationId;
    std::memcpy(msg.paramsDigest, paramsDigest, 32);
    unsigned char authHash[32];
    KangarooTwelve((const unsigned char*)&msg, sizeof(msg), authHash, 32);

    // Emit bundle: header + request + signers.
    fwrite(&hdr, 1, sizeof(hdr), stdout);
    fwrite(requestData, 1, requestSize, stdout);

    for (int i = 0; i < signerCount; ++i)
    {
        int c = dup ? (i == 0 ? 0 : (i - 1)) : i; // --dup: reuse previous index
        SignerEntry e;
        e.computorIndex = (unsigned short)c;
        unsigned char priv[32];
        getPrivateKey(subseed[c], priv);
        sign(subseed[c], pub[c], authHash, e.signature);
        if (forgeSig && i == 0)
            e.signature[10] ^= 0xFF; // corrupt one signature
        fwrite(&e, 1, sizeof(e), stdout);
    }
    return 0;
}
