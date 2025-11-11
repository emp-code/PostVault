#include <strings.h>

#include <sodium.h>

#include "AEM_KDF.h"

// Use the 368-bit Server Master Key (SMK) with an 8-bit nonce to generate up to 16 KiB
__attribute__((nonnull))
void aem_kdf_smk(unsigned char * const out, const size_t lenOut, const uint8_t n, const unsigned char smk[AEM_KDF_SMK_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ smk + 32,
	/* Counter */ (smk[44] << 24) | (smk[45] << 16) | (n << 8),
	/* Key */ smk);
}

// Use the 312-bit Server File Key to create the server's 320-bit MFK
__attribute__((nonnull))
static void aem_kdf_sfk_internal(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const uint16_t uid, const uint32_t chunk, const unsigned char sfk[AEM_KDF_SFK_KEYLEN], const bool clear) {
	if (clear) bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ (const uint8_t[]){(binTs >> 32) & 255, ((binTs >> 40) & 3) | ((uid & 63) << 2), (uid >> 6) | (((chunk >> 16) & 3) << 6), (chunk >> 8) & 255, chunk & 255, sfk[38], sfk[37], sfk[36], sfk[35], sfk[34], sfk[33], sfk[32]},
	/* Counter */ binTs & UINT32_MAX,
	/* Key */ sfk);
}

// Generate the server's MFK
__attribute__((nonnull))
void aem_kdf_sfk(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const uint16_t uid, const uint32_t chunk, const unsigned char sfk[AEM_KDF_SFK_KEYLEN]) {
	aem_kdf_sfk_internal(out, lenOut, binTs, uid, chunk, sfk, true);
}

// Mix (XOR) the server's MFK into the client's MFK
__attribute__((nonnull))
void aem_kdf_sfk_direct(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const uint16_t uid, const uint32_t chunk, const unsigned char sfk[AEM_KDF_SFK_KEYLEN]) {
	aem_kdf_sfk_internal(out, lenOut, binTs, uid, chunk, sfk, false);
}

// Use the 338-bit UAK to generate up to 64 bytes
__attribute__((nonnull))
void aem_kdf_uak(unsigned char * const out, const size_t lenOut, const uint64_t binTs, const bool post, const uint8_t type, const unsigned char uak[AEM_KDF_UAK_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ (const uint8_t[]){(binTs >> 32) & 255, ((binTs >> 40) & 3) | (post? AEM_UAK_POST : 0) | type | (uak[42] & 12), uak[41], uak[40], uak[39], uak[38], uak[37], uak[36], uak[35], uak[34], uak[33], uak[32]},
	/* Counter */ binTs & UINT32_MAX,
	/* Key */ uak);
}

// Get UserID from UAK
__attribute__((warn_unused_result))
uint16_t aem_getUserId(const unsigned char uak[AEM_KDF_UAK_KEYLEN]) {
	uint16_t uid;
	aem_kdf_uak((unsigned char*)&uid, sizeof(uint16_t), 0, false, 0, uak);
	return uid & 4095;
}

#ifdef AEM_KDF_UMK
// Use the 360-bit User Master Key (UMK) with a 16-bit nonce to generate up to 16 KiB
__attribute__((nonnull))
void aem_kdf_umk(unsigned char * const out, const size_t lenOut, const uint16_t n, const unsigned char umk[AEM_KDF_UMK_KEYLEN]) {
	bzero(out, lenOut);
	crypto_stream_chacha20_ietf_xor_ic(out, out, lenOut,
	/* Nonce */ umk + 32,
	/* Counter */ (umk[44] << 24) | (n << 8),
	/* Key */ umk);
}
#endif
