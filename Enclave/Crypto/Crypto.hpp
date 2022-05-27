#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <string>
#include <vector>

#include <ipp/ippcp.h>
#include <wolfssl/wolfcrypt/random.h> /* wc_InitRng() */
#include <wolfssl/wolfcrypt/asn.h> /* wc_KeyPemToDer() */
#include <wolfssl/wolfcrypt/rsa.h> /* wc_InitRsaKey(), wc_RsaPrivateKeyDecode() */
#include <wolfssl/wolfcrypt/signature.h> /* wc_SignatureGetSize(), wc_SignatureGenerate() */

#include "Enclave.h"
#include "Base.h"
#include "Enclave_t.h" /* print_string */

#include "Base.h"
#include "jsonsgx.hpp"
#include "Types.h"

#define SUCCESS 0
#define FAILURE -1

//#define DEBUG_LOOP

namespace crypto {

    // TODO Figure out what are the appropriate scopes for all of these implementations
    std::string rs256(const std::string string2sign, const std::string privatekey);
    std::vector<unsigned char> sha256_vec(const std::string& data);
    std::string sha256_b64(const std::string &data);
    std::string hmac_sha256_b16(const std::string string2sign, const std::string secret);
    std::string hmac_sha256_b64(const std::string string2sign, const std::string secret);
    std::string hmac_sha384_b16(const std::string string2sign, const std::string secret);
    std::string hmac_sha512_b64(const std::vector<unsigned char>& string2sign, const std::string secret);
    std::string hmac_sha512_kraken(const std::string string2sign, const std::string nonce, const std::string secret);
    std::string hmac_sha512_krakenfut(const std::string string2sign, const std::string nonce, const std::string secret);



    inline std::string hmac_sha512_kraken(std::string path, std::string nonce, std::string b64secret)
    {
        std::vector<unsigned char> nonce_postdata = sha256_vec(nonce);
        std::vector<unsigned char> data(path.begin(), path.end());
        data.insert(data.end(), nonce_postdata.begin(), nonce_postdata.end());
        std::string secret = base::decode<alphabet::base64>(base::pad<alphabet::base64>(b64secret));
        return hmac_sha512_b64(data, secret);
    }

    inline std::string hmac_sha512_krakenfut(std::string path, std::string nonce, std::string b64secret)
    {
        std::string combo = nonce + path;
        std::vector<unsigned char> hashedcombo = sha256_vec(combo);
        std::string secret = base::decode<alphabet::base64>(base::pad<alphabet::base64>(b64secret));
        return hmac_sha512_b64(hashedcombo, secret);
    }

    /* The crypto APIs below will take C++ strings as inputs and return C++
     * strings as outputs. This is done because the underlying primitives
     * expect C byte arrays, so the wrappers below handle the details of those
     * conversions.
     * All the functions are named in the following style: <algo>_<output>,
     * with b16 meaning base 16 (hexadecimal) and b64 meaning base 64.
     */

    /* TODO There is a potential for a signature mismatch because all of the
     * code below assumes that the input strings do NOT have NULL characters in
     * the middle of the string. This is usually a safe assumption, but some
     * exchanges use base64-encoded secrets, which *MAY* decode to an array of
     * bytes that contains a NULL byte (e.g., Coinbase and Kraken). In that
     * situation, the C-string would terminate earlier than expected. The only
     * way to fix this is to represent the ExchangeInfo.secret field as an
     * array of bytes, rather than as a std::string.
     */

    /**
     * Computes the HMAC-SHA384 of a string, using another string as the key,
     * and returns the digest in a hexadecimal representation as an ASCII
     * -encoded string.
     */
    inline std::string hmac_sha384_b16(const std::string string2sign, const std::string secret)
    {
        IppStatus ipp_ret;
        const uint8_t *secret_u8 = reinterpret_cast<const uint8_t *>(secret.c_str());
        int secretlen = strlen((const char *)secret_u8);
        const uint8_t *msg_u8 = reinterpret_cast<const uint8_t *>(string2sign.c_str());
        int msglen = strlen((const char *)msg_u8);
        int digestlen = 384/8;
        uint8_t digest[digestlen];

        ipp_ret = ippsHMACMessage_rmf(
            msg_u8, msglen,
            secret_u8, secretlen,
            digest, digestlen,
            ippsHashMethod_SHA384());
        if (ipp_ret != ippStsNoErr) {
            //TODO Do something safer than returning an empty string, like aborting
            return std::string();
        }

        std::string res = base::hexStr(digest, digestlen);
        return res;
    }

    /**
     * Computes the HMAC-SHA256, writing the digest as raw bytes to pDigest.
     */
    inline IppStatus hmac_sha256(const uint8_t *msg, const int msglen,
                          const uint8_t *secret, const int secretlen,
                          uint8_t *pDigest)
    {
        return ippsHMACMessage_rmf(msg, msglen, secret, secretlen, pDigest,
                                   256 / 8, ippsHashMethod_SHA256());
    }

    /**
     * Computes the HMAC-SHA256 of a string, using another string as the key,
     * and returns the digest in a hexadecimal representation as an ASCII-
     * encoded string.
     */
    inline std::string hmac_sha256_b16(const std::string string2sign, const std::string secret)
    {
        IppStatus ipp_ret;
        const uint8_t *secret_u8 = reinterpret_cast<const uint8_t *>(secret.c_str());
        int secretlen = strlen((const char *)secret_u8);
        const uint8_t *msg_u8 = reinterpret_cast<const uint8_t *>(string2sign.c_str());
        int msglen = strlen((const char *)msg_u8);
        int digestlen = 256/8;
        uint8_t digest[digestlen];

        ipp_ret = hmac_sha256(msg_u8, msglen, secret_u8, secretlen, digest);
        if (ipp_ret != ippStsNoErr) {
            //TODO Do something safer than returning an empty string, like aborting
            return std::string();
        }

        std::string res = base::hexStr(digest, digestlen);
        return res;
    }

    /**
     * Computes the HMAC-SHA256 of a string, using another string as the key,
     * and returns the digest in a base64-encoded ASCII string.
     */
    inline std::string hmac_sha256_b64(const std::string string2sign, const std::string secret)
    {
        IppStatus ipp_ret;
        const uint8_t *secret_u8 = reinterpret_cast<const uint8_t *>(secret.c_str());
        int secretlen = strlen((const char *)secret_u8);
        const uint8_t *msg_u8 = reinterpret_cast<const uint8_t *>(string2sign.c_str());
        int msglen = strlen((const char *)msg_u8);
        int digestlen = 256/8;
        uint8_t digest[digestlen];

        ipp_ret = hmac_sha256(msg_u8, msglen, secret_u8, secretlen, digest);
        if (ipp_ret != ippStsNoErr) {
            //TODO Do something safer than returning an empty string, like aborting
            return std::string();
        }

        std::string res = base::pad<alphabet::base64>(base::encode<alphabet::base64>(std::string(reinterpret_cast<char*>(digest), digestlen)));
        return res;
    }

    /**
     * Computes the HMAC-SHA512 of a string, using another string as the key,
     * and returns the digest in a base64-encoded ASCII string.
     */
    inline std::string hmac_sha512_b64(const std::vector<unsigned char>& string2sign,
          const std::string secret)
    {
        IppStatus ipp_ret;
        int secretlen = strlen(secret.c_str());
        const uint8_t *secret_u8 = reinterpret_cast<const uint8_t *>(secret.c_str());
        int digestlen = 512/8;
        uint8_t digest[digestlen];

        ipp_ret = ippsHMACMessage_rmf(
            string2sign.data(), string2sign.size(),
            secret_u8, secretlen,
            digest, digestlen,
            ippsHashMethod_SHA512());
        if (ipp_ret != ippStsNoErr) {
            //TODO Do something safer than returning an empty string, like aborting
            return std::string();
        }

        std::string encoded_res = base::pad<alphabet::base64>(base::encode<alphabet::base64>(std::string(reinterpret_cast<char*>(digest), digestlen)));
        return encoded_res;
    }

    /**
     * Computes the SHA256 hash of a string, returning the digest as a vector
     */
    inline std::vector<unsigned char> sha256_vec(const std::string& data)
    {
        IppStatus ipp_ret;
        std::vector<unsigned char> digest(256/8);
        ipp_ret = ippsSHA256MessageDigest((const uint8_t *)data.data(), data.length(), digest.data()); //XXX ippsSHA256MessageDigest is deprecated, apparently
        if (ipp_ret != ippStsNoErr) {
            //TODO -- abort or something? do something safer than returning empty
            return std::vector<unsigned char>();
        }
        return digest;
    }

    /**
     * Computes the SHA256 hash of a string, returning the digest as a base64-
     * encoded ASCII string
     */
    inline std::string sha256_b64(const std::string& data)
    {
        IppStatus ipp_ret;
        std::vector<unsigned char> digest = sha256_vec(data);
        std::string encoded_res = base::pad<alphabet::base64>(base::encode<alphabet::base64>(std::string(reinterpret_cast<char*>(digest.data()), digest.size())));
        return encoded_res;
    }

    inline std::string rs256(const std::string string2sign, const std::string privatekey) {
        int ret;
        uint8_t buf[4096] = {0};
        word32 offset = 0, siglen, keylen;
        uint8_t *sigbuf = NULL;
        RsaKey key;
        WC_RNG rng;

        ret = wc_KeyPemToDer(reinterpret_cast<const unsigned char *>(privatekey.c_str()), privatekey.length(),
                                buf, sizeof(buf), NULL);
        if (ret < 0) {
            //TODO Do something safer than returning an empty string
            return std::string();
        }

        ret = wc_InitRsaKey(&key, NULL);
        if (ret != 0) {
            //TODO Do something safer than returning an empty string
            return std::string();
        }

        ret = wc_RsaPrivateKeyDecode(buf, &offset, &key, sizeof(buf));
        if (ret != 0) {
            //TODO Do something safer than returning an empty string
            //TODO Memory leaks `key` by not calling `wc_FreeRsaKey()`
            return std::string();
        }
        keylen = offset;

 
        ret = wc_SignatureGetSize(WC_SIGNATURE_TYPE_RSA_W_ENC, &key, sizeof(key));


        if (ret < 0) {
            //TODO Do something safer than returning an empty string
            //TODO Memory leaks `key` by not calling `wc_FreeRsaKey()`
            return std::string();
        }
        siglen = ret;

        sigbuf = (uint8_t *)calloc(siglen, 1);
        if (sigbuf == NULL) {
            //TODO Do something safer than returning an empty string
            //TODO Memory leaks `key` by not calling `wc_FreeRsaKey()`
            return std::string();
        }

        ret = wc_InitRng(&rng);
        if (ret < 0) {
            //TODO Do something safer than returning an empty string
            //TODO Memory leaks `key` by not calling `wc_FreeRsaKey()`
            //TODO Memory leaks `sigbuf`
            return std::string();
        }

        ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256, WC_SIGNATURE_TYPE_RSA_W_ENC,
                                   reinterpret_cast<const byte *>(string2sign.c_str()), string2sign.length(),
                                   sigbuf, &siglen, &key, sizeof(key), &rng);
        
        
        std::string b64sig = base::trim<alphabet::base64url>(base::encode<alphabet::base64url>(std::string(reinterpret_cast<char *>(sigbuf), siglen)));


        if (sigbuf) free(sigbuf);
        wc_FreeRng(&rng);
        wc_FreeRsaKey(&key);

        return b64sig;
    }
}

#endif
