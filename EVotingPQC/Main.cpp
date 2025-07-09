#include <oqs/oqs.h> //using vcpkg for package managenet
//then using liboqs for quantum safe algorithms such as Dilithium and Kyber
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

#include <nlohmann/json.hpp>
#include <curl/curl.h>//added these for posting to that htpp endpoint
//added openssl lib to compare my solution with classical algs (RSA and ECDSA)
//added these defines to surpress deprecated build errors (will do sth better)
#define OPENSSL_API_COMPAT 30000
#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/evp.h>      
#include <openssl/obj_mac.h>  
#include <openssl/rsa.h>      
#include <openssl/bn.h>       
#include <openssl/sha.h>      
#include <openssl/ec.h>       
#include <openssl/ecdsa.h>    
#include <openssl/provider.h>
#include <openssl/rand.h> //for rand bytes
#include <openssl/hmac.h>   // for HKDF


#include <chrono>  // for timing

//we will cast these votes to a smart contract that
//checks if a voter is eligible, has already voted, accept the vote and write to blockchain
//we used quorum (a fork of ethereum) blockchain on kaleido for testing purposes that has max 3 nodes
//the more nodes the better decentralization
//IBFT consensus needs that 2 thirds of nodes need to agree in order for a vote to be written to blockchain
//i want to run quorum locally in the future i installed geth, i got quorum from git



static const std::string RPC_URL = "https://e0tm82438a-e0vvjmxi4s-rpc.de0-aws.kaleido.io/";
static const std::string FROM_ADDRESS = "0xf45f7cc54f856b146fc996302b5c0542f82cf292";//LucaInc
static const std::string CONTRACT_ADDR = "0xmycontractaddress";//in works

//hex code helper
std::string toHex(const std::vector<uint8_t>& data) {
    static const char* hexChars = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2 + 2);
    out += "0x";
    for (uint8_t b : data) {
        out += hexChars[(b >> 4) & 0xF];
        out += hexChars[b & 0xF];
    }
    return out;
}

/*
// testinng for vote casting
std::string encodeCastVote(const std::vector<uint8_t>& cipher,
    const std::vector<uint8_t>& sig) {
    // 1) selector
    std::string data = "0x09eef43e";
    // 2) offset to cipher payload (0x40)
    data += "0000000000000000000000000000000000000000000000000000000000000040";
    // 3) offset to sig payload (0x40 + padded cipher length)
    //    here pad both to 32 bytes
    data += "0000000000000000000000000000000000000000000000000000000000000080";
    // 4) cipher length (in last 64-bit)
    uint64_t clen = cipher.size();
    std::ostringstream oss;
    oss << std::hex << clen;
    auto clenHex = oss.str();
    data += std::string(64 - clenHex.length(), '0') + clenHex;
    data += std::string(2 * (32 - cipher.size()), '0') + toHex(cipher).substr(2);
    // 5) signature length
    oss.str(""); oss.clear();
    oss << std::hex << sig.size();
    auto slenHex = oss.str();
    data += std::string(64 - slenHex.length(), '0') + slenHex;
    data += std::string(2 * (32 - sig.size()), '0') + toHex(sig).substr(2);
    return data;
}


bool sendVoteTx(const std::string& payloadHex) {
    nlohmann::json rpc = {
      {"jsonrpc","2.0"},
      {"method","eth_sendTransaction"},
      {"params", {{
           {"from", FROM_ADDRESS},
           {"to",   CONTRACT_ADDR},
           {"gas",  "0x5208"},     // 21000 gas
           {"data", payloadHex}
      }}},
      {"id",1}
    };

    std::string s = rpc.dump();
    CURL* curl = curl_easy_init();
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, RPC_URL.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, s.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return true;
}
*/

//Generate a kyber key
bool kem_keygen(const std::string& kem_name,
    std::vector<uint8_t>& pk,
    std::vector<uint8_t>& sk) {
    OQS_KEM* kem = OQS_KEM_new(kem_name.c_str());
    if (!kem) return false;
    pk.resize(kem->length_public_key);
    sk.resize(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pk.data(), sk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return false;
    }
    OQS_KEM_free(kem);
    return true;
}

//Encapsulate a message with kyber
bool kem_encaps(const std::string& kem_name,
    const std::vector<uint8_t>& pk,
    std::vector<uint8_t>& ct,
    std::vector<uint8_t>& ss) {
    OQS_KEM* kem = OQS_KEM_new(kem_name.c_str());
    if (!kem) return false;
    ct.resize(kem->length_ciphertext);
    ss.resize(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return false;
    }
    OQS_KEM_free(kem);
    return true;
}

//Test decapsulation of that message with kyber
bool kem_decaps(const std::string& kem_name,
    const std::vector<uint8_t>& ct,
    const std::vector<uint8_t>& sk,
    std::vector<uint8_t>& ss) {
    OQS_KEM* kem = OQS_KEM_new(kem_name.c_str());
    if (!kem) return false;
    ss.resize(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, ss.data(), ct.data(), sk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        return false;
    }
    OQS_KEM_free(kem);
    return true;
}

//Generate a Dilithium keypair
bool sig_keygen(const std::string& sig_name,
    std::vector<uint8_t>& pk,
    std::vector<uint8_t>& sk) {
    OQS_SIG* sig = OQS_SIG_new(sig_name.c_str());
    if (!sig) return false;
    pk.resize(sig->length_public_key);
    sk.resize(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pk.data(), sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return false;
    }
    OQS_SIG_free(sig);
    return true;
}

//Message signing with dilithium
bool sign_message(const std::string& sig_name,
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& sk,
    std::vector<uint8_t>& signature) {
    OQS_SIG* sig = OQS_SIG_new(sig_name.c_str());
    if (!sig) return false;
    signature.resize(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, signature.data(), &sig_len,
        msg.data(), msg.size(), sk.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        return false;
    }
    signature.resize(sig_len);
    OQS_SIG_free(sig);
    return true;
}

//Verify a Dilithium signature
bool verify_signature(const std::string& sig_name,
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& pk) {
    OQS_SIG* sig = OQS_SIG_new(sig_name.c_str());
    if (!sig) return false;
    bool ok = (OQS_SIG_verify(sig,
        msg.data(), msg.size(),
        signature.data(), signature.size(),
        pk.data()) == OQS_SUCCESS);
    OQS_SIG_free(sig);
    return ok;
}

// HKDF-SHA-256 (RFC 5869) – Extract + Expand, single-shot
bool hkdf_sha256(const uint8_t* secret, size_t secret_len,
    const uint8_t* info, size_t info_len,
    uint8_t* out_key, size_t out_len)
{
    const size_t HASH_LEN = 32;               // SHA-256 output
    // ----- HKDF-Extract -----
    uint8_t prk[HASH_LEN];
    unsigned int prk_len = 0;
    HMAC(EVP_sha256(),                         // salt = zero-length
        nullptr, 0,
        secret, secret_len,
        prk, &prk_len);

    // ----- HKDF-Expand -----
    uint8_t prev[HASH_LEN];
    size_t pos = 0;
    uint8_t counter = 1;

    while (pos < out_len) {
        HMAC_CTX* hctx = HMAC_CTX_new();
        HMAC_Init_ex(hctx, prk, HASH_LEN, EVP_sha256(), nullptr);
        if (pos != 0) HMAC_Update(hctx, prev, HASH_LEN);
        HMAC_Update(hctx, info, info_len);
        HMAC_Update(hctx, &counter, 1);
        unsigned int len = 0;
        HMAC_Final(hctx, prev, &len);
        HMAC_CTX_free(hctx);

        size_t chunk = min((size_t)HASH_LEN, out_len - pos);
        memcpy(out_key + pos, prev, chunk);
        pos += chunk;
        counter++;
    }
    OPENSSL_cleanse(prk, HASH_LEN);
    OPENSSL_cleanse(prev, HASH_LEN);
    return true;
}


int main() {
    //init openssl
    OPENSSL_init_crypto(0, nullptr);
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    const std::string kem_alg = "Kyber512";
    const std::string sig_alg = "Dilithium2";


    std::vector<uint8_t> kem_pk, kem_sk;
    std::vector<uint8_t> sig_pk, sig_sk;

    std::cout << "PRE-ELECTION\n\n";

    std::cout << "Voter's Key(could be on a smart card):\n";
    //Dilithium2 keygen
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        sig_keygen(sig_alg, sig_pk, sig_sk);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Dilithium2 keygen: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n\n";
    }

    std::cout << "Generation of Election Key:\n";
    //Kyber512 keygen
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        kem_keygen(kem_alg, kem_pk, kem_sk);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Kyber512 keygen: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }

    std::cout << "VOTING PHASE (CLIENT SIDE)\n\n";
    // Prompt for vote
    std::string user_input;
    std::cout << "Cast your vote (yes / no): ";
    std::getline(std::cin, user_input);
    // Added a check if vote really is yes or no
    if (user_input != "yes" && user_input != "no") {
        std::cerr << "Invalid choice\n";
        return 1;
    }
    std::vector<uint8_t> vote_data(user_input.begin(), user_input.end());

    //voters choice

    std::cout << "\n";

    //Kyber encaps (each ballot)
    std::vector<uint8_t> ctKEM, shared_secret;
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        kem_encaps(kem_alg, kem_pk, ctKEM, shared_secret);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Kyber512 encapsulation: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }

    // Derive AES-256-GCM key from Kyber shared_secret using HKDF_SHA256
    // The shared_secret will be used just here on the client's machine

    uint8_t aes_key[32];
    uint8_t iv[12];
    const uint8_t info[] = "PQC-eVote-AES";

    uint8_t key_iv[sizeof(aes_key) + sizeof(iv)];    // 44 bytes
    hkdf_sha256(shared_secret.data(), shared_secret.size(),
        info, sizeof(info) - 1,
        key_iv, sizeof(key_iv));

    memcpy(aes_key, key_iv, sizeof(aes_key));
    memcpy(iv, key_iv + sizeof(aes_key), sizeof(iv));
    OPENSSL_cleanse(key_iv, sizeof(key_iv));
    // 96-bit nonce

    // Now encrypt the yes/no vote with the derived key

    std::vector<uint8_t> ciphertext(vote_data.size() + 16);   // space for padding
    int out_len = 0, fin_len = 0;
    unsigned char tag[16];
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key, iv);
        EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
            vote_data.data(), vote_data.size());
        EVP_EncryptFinal_ex(ctx, ciphertext.data() + out_len, &fin_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
        EVP_CIPHER_CTX_free(ctx);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "AES-256-GCM encrypt: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }
    ciphertext.resize(out_len + fin_len);

    // Build the message: encrypted vote, iv, tag and 
    // kyber ciphertext that will be used to derive the aes key for each vote

    std::vector<uint8_t> msg;
    msg.insert(msg.end(), ctKEM.begin(), ctKEM.end());
    msg.insert(msg.end(), iv, iv + sizeof(iv));
    msg.insert(msg.end(), ciphertext.begin(), ciphertext.end());
    msg.insert(msg.end(), tag, tag + sizeof(tag));

    //Dilithium2 sign
    std::vector<uint8_t> signature;
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        sign_message(sig_alg, msg, sig_sk, signature);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Dilithium2 sign: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }

    std::cout << "Vote is sent to Quorum\n\n";

    std::cout << "Vote is retrieved from Quorum\n\n";

    std::cout << "TALLY PHASE (TALLY SV SIDE)\n\n";



    //Verify the Dilithium2 signature (a tally could do this)
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        bool ok = verify_signature(sig_alg, msg, signature, sig_pk);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Dilithium2 verify: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms, valid=" << (ok ? "yes" : "no") << "\n";
        if (!ok) { std::cerr << "Signature check failed\n"; return 1; }
    }


    // ── 8.  Tally-side Kyber decapsulation  +  AES-GCM decrypt ──────
    {
        // 8a.  Recreate shared secret from ctKEM and private key
        std::vector<uint8_t> shared_secret_tally;
        auto t_dec0 = std::chrono::high_resolution_clock::now();
        bool ok_dec = kem_decaps(kem_alg, ctKEM, kem_sk, shared_secret_tally);
        auto t_dec1 = std::chrono::high_resolution_clock::now();

        if (!ok_dec) {
            std::cerr << "Kyber decapsulation failed on tally side\n";
            return 1;
        }
        std::cout << "Kyber512 decapsulation (tally): "
            << std::chrono::duration<double, std::milli>(t_dec1 - t_dec0).count()
            << " ms\n";

        // 8b.  Derive AES key + IV with the SAME HKDF
        uint8_t aes_key_tally[32];
        uint8_t iv_tally[12];
        const uint8_t info[] = "PQC-eVote-AES";

        uint8_t key_iv[sizeof(aes_key_tally) + sizeof(iv_tally)]; // 44 B
        hkdf_sha256(shared_secret_tally.data(), shared_secret_tally.size(),
            info, sizeof(info) - 1,
            key_iv, sizeof(key_iv));

        memcpy(aes_key_tally, key_iv, sizeof(aes_key_tally));
        memcpy(iv_tally, key_iv + sizeof(aes_key_tally), sizeof(iv_tally));
        OPENSSL_cleanse(key_iv, sizeof(key_iv));

        // 8c.  AES-256-GCM decrypt and tag-check
        std::vector<uint8_t> plain(vote_data.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv_tally), nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key_tally, iv_tally);

        int len = 0;
        EVP_DecryptUpdate(ctx, plain.data(), &len,
            ciphertext.data(), ciphertext.size());
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

        int ret = EVP_DecryptFinal_ex(ctx, plain.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        auto t_dec2 = std::chrono::high_resolution_clock::now();
        std::cout << "AES-256-GCM decrypt (tally): "
            << std::chrono::duration<double, std::milli>(t_dec2 - t_dec1).count()
            << " ms, success=" << (ret > 0 ? "yes" : "no") << "\n";

        if (ret > 0) {
            std::string recovered(plain.begin(), plain.begin() + vote_data.size());
            std::cout << "Decrypted vote = \"" << recovered << "\"\n\n";
        }
        else {
            std::cerr << "Tag verification failed—ballot rejected\n";
            return 1;
        }
    }


    std::cout << "COMPARISONS\n\n";
   
    // === Classical algorithms for comparison ===

   // Declare these before the RSA block so they’re in scope for both RSA and ECDSA
    std::vector<uint8_t> rsa_ct;
    int ct_len = 0;

    // RSA-2048 keygen + OAEP encrypt/decrypt
    {
        auto r0 = std::chrono::high_resolution_clock::now();
        BIGNUM* bn = BN_new(); BN_set_word(bn, RSA_F4);
        RSA* rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        BN_free(bn);
        auto r1 = std::chrono::high_resolution_clock::now();
        std::cout << "RSA-2048 keygen: "
            << std::chrono::duration<double, std::milli>(r1 - r0).count()
            << " ms\n";

        rsa_ct.resize(RSA_size(rsa));
        auto r2 = std::chrono::high_resolution_clock::now();
        ct_len = RSA_public_encrypt(
            vote_data.size(), vote_data.data(),
            rsa_ct.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        auto r3 = std::chrono::high_resolution_clock::now();
        std::cout << "RSA-2048 OAEP encrypt: "
            << std::chrono::duration<double, std::milli>(r3 - r2).count()
            << " ms\n";

        std::vector<uint8_t> rsa_pt(vote_data.size());
        auto r4 = std::chrono::high_resolution_clock::now();
        RSA_private_decrypt(ct_len, rsa_ct.data(), rsa_pt.data(),
            rsa, RSA_PKCS1_OAEP_PADDING);
        auto r5 = std::chrono::high_resolution_clock::now();
        std::cout << "RSA-2048 OAEP decrypt: "
            << std::chrono::duration<double, std::milli>(r5 - r4).count()
            << " ms\n\n";
        RSA_free(rsa);
    }

    // ECDSA-P256 keygen / sign / verify
    {
        auto e0 = std::chrono::high_resolution_clock::now();
        EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(eckey);
        auto e1 = std::chrono::high_resolution_clock::now();
        std::cout << "ECDSA-P256 keygen: "
            << std::chrono::duration<double, std::milli>(e1 - e0).count()
            << " ms\n";

        unsigned char sig_ec[72]; unsigned int sig_ec_len;
        auto e2 = std::chrono::high_resolution_clock::now();
        ECDSA_sign(0, rsa_ct.data(), ct_len,
            sig_ec, &sig_ec_len, eckey);
        auto e3 = std::chrono::high_resolution_clock::now();
        std::cout << "ECDSA-P256 sign: "
            << std::chrono::duration<double, std::milli>(e3 - e2).count()
            << " ms\n";

        auto e4 = std::chrono::high_resolution_clock::now();
        int ok_ec = ECDSA_verify(0, rsa_ct.data(), ct_len,
            sig_ec, sig_ec_len, eckey);
        auto e5 = std::chrono::high_resolution_clock::now();
        std::cout << "ECDSA-P256 verify: "
            << std::chrono::duration<double, std::milli>(e5 - e4).count()
            << " ms, valid=" << ok_ec << "\n";
        EC_KEY_free(eckey);
    }

    return 0;
}
