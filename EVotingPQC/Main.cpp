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


int main() {
    //init openssl
    OPENSSL_init_crypto(0, nullptr);
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    const std::string kem_alg = "Kyber512";
    const std::string sig_alg = "Dilithium2";


    std::vector<uint8_t> kem_pk, kem_sk, ct;
    std::vector<uint8_t> ss1, ss2;
    std::vector<uint8_t> sig_pk, sig_sk, sig;

    std::cout << "PRE-ELECTION\n\n";

    std::cout << "Voter's Key(could be on a smart card):\n";
    //Dilithium2 keygen
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!sig_keygen(sig_alg, sig_pk, sig_sk)) {
            std::cerr << "Signature keygen failed\n";
            return 1;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Dilithium2 keygen: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n\n";
    }

    std::cout << "Generation of Election Keys:\n";
    //Kyber512 keygen
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!kem_keygen(kem_alg, kem_pk, kem_sk)) {
            std::cerr << "KEM keygen failed\n";
            return 1;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Election Kyber512 Key generation: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }

    //Kyber encaps
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!kem_encaps(kem_alg, kem_pk, ct, ss1)) {
            std::cerr << "KEM encapsulation failed\n";
            return 1;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Election Kyber512 Key encapsulation: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }

    std::cout << "\nDecapsulation of Election Keys for each Tally Auth:\n";
    //Kyber decaps
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        if (!kem_decaps(kem_alg, ct, kem_sk, ss2)) {
            std::cerr << "KEM decapsulation failed\n";
            return 1;
        }
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Election Kyber512 Key decapsulation: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    }

    //is the shared secret matching?
    std::cout << "Shared-secret match: "
        << ((ss1 == ss2) ? "yes" : "no") << "\n\n";

    std::cout << "VOTING PHASE (CLIENT SIDE)\n\n";
    // Prompt for vote
    std::string user_input;
    do {
        std::cout << "Please cast your vote (yes/no): ";
        std::cin >> user_input;
        std::transform(user_input.begin(), user_input.end(), user_input.begin(), ::tolower);
    } while (user_input != "yes" && user_input != "no");

    //voters choice
    std::vector<uint8_t> vote_data(user_input.begin(), user_input.end());

    std::cout << "\n";


    //Encrypt the vote with AES-256-GCM using Kyber shared secret
    std::vector<uint8_t> encrypted_vote;
    std::vector<uint8_t> iv(12), tag(16);
    auto t_enc0 = std::chrono::high_resolution_clock::now();
    {
        //Derive AES key from ss1 via SHA-256
        unsigned char aes_key[32];
        SHA256(ss1.data(), ss1.size(), aes_key);
        //Generate random IV
        RAND_bytes(iv.data(), iv.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key, iv.data());

        int len;
        encrypted_vote.resize(vote_data.size());
        EVP_EncryptUpdate(ctx,
            encrypted_vote.data(), &len,
            vote_data.data(), vote_data.size());
        int ciphertext_len = len;

        EVP_EncryptFinal_ex(ctx,
            encrypted_vote.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_ctrl(ctx,
            EVP_CTRL_GCM_GET_TAG,
            tag.size(), tag.data());
        EVP_CIPHER_CTX_free(ctx);
    }
    auto t_enc1 = std::chrono::high_resolution_clock::now();
    std::cout << "Vote encryption time: "
        << std::chrono::duration<double, std::milli>(t_enc1 - t_enc0).count()
        << " ms\n";

    //Dilithium2 sign
    auto t_sig0 = std::chrono::high_resolution_clock::now();
    if (!sign_message(sig_alg, encrypted_vote, sig_sk, sig)) {
        std::cerr << "Signing encrypted vote failed\n";
        return 1;
    }
    auto t_sig1 = std::chrono::high_resolution_clock::now();
    std::cout << "Encrypted vote signing time: "
        << std::chrono::duration<double, std::milli>(t_sig1 - t_sig0).count()
        << " ms\n\n";


    std::cout << "Vote is sent to Quorum\n\n";


    std::cout << "DECRYPTION PHASE (TALLY SV SIDE)\n\n";

    std::cout << "Vote is retrieved from Quorum\n\n";


    //Verify the Dilithium2 signature on the encrypted vote
    auto t_ver0 = std::chrono::high_resolution_clock::now();
    bool sig_ok = verify_signature(sig_alg, encrypted_vote, sig, sig_pk);
    auto t_ver1 = std::chrono::high_resolution_clock::now();

    std::cout << "Encrypted vote signature verify time: "
        << std::chrono::duration<double, std::milli>(t_ver1 - t_ver0).count()
        << " ms, valid=" << (sig_ok ? "yes" : "no") << "\n";

    if (!sig_ok) {
        std::cerr << "Signature verification failed—aborting\n";
        return 1;
    }


    // Decrypt the vote with AES-256-GCM using Kyber shared secret
    std::vector<uint8_t> decrypted_vote(vote_data.size());
    auto t_dec0 = std::chrono::high_resolution_clock::now();
    {
        // Derive AES key from ss2 via SHA-256
        unsigned char aes_key[32];
        SHA256(ss2.data(), ss2.size(), aes_key);

        EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_DecryptInit_ex(dctx, nullptr, nullptr, aes_key, iv.data());

        int len;
        // No AAD in this PoC
        EVP_DecryptUpdate(dctx, nullptr, &len, nullptr, 0);

        int plaintext_len;
        EVP_DecryptUpdate(dctx,
            decrypted_vote.data(), &plaintext_len,
            encrypted_vote.data(), encrypted_vote.size());

        // Set expected tag
        EVP_CIPHER_CTX_ctrl(dctx,
            EVP_CTRL_GCM_SET_TAG,
            tag.size(), tag.data());

        // Finalize (returns <=0 on auth failure)
        if (EVP_DecryptFinal_ex(dctx,
            decrypted_vote.data() + plaintext_len,
            &len) <= 0) {
            std::cerr << "Decryption failed: authentication tag mismatch\n";
        }
        EVP_CIPHER_CTX_free(dctx);
    }
    auto t_dec1 = std::chrono::high_resolution_clock::now();
    std::string decrypted_vote_str(decrypted_vote.begin(), decrypted_vote.end());
    std::cout << "Vote decryption time: "
        << std::chrono::duration<double, std::milli>(t_dec1 - t_dec0).count()
        << " ms\n";
    std::cout << "Decrypted vote: " << decrypted_vote_str << "\n\n";

    std::cout << "TALLY PHASE (TALLY SV SIDE)\n\n";
    std::cout << "Currently out of scope of this PoC\n\n";



    std::cout << "COMPARISONS\n\n";
   
    // === Classical algorithms for comparison ===

   // Declare these before the RSA block so they’re in scope for both RSA and ECDSA
    std::vector<uint8_t> rsa_ct;
    int ct_len = 0;

    // RSA-2048 Keygen + OAEP encrypt/decrypt
    {
        // RSA-2048 Keygen
        auto r0 = std::chrono::high_resolution_clock::now();
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);
        RSA* rsa = RSA_new();
        RSA_generate_key_ex(rsa, 2048, bn, nullptr);
        BN_free(bn);
        auto r1 = std::chrono::high_resolution_clock::now();
        std::cout << "RSA-2048 keygen: "
            << std::chrono::duration<double, std::milli>(r1 - r0).count()
            << " ms\n";

        // RSA-2048 OAEP encrypt (using vote_data)
        rsa_ct.resize(RSA_size(rsa));
        auto r2 = std::chrono::high_resolution_clock::now();
        ct_len = RSA_public_encrypt(
            vote_data.size(),
            vote_data.data(),
            rsa_ct.data(),
            rsa,
            RSA_PKCS1_OAEP_PADDING
        );
        auto r3 = std::chrono::high_resolution_clock::now();
        std::cout << "RSA-2048 OAEP encrypt: "
            << std::chrono::duration<double, std::milli>(r3 - r2).count()
            << " ms\n";

        // RSA-2048 OAEP decrypt
        std::vector<uint8_t> rsa_pt(vote_data.size());
        auto r4 = std::chrono::high_resolution_clock::now();
        int pt_len = RSA_private_decrypt(
            ct_len,
            rsa_ct.data(),
            rsa_pt.data(),
            rsa,
            RSA_PKCS1_OAEP_PADDING
        );
        auto r5 = std::chrono::high_resolution_clock::now();
        std::cout << "RSA-2048 OAEP decrypt: "
            << std::chrono::duration<double, std::milli>(r5 - r4).count()
            << " ms, got='"
            << std::string(rsa_pt.begin(), rsa_pt.begin() + pt_len)
            << "'\n\n";

        RSA_free(rsa);
    }

    // ECDSA-P256 Keygen + Sign + Verify
    {
        // ECDSA-P256 Keygen
        auto e0 = std::chrono::high_resolution_clock::now();
        EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        EC_KEY_generate_key(eckey);
        auto e1 = std::chrono::high_resolution_clock::now();
        std::cout << "ECDSA-P256 keygen: "
            << std::chrono::duration<double, std::milli>(e1 - e0).count()
            << " ms\n";

        // ECDSA-P256 sign of the RSA ciphertext
        unsigned char sig_ec[72];
        unsigned int sig_ec_len = 0;
        auto e2 = std::chrono::high_resolution_clock::now();
        ECDSA_sign(
            0,
            rsa_ct.data(), ct_len,
            sig_ec, &sig_ec_len,
            eckey
        );
        auto e3 = std::chrono::high_resolution_clock::now();
        std::cout << "ECDSA-P256 sign: "
            << std::chrono::duration<double, std::milli>(e3 - e2).count()
            << " ms\n";

        // ECDSA-P256 verify
        auto e4 = std::chrono::high_resolution_clock::now();
        int ok_ec = ECDSA_verify(
            0,
            rsa_ct.data(), ct_len,
            sig_ec, sig_ec_len,
            eckey
        );
        auto e5 = std::chrono::high_resolution_clock::now();
        std::cout << "ECDSA-P256 verify: "
            << std::chrono::duration<double, std::milli>(e5 - e4).count()
            << " ms, valid=" << ok_ec << "\n";

        EC_KEY_free(eckey);
    }

    return 0;
}
