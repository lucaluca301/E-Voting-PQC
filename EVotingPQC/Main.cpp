#include <oqs/oqs.h> //using vcpkg for package managenet
//then using liboqs for quantum safe algorithms such as Dilithium and Kyber
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>

#include <sstream>     // ostringstream
#include <iomanip>     // std::hex, setw, setfill

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
#include <openssl/pem.h>   // for size comparisons


#include <chrono>  // for timing
#include <array>   //


//we will cast these votes to a smart contract that
//checks if a voter is eligible, has already voted, accept the vote and write to blockchain
//we used quorum (a fork of ethereum) blockchain on wsl2 for testing purposes that has max 3 nodes
//the more nodes the better decentralization
//IBFT consensus needs that 2 thirds of nodes need to agree in order for a vote to be written to blockchain
//i want to run quorum locally in the future i installed geth, i got quorum from git


// They're hardcoded but this is still a PoC
static const std::string RPC_URL ="http://127.0.0.1:8545";
static const std::string FROM_ADDRESS = "0xc9c913c8c3c1cd416d80a0abf475db2062f161f6";
static const std::string CONTRACT_ADDR = "0x0C9E3D598b9F95D266fef76019674ea5458f2d5F";// Smart contract's address

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

std::string pad32(size_t n) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(64) << n;
    return oss.str();
}

std::string encodeDyn(const std::vector<uint8_t>& v) {
    std::string hex = toHex(v).substr(2);             // drop 0x
    size_t len = v.size();
    size_t padded = ((len + 31) / 32) * 32;
    hex += std::string((padded - len) * 2, '0');      // right-pad
    return pad32(len) + hex;
}

std::string encodeCastVote(
    const std::vector<uint8_t>& ct,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& cipher,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& sig)
{
    const std::string selector = "09eef43e";
    // offsets start after the 5*32-byte headers = 0xa0
    uint64_t off2 = 0xa0 + encodeDyn(ct).size() / 2;
    uint64_t off3 = off2 + encodeDyn(iv).size() / 2;
    uint64_t off4 = off3 + encodeDyn(cipher).size() / 2;
    uint64_t off5 = off4 + encodeDyn(tag).size() / 2;

    std::string data = "0x" + selector
        + pad32(0xa0)          // offset1
        + pad32(off2)
        + pad32(off3)
        + pad32(off4)
        + pad32(off5)
        + encodeDyn(ct)
        + encodeDyn(iv)
        + encodeDyn(cipher)
        + encodeDyn(tag)
        + encodeDyn(sig);

    return data;
}

// Generate a kyber key
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

// Encapsulate a message with kyber
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

// Generate a Dilithium keypair
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

// Message signing with dilithium
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

// Verify a Dilithium signature
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

// JSON-RPC helper: pushes the ABI-encoded vote payload
bool sendVoteTx(const std::string& payloadHex)
{
    // Build RPC body
    nlohmann::json rpc = {
        { "jsonrpc", "2.0" },
        { "method",  "eth_sendTransaction" },
        { "params", nlohmann::json::array({ {
             { "from", FROM_ADDRESS },            // 0xc9c913c8c3c1cd416d80a0abf475db2062f161f6
             { "to",   CONTRACT_ADDR },           // 0x0C9E3D598b9F95D266fef76019674ea5458f2d5F
             { "gas",  "0x7a1200" },              // 8 000 000 (hex)
             { "data", payloadHex }
        } }) },
        { "id", 1 }
    };
    const std::string body = rpc.dump();

    // Prepare libcurl
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "curl_easy_init() failed\n";
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8545");   // same node Explorer talks to
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    // Capture the reply
    std::string reply;                                     // will hold the node’s answer
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* out = static_cast<std::string*>(userdata);
            out->append(ptr, size * nmemb);
            return size * nmemb;
        });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &reply);

    // Perform Request
    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "libcurl error: " << curl_easy_strerror(res) << '\n';
        return false;
    }

    std::cout << "RPC reply: " << reply << '\n';

    try {
        auto j = nlohmann::json::parse(reply);
        // success - "result" contains the tx-hash
        // failure - "error" contains {code,message}
        return j.contains("result");
    }
    catch (const std::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << '\n';
        return false;
    }
}


// Helper to fetch the transaction from it's hash
std::string fetchTxInput(const std::string& txHash)
{
    nlohmann::json rpc = {
        { "jsonrpc","2.0" },
        { "method","eth_getTransactionByHash" },
        { "params", nlohmann::json::array({ txHash }) },
        { "id", 1 }
    };
    std::string body = rpc.dump(), reply;
    CURL* curl = curl_easy_init();
    struct curl_slist* hdr = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, RPC_URL.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
        +[](char* p, size_t s, size_t n, void* d) {((std::string*)d)->append(p, s * n); return s * n; });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &reply);
    CURLcode ok = curl_easy_perform(curl);
    curl_slist_free_all(hdr); curl_easy_cleanup(curl);
    if (ok != CURLE_OK) throw std::runtime_error("curl failed");
    auto j = nlohmann::json::parse(reply);
    return j["result"]["input"];                 // "0x09eef43e…"
}

// Functions for ABI decoding the payload once retrieved
struct DecodedVote {
    std::vector<uint8_t> ct, iv, cipher, tag, sig;
};
std::vector<uint8_t> hex2vec(const std::string& h)
{
    std::vector<uint8_t> v; v.reserve((h.size() - 2) / 2);
    for (size_t i = 2; i < h.size(); i += 2)
        v.push_back(std::stoi(h.substr(i, 2), nullptr, 16));
    return v;
}
uint64_t be64(const std::string& word32)
{
    return std::stoull(word32.substr(word32.size() - 16), nullptr, 16);
}
DecodedVote decodeCastVoteInput(const std::string& input)
{
    if (input.substr(0, 10) != "0x09eef43e") throw std::runtime_error("selector mismatch");
    // strip "0x" + selector
    std::string data = "0x" + input.substr(10);
    auto bytes = hex2vec(data);
    auto word = [&](size_t ofs) { return std::string(data.begin() + 2 + ofs * 64, data.begin() + 2 + (ofs + 1) * 64); };
    size_t base = 4 * 32;                        // 4 bytes sel + 4*32-B heads already read
    size_t o1 = be64(word(0));
    size_t o2 = be64(word(1));
    size_t o3 = be64(word(2));
    size_t o4 = be64(word(3));
    size_t o5 = be64(word(4));
    auto slice = [&](size_t off) {
        size_t len = be64(data.substr(2 + off * 2, 64));
        off += 32;
        return std::vector<uint8_t>(bytes.begin() + off, bytes.begin() + off + len);
        };
    DecodedVote v{
        slice(o1), slice(o2), slice(o3), slice(o4), slice(o5)
    };
    return v;
}
// Temp helper to see if kyber really generated different shared secrets for the same pk as hex
void dump(const std::string& label, const std::vector<uint8_t>& v) {
    std::cout << label << " (" << v.size() << " B) = "
        << toHex(v).substr(0, 34)  // show first 16 bytes: 0x____________
        << " …\n";
}

int main() {
    OPENSSL_init_crypto(0, nullptr);
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "legacy");

    const std::string kem_alg = "Kyber512";
    const std::string sig_alg = "Dilithium2";


    std::vector<uint8_t> kem_pk, kem_sk;
    std::vector<uint8_t> sig_pk, sig_sk;

    std::cout << "PRE-ELECTION\n\n";

    std::cout << "Voter's Key(could be on a smart card):\n";
    // Dilithium2 keygen
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        sig_keygen(sig_alg, sig_pk, sig_sk);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Dilithium2 keygen: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n\n";
    }

    std::cout << "Generation of Election Key:\n";
    // Kyber512 keygen
    {
        auto t0 = std::chrono::high_resolution_clock::now();
        kem_keygen(kem_alg, kem_pk, kem_sk);
        auto t1 = std::chrono::high_resolution_clock::now();
        std::cout << "Kyber512 keygen: "
            << std::chrono::duration<double, std::milli>(t1 - t0).count()
            << " ms\n";
    } 
    /* TESTING PURPOSES
    std::cout << "\n Kyber512 multiple encapsulations with SAME pk:\n";
    for (int i = 0; i < 8; ++i) {          // run 8 times
        std::vector<uint8_t> ct_i, ss_i;
        kem_encaps(kem_alg, kem_pk, ct_i, ss_i);

        std::cout << "  Encapsulation " << i + 1 << ":\n";
        dump("    ct", ct_i);
        dump("    ss", ss_i);
    }*/
    std::cout << std::endl;

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

    std::cout << "\n";

    // Kyber encaps
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

    // Build the message: encrypted vote, iv(for debugging), tag and 
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

    // Build ABI payload and push to the contract

    std::vector<uint8_t> ivVec(iv, iv + sizeof(iv));
    std::vector<uint8_t> cipherVec(ciphertext.begin(), ciphertext.end());
    std::vector<uint8_t> tagVec(tag, tag + sizeof(tag));

    std::string payload = encodeCastVote(
        ctKEM,         // Kyber ciphertext
        ivVec,         // 12-byte IV for debugging
        cipherVec,     // AES-GCM ciphertext
        tagVec,        // 16-byte tag
        signature      // Dilithium2 signature
    );

    if (!sendVoteTx(payload)) {
        std::cerr << "RPC sendVoteTx failed\n";
        return 1;
    }


    std::cout << "Vote is sent to Quorum\n\n";

    std::cout << "Vote is retrieved from Quorum\n\n";

    std::cout << "TALLY PHASE (TALLY SV SIDE)\n\n";

    try {
        /* 1. obtain the tx-hash from user or from the RPC reply above */
        std::string hash;
        std::cout << "Enter tx-hash to tally (0xetc): ";
        std::getline(std::cin, hash);

        /* 2. pull raw input */
        std::string input = fetchTxInput(hash);
        auto vote = decodeCastVoteInput(input);

        /* 3. verify signature */
        std::vector<uint8_t> msg;                   // reconstruct exactly as sender did
        msg.insert(msg.end(), vote.ct.begin(), vote.ct.end());
        msg.insert(msg.end(), vote.iv.begin(), vote.iv.end());
        msg.insert(msg.end(), vote.cipher.begin(), vote.cipher.end());
        msg.insert(msg.end(), vote.tag.begin(), vote.tag.end());

        bool okSig = verify_signature("Dilithium2", msg, vote.sig, sig_pk);
        if (!okSig) { std::cerr << " bad signature → discard\n"; return 1; }

        // 4. Kyber decapsulation
        std::vector<uint8_t> ss;
        if (!kem_decaps("Kyber512", vote.ct, kem_sk, ss))
        {
            std::cerr << "ERROR! decapsulation failed\n"; return 1;
        }

        /* 5. HKDF to AES-key + IV (same as sender) */
        uint8_t key[32], iv[12], tmp[44];
        const uint8_t info[] = "PQC-eVote-AES";
        hkdf_sha256(ss.data(), ss.size(), info, sizeof(info) - 1, tmp, sizeof(tmp));
        memcpy(key, tmp, 32); memcpy(iv, tmp + 32, 12); OPENSSL_cleanse(tmp, sizeof(tmp));

        /* 6. AES-256-GCM decrypt */
        std::vector<uint8_t> plain(vote.cipher.size());
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);
        int len = 0;
        EVP_DecryptUpdate(ctx, plain.data(), &len,
            vote.cipher.data(), vote.cipher.size());
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, vote.tag.data());
        if (EVP_DecryptFinal_ex(ctx, plain.data() + len, &len) <= 0)
        {
            std::cerr << "ERROR! GCM tag verify failed – ballot forged?\n"; return 1;
        }
        EVP_CIPHER_CTX_free(ctx);

        std::string ballot(plain.begin(), plain.end());
        std::cout << "GOOD! decrypted vote = \"" << ballot << "\"\n";

    }
    catch (const std::exception& ex) {
        std::cerr << "tally error: " << ex.what() << "\n";
        return 1;
    }


    std::cout << "COMPARISONS\n\n";
   
/*
   Classical algorithms: RSA-2048 ‖ AES-256-GCM ‖ ECDSA-P256
   To mirror Kyber ‖ AES ‖ Dilithium pipeline
 */

    auto clk = std::chrono::high_resolution_clock::now;
    auto ms = [](auto d) { return std::chrono::duration<double, std::milli>(d).count(); };

    std::array<uint8_t, 32> aes_key_cls;
    RAND_bytes(aes_key_cls.data(), aes_key_cls.size());

    /* ------ (a)  RSA-2048 keygen ---------------------------------- */
    auto t0 = clk();
    BIGNUM* bn = BN_new(); BN_set_word(bn, RSA_F4);
    RSA* rsa = RSA_new();
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    BN_free(bn);
    auto t1 = clk();
    std::cout << "RSA-2048 keygen: " << ms(t1 - t0) << "  ms\n";

    /* ------ (b)  RSA encapsulates the AES key --------------------- */
    std::vector<uint8_t> rsa_ct(RSA_size(rsa));
    t0 = clk();
    int rsa_ct_len = RSA_public_encrypt(
        aes_key_cls.size(), aes_key_cls.data(),
        rsa_ct.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    t1 = clk();
    std::cout << "RSA-2048 OAEP encrypt (AES key): "
        << ms(t1 - t0) << "  ms\n";

    /* ------ (c)  AES-256-GCM encrypt the ballot ------------------- */
    unsigned char iv_cls[12];
    RAND_bytes(iv_cls, sizeof(iv_cls));

    std::vector<uint8_t> cipher_cls(vote_data.size() + 16);
    unsigned char tag_cls[16];
    int outl = 0, finl = 0;

    t0 = clk();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv_cls), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, aes_key_cls.data(), iv_cls);
    EVP_EncryptUpdate(ctx, cipher_cls.data(), &outl,
        vote_data.data(), vote_data.size());
    EVP_EncryptFinal_ex(ctx, cipher_cls.data() + outl, &finl);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag_cls), tag_cls);
    EVP_CIPHER_CTX_free(ctx);
    t1 = clk();
    cipher_cls.resize(outl + finl);
    std::cout << "AES-256-GCM encrypt (classic): "
        << ms(t1 - t0) << "  ms\n";

    /* ------ (d)  Build composite message for signature ------------ */
    std::vector<uint8_t> classic_msg;
    classic_msg.insert(classic_msg.end(), rsa_ct.begin(), rsa_ct.begin() + rsa_ct_len);
    classic_msg.insert(classic_msg.end(), iv_cls, iv_cls + sizeof(iv_cls));
    classic_msg.insert(classic_msg.end(), cipher_cls.begin(), cipher_cls.end());
    classic_msg.insert(classic_msg.end(), tag_cls, tag_cls + sizeof(tag_cls));

    /* ------ (e)  ECDSA-P256 keygen -------------------------------- */
    t0 = clk();
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(eckey);
    t1 = clk();
    std::cout << "ECDSA-P256 keygen: " << ms(t1 - t0) << "  ms\n";

    /* ------ (f)  ECDSA sign the composite message ----------------- */
    unsigned char sig_ec[80]; unsigned int sig_ec_len;
    t0 = clk();
    ECDSA_sign(0, classic_msg.data(), classic_msg.size(),
        sig_ec, &sig_ec_len, eckey);
    t1 = clk();
    std::cout << "ECDSA-P256 sign: " << ms(t1 - t0) << "  ms\n";

    /* ------ (g)  ECDSA verify ------------------------------------- */
    t0 = clk();
    int ok_ec = ECDSA_verify(0, classic_msg.data(), classic_msg.size(),
        sig_ec, sig_ec_len, eckey);
    t1 = clk();
    std::cout << "ECDSA-P256 verify: " << ms(t1 - t0)
        << "  ms, valid=" << ok_ec << '\n';

    /* ------ (h)  RSA decrypt the AES key -------------------------- */
    std::array<uint8_t, 32> aes_key_rec;
    t0 = clk();
    RSA_private_decrypt(rsa_ct_len, rsa_ct.data(),
        aes_key_rec.data(), rsa, RSA_PKCS1_OAEP_PADDING);
    t1 = clk();
    std::cout << "RSA-2048 OAEP decrypt (AES key): "
        << ms(t1 - t0) << "  ms\n";

    /* ------ (i)  AES-256-GCM decrypt the ballot ------------------- */
    std::vector<uint8_t> plain_cls(vote_data.size());
    ctx = EVP_CIPHER_CTX_new();
    t0 = clk();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv_cls), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, aes_key_rec.data(), iv_cls);
    EVP_DecryptUpdate(ctx, plain_cls.data(), &outl,
        cipher_cls.data(), cipher_cls.size());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag_cls), tag_cls);
    int dec_ok = EVP_DecryptFinal_ex(ctx, plain_cls.data() + outl, &finl);
    EVP_CIPHER_CTX_free(ctx);
    t1 = clk();
    std::cout << "AES-256-GCM decrypt (classic): "
        << ms(t1 - t0) << "  ms, success="
        << (dec_ok > 0 ? "yes" : "no") << "\n\n";

    RSA_free(rsa);
    EC_KEY_free(eckey);

    // Compare sizes aswell

    auto der_size_RSA_pub = [&](RSA* r) {
        int len = i2d_RSAPublicKey(r, nullptr);
        return len > 0 ? len : 0;
        };
    auto der_size_RSA_priv = [&](RSA* r) {
        int len = i2d_RSAPrivateKey(r, nullptr);
        return len > 0 ? len : 0;
        };
    auto der_size_EC_pub = [&](EC_KEY* k) {
        int len = i2o_ECPublicKey(k, nullptr);
        return len > 0 ? len : 0;
        };
    auto der_size_EC_priv = [&](EC_KEY* k) {
        int len = i2d_ECPrivateKey(k, nullptr);
        return len > 0 ? len : 0;
        };

    std::cout << "SIZE OVERVIEW (bytes)\n";
    std::cout << "Post-Quantum\n";
    std::cout << "    Kyber512  public key : " << kem_pk.size() << "\n";
    std::cout << "    Kyber512  secret key : " << kem_sk.size() << "\n";
    std::cout << "    Dilithium2 public key: " << sig_pk.size() << "\n";
    std::cout << "    Dilithium2 secret key: " << sig_sk.size() << "\n";
    std::cout << "    PQC payload (msg)    : " << msg.size() << "\n";
    std::cout << "    Dilithium signature  : " << signature.size() << "\n";
    std::cout << "    On-chain data total  : "
        << msg.size() + signature.size() << "\n\n";

    std::cout << "Classical\n";
    std::cout << "    RSA-2048 public key (DER) : "
        << der_size_RSA_pub(rsa) << "\n";
    std::cout << "    RSA-2048 private key (DER): "
        << der_size_RSA_priv(rsa) << "\n";
    std::cout << "    ECDSA-P256 public key (DER): "
        << der_size_EC_pub(eckey) << "\n";
    std::cout << "    ECDSA-P256 private key (DER): "
        << der_size_EC_priv(eckey) << "\n";
    std::cout << "    Classical payload (msg)   : "
        << classic_msg.size() << "\n";
    std::cout << "    ECDSA signature           : " << sig_ec_len << "\n";
    std::cout << "    On-chain data total       : "
        << classic_msg.size() + sig_ec_len << "\n\n";


    return 0;
}
