#include "openfhe.h"
// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/bfvrns-ser.h"
#include <unistd.h>

using namespace lbcrypto;


using namespace std::chrono;

   std::ifstream::pos_type get(const char* filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    in.seekg(0, std::ios_base::end);
    return in.tellg();
    //return std::filesystem::file_size("test");
}

int main() {
   //std::system("(top -b -d 0.05 >> top.txt)&");
   // Sample Program: Step 1: Set CryptoContext
   CCParams<CryptoContextBFVRNS> parameters;
   //CCParams<CryptoContextBFVRNS> parameters;
   parameters.SetPlaintextModulus(65537); //65537
   parameters.SetMultiplicativeDepth(12);
   parameters.SetFirstModSize(55); //55
   parameters.SetScalingModSize(56); //55
   parameters.SetNumLargeDigits(1); //4
 
   parameters.SetRingDim(16384); //4096 //8192
    parameters.SetKeySwitchTechnique(HYBRID);
   //parameters.SetScalingTechnique(NORESCALE);
   parameters.SetScalingTechnique(FLEXIBLEAUTO);
   parameters.SetSecurityLevel(HEStd_128_classic);
   
/*
   parameters.SetPlaintextModulus(65537);
   parameters.SetMultiplicativeDepth(1); //1 4 19
   parameters.SetFirstModSize(60); //46 50
   parameters.SetScalingModSize(60); //46 50
   parameters.SetNumLargeDigits(4); //4
 
   parameters.SetRingDim(16384); //4096 //8192
   parameters.SetSecurityLevel(HEStd_NotSet);
*/
   CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
   // Enable features that you wish to use
   cryptoContext->Enable(PKE);  //can change
   cryptoContext->Enable(KEYSWITCH);
   cryptoContext->Enable(LEVELEDSHE);


   // Sample Program: Step 2: Key Generation


   // Initialize Public Key Containers
   KeyPair<DCRTPoly> keyPair;

    double key_start;
    key_start = get_time_msec();
   // Generate a public/private key pair
   keyPair = cryptoContext->KeyGen();

 /*   // export the secret key to know the size
    {
        std::ofstream ofs{"secret.key", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        keyPair.secretKey->save(ar, 0);
    };
    std::cout << "secret key size is " << get("secret.key") << " bytes" <<  std::endl;

     // export the secret key to know the size
    {
        std::ofstream ofs{"public.key", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        keyPair.publicKey->save(ar, 0);
    };
    std::cout << "secret key size is " << get("public.key") << " bytes" << std::endl;

*/


   // Generate the relinearization key
   cryptoContext->EvalMultKeyGen(keyPair.secretKey);
   std::cout << "key generation time is " << get_time_msec()-key_start << std::endl;


   // Generate the rotation evaluation keys
   //cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});


   // Sample Program: Step 3: Encryption


   // First plaintext vector is encoded
   const int vector_size = 48;
   //std::srand(time(NULL));
   std::vector<int64_t> vectorOfInts1(vector_size);
   for (int i = 0; i < vector_size; i++) {
       vectorOfInts1[i] = 1;
   }
   Plaintext plaintext1 = cryptoContext->MakePackedPlaintext(vectorOfInts1);
   //std::cout << "level is " << plaintext1.GetLevel() << std::endl;

    double encrypt_start;
    encrypt_start = get_time_msec();
   // The encoded vectors are encrypted
   auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
   //auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
   std::cout << "encryption time is " << get_time_msec()-encrypt_start << std::endl;
   auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
   //auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
   //const auto evalKeyVec = cryptoContext->GetEvalMultKeyVector(ciphertext1->GetKeyTag());

  /*  const std::string DATAFOLDER = "demoData";
    std::string multKeyLocation   = "/key_mult.txt";
    std::ofstream multKeyFile(DATAFOLDER + multKeyLocation, std::ios::out | std::ios::binary);
    if (multKeyFile.is_open()) {
        if (!cryptoContext->SerializeEvalMultKey(multKeyFile, SerType::BINARY)) {
            std::cerr << "Error writing eval mult keys" << std::endl;
            std::exit(1);
        }
        std::cout << "EvalMult/ relinearization keys have been serialized" << std::endl;
        std::cout << "keyswithching key size2 is " << get("demoData/key_mult.txt") << " bytes" <<std::endl;
        multKeyFile.close();
    }
    else {
        std::cerr << "Error serializing EvalMult keys" << std::endl;
        std::exit(1);
    }

     // export the secret key to know the size
    {
        std::ofstream ofs{"ciphertext", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        ciphertext1->save(ar, 0);
    };
    std::cout << "ciphertext size is " << get("ciphertext") << " bytes" << std::endl;
   */ 
   
   const int loop = 10;
   double start, end;
   //std::system("(vmstat -n -S m -t 1 >> vmstat_openfhe_mult_bfv_depth11_3.txt)&");
   //std::system("(top -b -d 0.001 >> top.txt)&");
   //sleep(2);
   
   std::cout << "start mult" << std::endl;
   // Homomorphic additions
   start = get_time_msec();
   for (int i = 0; i < loop; i++) {
       ciphertext1 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
       //cryptoContext->ModReduce(ciphertext1);
       //std::cout << "ciphertext1 level is " << ciphertext1->GetLevel() << std::endl;
       //std::cout << "ciphertext2 level is " << ciphertext2->GetLevel() << std::endl;
   }
   end = get_time_msec();
   std::cout << "mult time is " << end - start << std::endl;

    // Not bootstrapping.

    double decrypt_start = get_time_msec();
    // Decrypt the result of additions
   Plaintext plaintextMultResult;
   cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextMultResult);
  std::cout << "decryption time is " << get_time_msec() - decrypt_start << std::endl;
   // Result
   std::cout << "Plaintext #1: " << plaintext1 << std::endl;
   std::cout << "#1 * #1 * #1 + ...: " << plaintextMultResult << std::endl;
   


}
