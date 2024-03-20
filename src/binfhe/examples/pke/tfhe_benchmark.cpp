#include "binfhecontext.h"
#include <cereal/archives/portable_binary.hpp>
#include <cereal/types/vector.hpp>
#include <filesystem>
#include <fstream>
using namespace lbcrypto;
using namespace std::chrono;


double CalculateApproximationError(const std::vector<int>& result, const std::vector<LWEPlaintext>& expectedResult) {
    if (result.size() != expectedResult.size()) {
        std::cout << "Cannot compare vectors with different numbers of elements" << std::endl;
        return 0;
    }
    // using the Euclidean norm
    double avrg = 0;
    for (size_t i = 0; i < result.size(); ++i) {
        avrg += std::pow(std::abs(result[i] - expectedResult[i]), 2);
    }
    avrg = std::sqrt(avrg / result.size());
    return avrg;
    //avrg = std::sqrt(avrg) / result.size();  // get the average
    //return std::abs(std::log2(avrg));
}

std::ifstream::pos_type get(const char* filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    in.seekg(0, std::ios_base::end);
    return in.tellg();
    //return std::filesystem::file_size("test");
}

int main() {
    //std::system("(top -b -d 0.04 >> top_tfhe_openfhe_singleCPU.txt)&");
    //std::system("(mpstat -P ALL 3 >> mpstat.txt)&");
    //std::system("( vmstat -n -S m -t 1 >> openfhe_tfhe_bootstrap_vmstat_STD128.txt)&");
//    std::system("(top -b -d 0.5 >> top_openfhe_0125.txt)&");
     //std::system("( vmstat -n -S m -t 1 >> vmstat.txt)&");
//    std::system("(iotop -b -d 0.5 -k >> iotop_openfhe_0125.txt)&");
    double total_time = get_time_msec();
    // Sample Program: Step 1: Set CryptoContext
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);

    // Sample Program: Step 2: Key Generation
    //std::cout << "Generate a rondom key." << std::endl;
    double sk_start = get_time_msec();
    // Generate the secret key
    auto sk = cc.KeyGen();
    std::cout << "time for generating sk is " << get_time_msec() - sk_start << std::endl;

    // export the secret key to know the size
   /* {
        std::ofstream ofs{"secret.key", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        sk->save(ar, 0);
    };
    std::cout << "secret key size is " << get("secret.key") << std::endl;
    */

    //std::cout << "Generating the bootstrapping keys..." << std::endl;
    double gk_start = get_time_msec();
    // Generate the bootstrapping keys (refresh and switching keys)
    cc.BTKeyGen(sk);
    std::cout << "time for generating gk is " << get_time_msec() - gk_start << std::endl;
   
    // export the secret key to know the size
  /*  {
        std::ofstream ofs{"gate_bootstrap.key", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        gk.BSkey->save(ar, 0);
    };
    std::cout << "bootstrap key size is " << get("gate_bootstrap.key") << std::endl;

    // export the secret key to know the size
    {
        std::ofstream ofs{"gate_ks.key", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        gk.KSkey->save(ar, 0);
    };
    std::cout << "keyswitching key size is " << get("gate_ks.key") << std::endl;
*/
    std::cout << "Completed the key generation. It is " << get_time_msec() - total_time << std::endl;

    // Sample Program: Step 3: Create the to-be-evaluated funciton and obtain its corresponding LUT
    int p = cc.GetMaxPlaintextSpace().ConvertToInt();  // Obtain the maximum plaintext space
    std::cout << "maximum plaintext space is " << p << std::endl;

    // Initialize Function f(x) = x^2/4 % p

    auto fp = [](NativeInteger m, NativeInteger p1) -> NativeInteger {
       // if (m < p1)
       //     return m;
       //else
        //    return m % p1;
        return m;
    };

    //auto lut = cc.GenerateLUTviaFunction(fp, p);

    const int vector_size = 1;
    std::srand(time(NULL));
    std::vector<double> plain(vector_size);
    for (int i = 0; i < vector_size; i++) {
        if (i == 3) {
            plain[i] = 0;
            continue;
        }
        plain[i] = 2.01;
    }
    //std::cout << "Encrypt a plaintext." << std::endl;
    std::vector<LWECiphertext> cipher(vector_size);
    //, cipher2(vector_size);
    double encryption_start = get_time_msec();
    for (int i = 0; i < vector_size; i++) {
        cipher[i] = cc.Encrypt(sk, plain[i], FRESH, p);
        //cipher2[i] = cc.Encrypt(sk, plain[i], FRESH, p);
    }
    std::cout << "time for encryption is " << get_time_msec() - encryption_start << std::endl;
 /*   // export the secret key to know the size
    {
        std::ofstream ofs{"ciphertext.key", std::ios::binary};
        cereal::PortableBinaryOutputArchive ar(ofs);
        cipher[0]->save(ar, 0);
    };
    std::cout << "ciphertext size is " << get("ciphertext.key") << std::endl;
    */
    std::cout << "Finish encryption. It is " << get_time_msec() - total_time << std::endl;
    //const int loop_bootstrap = 10;
    double start, end;
    //std::system("(top -b -d 1 >> top_tfhe_result_openfhe5.txt)&");
    //std::system("(mpstat -P ALL 2 >> mpstat_openfhe5.txt)&");
    LWECiphertext answer;
    start = get_time_msec();
   
    for (int i = 0; i < vector_size; i++) {
        auto lut  = cc.GenerateLUTviaFunction(fp, p);
        cipher[i] = cc.EvalFunc(cipher[i], lut);
        //answer = cc.EvalBinGate(XOR, cipher[i], cipher2[i]);


    }

    end = get_time_msec();
    std::cout << "Finished bootstrapping. It is " << get_time_msec() - total_time << std::endl;
    //std::cout << "bootstrap time is " << end - start << std::endl;
    std::cout << "bootstrap time is " << end - start << std::endl;
    std::vector<LWEPlaintext> decrypted_answer(vector_size);
    double decryption_start = get_time_msec();
    for (int i = 0; i < vector_size; i++) {
        cc.Decrypt(sk, cipher[i], &decrypted_answer[i], p);
    }
    std::cout << "time for decryption is " << get_time_msec() - decryption_start << std::endl;
    std::cout << "decyrpted answer is " << std::endl;
    for (int i = 0; i < vector_size; i++) {
        std::cout << decrypted_answer[i] << " ";
    }
    std::cout << std::endl;

    //std::cout << "precision is " << CalculateApproximationError(plain, decrypted_answer) << std::endl;
   
   

    return 0;
}
