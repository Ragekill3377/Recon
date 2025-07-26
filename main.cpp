#include <iostream>                                  
#include <chrono>

#include "Recon.hpp"

int main()                                           
{                                                        
    Recon::Encryptor         E;                      
    std::string              PlainText     = "کیا ہو رہا ہے";
    auto                     StartEnc      = std::chrono::high_resolution_clock::now();
    std::string              CipherText    = E.Encrypt(PlainText);
    auto                     EndEnc        = std::chrono::high_resolution_clock::now();
    auto                     StartDec      = std::chrono::high_resolution_clock::now();
    std::string              DecryptedText = E.Decrypt(CipherText);
    auto                     EndDec        = std::chrono::high_resolution_clock::now();
    auto                     EncTime   = std::chrono::duration_cast<std::chrono::nanoseconds>(EndEnc - StartEnc).count();
    auto                     DecTime   = std::chrono::duration_cast<std::chrono::nanoseconds>(EndDec - StartDec).count();
    std::cout << "Crypt text:  " << CipherText     << std::endl;
    std::cout << "old text (as is):   " << PlainText      << std::endl;
    std::cout << "Decrypted:  " << DecryptedText  << std::endl;
    std::cout << "Enc Time:   " << EncTime    << " ns" << std::endl;
    std::cout << "Dec Time:   " << DecTime    << " ns" << std::endl;
}
