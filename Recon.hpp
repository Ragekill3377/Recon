#pragma once

/*
Ugly
Not Secure
If you want to make it better, feel free to do so.
MAKE A PR IF ITS ACTUALLY GOOD< I'LL TAKE ANYTHING
*/

#pragma mark - Recon: a trash encryption lib
// no external libs, you could use this on pretty much any libc system
#include <array>
#include <vector>
#include <string>
#include <random>
#include <cstdint>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace Recon
{   // i mean i saw all the pros doing ts, so i figured to adopt this habit for myself aswell.
    // its pretty clean.
    using Byte         =    uint8_t;
    using Block        =    std::array<Byte, 16>;
    using Key          =    std::array<Byte, 32>;
    using Iv           =    std::array<Byte, 16>;
    using Hmac         =    std::array<Byte, 32>;
    using Buffer       =    std::vector<Byte>;
    using Index        =    std::size_t;
    using Seed         =    std::random_device::result_type;

    static inline Byte RotL(Byte x, int n)
    {
        return static_cast<Byte>((x << n) | (x >> (8 - n))); // shifting bits L and R. Still confuses me, and i easily screw it up.
    }

    static inline Byte RotR(Byte x, int n)
    {
        return static_cast<Byte>((x >> n) | (x << (8 - n)));
    }
    // im not worrying too much about these, its completely random
    static inline Iv GenerateIV()
    {
        Iv Output;
        std::random_device Rd;
        for (auto& B : Output)
        {
            B = static_cast<Byte>(Rd() & 0xFF);
        }
        return Output;
    }

    static inline Key GenerateKey()
    {
        Key Output;
        std::random_device Rd;
        for (auto& B : Output)
        {
            B = static_cast<Byte>(Rd() & 0xFF);
        }
        return Output;
    }
    // jsut like AES's sbox stuff
    static inline std::array<Byte, 256> BuildSBox()
    {
        std::array<Byte, 256> S;
        for (Index i = 0; i < 256; ++i) S[i] = static_cast<Byte>(i);
        std::random_device Rd;
        for (Index i = 255; i > 0; --i)
        {
            Index j = Rd() % (i + 1);
            std::swap(S[i], S[j]);
        }
        return S;
    }

    static inline std::array<Byte, 256> SBox = BuildSBox();
// all this is to mess around with the sbox and make it hard to mess with/predict
    static inline std::array<Byte, 256> InverseSBox()
    {
        std::array<Byte, 256> Inv{};
        for (Index i = 0; i < 256; ++i)
        {
            Inv[SBox[i]] = static_cast<Byte>(i);
        }
        return Inv;
    }

    static inline const std::array<Byte, 256> InvSBox = InverseSBox();

    static inline void Substitute(Buffer& Data)
    {
        for (auto& B : Data)
        {
            B = SBox[B];
        }
    }

    static inline void InverseSubstitute(Buffer& Data)
    {
        for (auto& B : Data)
        {
            B = InvSBox[B];
        }
    }

    static inline void IncrementCounter(Iv& Counter)
    {
        for (int i = 15; i >= 0; --i)
        {
            if (++Counter[i] != 0) break;
        }
    }

    static inline Buffer Keystream(const Key& K, Iv V, Index Length)
    {
        Buffer Stream;
        Stream.reserve(Length);
        while (Stream.size() < Length)
        {
            for (int i = 0; i < 16 && Stream.size() < Length; ++i)
            {
                Byte B = V[i] ^ K[i % K.size()];
                B = RotL(SBox[B], 3);
                Stream.push_back(B);
            }
            IncrementCounter(V);
        }
        return Stream;
    }

    static inline Buffer Transform(const Buffer& In, const Key& K, Iv V)
    {
        Buffer Out = In;
        Buffer Stream = Keystream(K, V, Out.size());
        for (Index i = 0; i < Out.size(); ++i)
        {
            Out[i] ^= Stream[i];
        }
        Substitute(Out);
        return Out;
    }

    static inline Buffer InverseTransform(const Buffer& In, const Key& K, Iv V)
    {
        Buffer Out = In;
        InverseSubstitute(Out);
        Buffer Stream = Keystream(K, V, Out.size());
        for (Index i = 0; i < Out.size(); ++i)
        {
            Out[i] ^= Stream[i];
        }
        return Out;
    }
// this is to wipe the key in memory, just a little extra 'security'
    static inline void ZeroMemory(Byte* data, size_t len)
    {
        volatile Byte* p = data;
        while (len--) *p++ = 0;
    }
// nice hashed-like output
// though its like simple xorring
// also, this is a security check for tampering.
    static inline Hmac GenerateHmac(const Buffer& D, const Key& K, const Iv& V)
    {
        Hmac H = {{0}};
        for (Index i = 0; i < D.size(); ++i)
        {
            H[i % 32] ^= RotL(D[i] ^ K[i % K.size()], 1);
            H[i % 32] ^= V[i % V.size()];
        }
        for (Index i = 0; i < 32; ++i)
        {
            H[i] ^= K[(i * 11 + 7) % K.size()] ^ static_cast<Byte>(i);
            H[i] = RotR(H[i], 2);
        }
        return H;
    }
// bunch of utils
    static inline bool ConstantTimeEqual(const Hmac& A, const Hmac& B)
    {
        Byte R = 0;
        for (Index i = 0; i < A.size(); ++i)
        {
            R |= A[i] ^ B[i];
        }
        return R == 0;
    }

    static inline std::string BytesToHex(const Buffer& B)
    {
        std::ostringstream S;
        for (Byte C : B)
        {
            S << std::hex << std::setw(2) << std::setfill('0') << int(C);
        }
        return S.str();
    }

    static inline Buffer HexToBytes(const std::string& Hex)
    {
        Buffer B;
        for (Index i = 0; i < Hex.length(); i += 2)
        {
            std::string ByteStr = Hex.substr(i, 2);
            Byte V = static_cast<Byte>(std::stoi(ByteStr, nullptr, 16));
            B.push_back(V);
        }
        return B;
    }

    class Encryptor
    {
    private:
        Key InternalKey;

    public:
        Encryptor()
        {
            InternalKey = GenerateKey(); // if read fast enough, faster than ZeroMemory executes, consider yourself screwed. Unless, you don't let anyone else access program memory in the first place
        }
// this is to remove the key
        ~Encryptor()
        {
            ZeroMemory(InternalKey.data(), InternalKey.size());
        }
// strs only for now
        std::string Encrypt(const std::string& Msg)
        {
            Buffer Raw(Msg.begin(), Msg.end());
            Iv V = GenerateIV();
            Buffer Enc = Transform(Raw, InternalKey, V);
            Hmac Mac = GenerateHmac(Enc, InternalKey, V);
            Buffer Out;
            Out.insert(Out.end(), V.begin(), V.end());
            Out.insert(Out.end(), Enc.begin(), Enc.end());
            Out.insert(Out.end(), Mac.begin(), Mac.end());
            std::fill(Raw.begin(), Raw.end(), 0);
            return BytesToHex(Out);
        }

        std::string Decrypt(const std::string& Cipher)
        {
            Buffer All = HexToBytes(Cipher);
            if (All.size() < 16 + 32) throw std::runtime_error("Invalid");

            Iv V;
            std::copy(All.begin(), All.begin() + 16, V.begin());
            Buffer D = Buffer(All.begin() + 16, All.end() - 32);
            Hmac Recvd;
            std::copy(All.end() - 32, All.end(), Recvd.begin());
            
            // see this? if hmacs dont match, it means someone was messing around.
            Hmac Calc = GenerateHmac(D, InternalKey, V);
            if (!ConstantTimeEqual(Calc, Recvd)) throw std::runtime_error("Tampered");

            Buffer Dec = InverseTransform(D, InternalKey, V);
            return std::string(Dec.begin(), Dec.end());
        }
    };
}
