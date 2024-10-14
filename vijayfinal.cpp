#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <cstring>
#include <bitset>
#include <cstdint>  // Include for uint32_t and uint8_t

// SHA-256 Constants
const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Utility Functions
class Utils {
public:
    static uint32_t rightRotate(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static std::vector<uint8_t> pad(const std::vector<uint8_t>& data) {
        size_t originalSize = data.size();
        size_t bitSize = originalSize * 8;
        std::vector<uint8_t> paddedData = data;

        // Append 1 bit followed by zeros
        paddedData.push_back(0x80);
        while ((paddedData.size() * 8) % 512 != 448) {
            paddedData.push_back(0x00);
        }

        // Append the original length as a 64-bit number
        for (int i = 7; i >= 0; --i) {
            paddedData.push_back(static_cast<uint8_t>((bitSize >> (i * 8)) & 0xFF));
        }

        return paddedData;
    }

    static uint32_t bytesToUint32(const uint8_t* bytes) {
        return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
    }

    static void uint32ToBytes(uint32_t value, uint8_t* bytes) {
        bytes[0] = (value >> 24) & 0xFF;
        bytes[1] = (value >> 16) & 0xFF;
        bytes[2] = (value >> 8) & 0xFF;
        bytes[3] = value & 0xFF;
    }
};

// The SHA-256 Hashing Class
class SHA256 {
private:
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

public:
    std::string hash(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> paddedData = Utils::pad(data);
        processBlocks(paddedData);
        return digest();
    }

private:
    void processBlocks(const std::vector<uint8_t>& data) {
        for (size_t i = 0; i < data.size(); i += 64) {
            uint32_t w[64];
            for (int j = 0; j < 16; ++j) {
                w[j] = Utils::bytesToUint32(&data[i + j * 4]);
            }
            for (int j = 16; j < 64; ++j) {
                uint32_t s0 = Utils::rightRotate(w[j - 15], 7) ^ Utils::rightRotate(w[j - 15], 18) ^ (w[j - 15] >> 3);
                uint32_t s1 = Utils::rightRotate(w[j - 2], 17) ^ Utils::rightRotate(w[j - 2], 19) ^ (w[j - 2] >> 10);
                w[j] = w[j - 16] + s0 + w[j - 7] + s1;
            }

            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], h0 = h[7];

            for (int j = 0; j < 64; ++j) {
                uint32_t S1 = Utils::rightRotate(e, 6) ^ Utils::rightRotate(e, 11) ^ Utils::rightRotate(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h0 + S1 + ch + k[j] + w[j];
                uint32_t S0 = Utils::rightRotate(a, 2) ^ Utils::rightRotate(a, 13) ^ Utils::rightRotate(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                h0 = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += h0;
        }
    }

    std::string digest() {
        std::stringstream ss;
        for (int i = 0; i < 8; ++i) {
            ss << std::hex << std::setw(8) << std::setfill('0') << h[i];
        }
        return ss.str();
    }
};

// Helper function to read a file into a string
std::vector<uint8_t> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return buffer;
}

int main() {
    std::string filename = "VIJAYfinal256.txt";
    std::vector<uint8_t> fileData = readFile(filename);

    SHA256 sha256;
    std::string hashValue = sha256.hash(fileData);

    std::cout << "SHA-256 Hash: " << hashValue << std::endl;

    return 0;
}
