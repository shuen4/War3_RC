#include <vector>
#include "util.h"

// copied from GHost++ util.cpp
std::vector<uint8_t> EncodeGameDesc(std::vector<uint8_t>& data) {
    unsigned char Mask = 1;
    std::vector<uint8_t> Result;

    for (unsigned int i = 0; i < data.size(); ++i) {
        if ((data[i] % 2) == 0)
            Result.push_back(data[i] + 1);
        else {
            Result.push_back(data[i]);
            Mask |= 1 << ((i % 7) + 1);
        }

        if (i % 7 == 6 || i == data.size() - 1) {
            Result.insert(Result.end() - 1 - (i % 7), Mask);
            Mask = 1;
        }
    }

    return Result;
}
std::vector<uint8_t> DecodeGameDesc(std::vector<uint8_t>& data) {
    unsigned char Mask;
    std::vector<uint8_t> Result;

    for (unsigned int i = 0; i < data.size(); ++i) {
        if ((i % 8) == 0)
            Mask = data[i];
        else {
            if ((Mask & (1 << (i % 8))) == 0)
                Result.push_back(data[i] - 1);
            else
                Result.push_back(data[i]);
        }
    }

    return Result;
}
std::vector<uint8_t> DecodeGameDesc(char* s) {
    std::vector<uint8_t> data(s, s + strlen(s));
    return DecodeGameDesc(data);
}
