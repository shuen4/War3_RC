#pragma once

// copied from GHost++ util.cpp
std::vector<uint8_t> EncodeGameDesc(std::vector<uint8_t>& data);
std::vector<uint8_t> DecodeGameDesc(std::vector<uint8_t>& data);
std::vector<uint8_t> DecodeGameDesc(char* s);