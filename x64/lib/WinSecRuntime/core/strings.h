#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace secure {
namespace util {

inline void secure_zero(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) { *v++ = 0; }
}

template <size_t N, uint8_t K>
struct obf_string {
    std::array<char, N> data{};
    constexpr obf_string(const char (&s)[N]) {
        for (size_t i = 0; i < N; ++i) data[i] = static_cast<char>(s[i] ^ K);
    }
    inline void decrypt_to(char* out) const {
        for (size_t i = 0; i < N; ++i) out[i] = static_cast<char>(data[i] ^ K);
    }
    inline std::array<char, N> decrypt() const {
        std::array<char, N> out{};
        decrypt_to(out.data());
        return out;
    }
};

template <size_t N, uint16_t K>
struct obf_wstring {
    std::array<wchar_t, N> data{};
    constexpr obf_wstring(const wchar_t (&s)[N]) {
        for (size_t i = 0; i < N; ++i) data[i] = static_cast<wchar_t>(s[i] ^ K);
    }
    inline void decrypt_to(wchar_t* out) const {
        for (size_t i = 0; i < N; ++i) out[i] = static_cast<wchar_t>(data[i] ^ K);
    }
    inline std::array<wchar_t, N> decrypt() const {
        std::array<wchar_t, N> out{};
        decrypt_to(out.data());
        return out;
    }
};

#define SECURE_OBF_KEY(line) static_cast<uint8_t>(((line) * 131u + 17u) % 251u + 1u)
#define SECURE_OBF(s) secure::util::obf_string<sizeof(s), SECURE_OBF_KEY(__LINE__)>(s)
#define SECURE_OBF_W(s) secure::util::obf_wstring<sizeof(s) / sizeof(wchar_t), static_cast<uint16_t>(SECURE_OBF_KEY(__LINE__))>(s)

} // namespace util
} // namespace secure
