#pragma once

#include <stdint.h>
#define SINATURE_SEARCH_NOT_FOUND (-1)

#ifdef __cplusplus 
extern "C"{
#endif // __cplusplus 

	size_t sunday_search_pattern_enc(const unsigned char* buffer, size_t size, const char* pattern, size_t len, int added, unsigned char xorbyte);
	size_t sunday_search_pattern(const unsigned char* buffer, size_t size, const char* pattern, size_t len, int added);

	size_t sunday_search_bytes_enc(const unsigned char* buffer, size_t size, const uint8_t* bytes, size_t len, uint64_t mark, int added, unsigned char xorbyte);
	size_t sunday_search_bytes(const unsigned char* buffer, size_t size, const uint8_t* bytes, size_t len, uint64_t mark, int added);

	uint8_t* sunday_search_ptr_pattern_enc(const unsigned char* buffer, size_t size, const char* pattern, size_t len, int added, unsigned char xorbyte);
	uint8_t* sunday_search_ptr_pattern(const unsigned char* buffer, size_t size, const char* pattern, size_t len, int added);

	uint8_t* sunday_search_ptr_bytes_enc(const unsigned char* buffer, size_t size, const uint8_t* bytes, size_t len, uint64_t mark, int added, unsigned char xorbyte);
	uint8_t* sunday_search_ptr_bytes(const unsigned char* buffer, size_t size, const uint8_t* bytes, size_t len, uint64_t mark, int added);

#ifdef __cplusplus 
}
#endif // __cplusplus 


#ifdef __cplusplus 
#include <vector>
#include <array>

namespace signature_search {
  namespace detail {

		template<std::size_t X>
		constexpr char xor_with_X(char c) {
			return c ^ X;
		}

		template< std::size_t X, std::size_t N>
		constexpr auto xor_string(const char(&str)[N]) {
			std::array<char, N-1> result = {};
			if (X != 0)
			{
				for (std::size_t i = 0; i < N - 1; ++i) {
					result[i] = xor_with_X<X>(str[i]);
				}
			}
			else
			{
				for (std::size_t i = 0; i < N - 1; ++i) {
					result[i] = str[i];
				}
			}

			return result;
		}
  }

	template<std::size_t X, std::size_t N>
	class signature_searcher
	{
		const char xor_num = X;
		std::array<char, N-1> sign = {};
	public:
		signature_searcher(const char(&str)[N])
			:sign(detail::xor_string<X, N>(str))
		{
		}
		
		size_t search(unsigned char* buffer, size_t size, size_t added = 0) 
		{
			size_t offset = sunday_search_enc(buffer, size, sign.data(), sign.size(), xor_num);
			if (offset == SINATURE_SEARCH_NOT_FOUND)
				return SINATURE_SEARCH_NOT_FOUND;

			return offset + added;
		}

	};

	template<std::size_t X = 0, std::size_t N>
	signature_searcher<X, N> make_signaturer(const char(&str)[N]) 
	{
		static_assert((N-1) % 2 == 0);
		return signature_searcher<X, N>(str);
	}


}

#endif // __cplusplus 