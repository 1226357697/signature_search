#pragma once

#ifdef __cplusplus 
extern "C"{
#endif // __cplusplus 


	size_t sunday_search_enc(const unsigned char* buffer, size_t size, const char* pattern, size_t len, unsigned char xorbyte);
	size_t sunday_search(const unsigned char* buffer, size_t size, const char* pattern, size_t len);


	size_t sunday_search_code_enc(const unsigned char* imagebase, const char* pattern, size_t len, unsigned char xorbyte);


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
		
	};

	template<std::size_t X = 0, std::size_t N>
	signature_searcher<X, N> make_signaturer(const char(&str)[N]) 
	{
		static_assert((N-1) % 2 == 0);
		return signature_searcher<X, N>(str);
	}


}

#endif // __cplusplus 