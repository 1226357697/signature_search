#pragma once

#ifdef __cplusplus 
extern "C"{
#endif // __cplusplus 


	size_t sunday_search_enc(const unsigned char* buffer, size_t size, const char* pattern, size_t len, unsigned char xorbyte);
	size_t sunday_search(const unsigned char* buffer, size_t size, const char* pattern, size_t len);

#ifdef __cplusplus 
}
#endif // __cplusplus 


#ifdef __cplusplus 

namespace signature_search {
  namespace detail {

  }

	class signature_searcher
	{
	public:
		signature_searcher();
		~signature_searcher();

	private:

	};


}

#endif // __cplusplus 