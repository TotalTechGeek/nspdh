#ifndef _NSPDH_IO_H_
#define _NSPDH_IO_H_ 1


#include "../cryptopp/integer.h"

using CryptoPP::Integer;

#include <string>
#include <vector>
#include <fstream>

// Used to link in a C function from an object file.
#ifdef LINKASN1C
extern "C"
{
    int processBuffer(const char *textBuf, int len, char* out, int* size);
}
#endif

namespace nspdh 
{
    // Defines available functions.
    void printByteArray(std::vector<char>& r, std::ostream& file);
    std::vector<char> getByteArray(Integer v);
    std::string quotes(const std::string& tag, const std::string& internal);
    std::string quotes(const std::string& tag, int x); 
    void createXML(std::vector<Integer>& params, std::ostream& file);
    std::string createBinary(std::vector<Integer>& params);
    void exportParameters(const std::string& outFile, std::vector<Integer>& params, char convert);
    void exportParameters(const std::string& outFile, Integer& modulusPrime, Integer& generator, char convert);    
}
#endif
