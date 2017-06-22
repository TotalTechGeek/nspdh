#ifndef _NSPDH_IO_H_
#define _NSPDH_IO_H_ 1

#include <boost/multiprecision/cpp_int.hpp>

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
    std::vector<char> getByteArray(boost::multiprecision::cpp_int v);
    std::string quotes(const std::string& tag, const std::string& internal);
    std::string quotes(const std::string& tag, int x); 
    void createXML(std::vector<boost::multiprecision::cpp_int>& params, std::ostream& file);
    void exportParameters(const std::string& outFile, std::vector<boost::multiprecision::cpp_int>& params, char convert);
    void exportParameters(const std::string& outFile, boost::multiprecision::cpp_int& modulusPrime, boost::multiprecision::cpp_int& generator, char convert);    
}
#endif