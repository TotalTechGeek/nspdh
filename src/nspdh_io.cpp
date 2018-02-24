#include "nspdh_io.hpp"
#include "base64.hpp"
#include <sstream>

#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>

#include "nspdh_utilities.hpp"

using namespace std;
using namespace boost::multiprecision;
using namespace boost::math;

using boost::format;
using boost::lexical_cast;

namespace nspdh 
{
    // Prints the byte array for prime values.
    void printByteArray(vector<char>& r, ostream& file)
    {
        for(int i = r.size() -1; i >= 0; i--)
        {
            file << "&#x" << format("%02x")  % (int)((unsigned char)r[i]) << ";";  
        }
    }

    // Gets the bytes for a given prime.
    vector<char> getByteArray(cpp_int v)
    {
        vector<char> res;
        while(v != 0)
        {
            res.push_back((v & 255).convert_to<char>());
            v >>= 8; 
        }
        return res;
    }

   // Used for the XML generation. Produces something in the form tag="internal"
    string quotes(const string& tag, const string& internal)
    {
        return tag + "=\"" + internal + "\"";
    }

    // Used for XML generation, just casts the integer to a string. I could use C++11 libraries for this,
    // but since I already have a Boost Dependency, I'll use the boost library for backwards compatibility. 
    string quotes(const string& tag, int x)
    {
        return quotes(tag, lexical_cast<string>(x));
    }

    // Creates the XML File to be converted by a tool like "enber". 
    void createXML(vector<cpp_int>& params, ostream& file)
    {
        // This code could be really, really buggy.
        // Thus far, it has worked quite well though. :)

        // Gets the bytes for the modulus and the generator. 
        int tl1 = 2; 

        // Computes the length of all that the sequence contains.
        int length = tl1;

        // Used to extract the data from each element.
        vector< vector<char> > data;
        vector<int> tls; 

        // Iterates through each element.
        for(int i = 0; i < params.size(); i++)
        {
            // Gets the bytes from each.
            vector<char> bytes = getByteArray(params[i]);
            data.push_back(bytes);

            // "Length" Container
            int tl =2;
            
            // Computes the size of the "length" container
            if((int)(data[i].size()) +1 > 127) tl++;
            if((int)(data[i].size()) +1 > 256) tl++;

            // Stores the size of the length container.
            tls.push_back(tl);

            // Used to fix the ASN.1 Encoding for sizes divisible by 8.
            char adjust = 0;

            if(params[i] != 0)
            {
                // Detects if divisible by 8.
                adjust = (blog2(params[i])) % 8;

                // Adjusts the value
                if(adjust) adjust = 0;
                else adjust = 1;
            }
            else
            {
                // Ensures that there is a single byte to use.
                data[i].push_back(0);
            }

            // Adjust the overall length.
            length += tl + (int)(data[i].size() + adjust);
        }

        // Increases the sequence "length" container size.
        if(length > 127)
        {
            tl1++;
            length++;
        }

        // Increases the sequence "length" container size.
        if(length > 256)
        {
            tl1++; 
            length++;
        }

        // Offsets are computed by the number of bytes that are supposed to trail behind the section, you'll see them in the "O"s written below.
        // The "T"s are just tags that indicate what type of value they are in ASN1 Encoding.
        // The "TL"s are apparently the containers that describe the length of the section.
        // The "V"s are the actual size of the section. 
        // The "A"s describes what type it is.

        // Write the Sequence Header Tag
        file << "<C " << quotes("O", "0") << " " << quotes("T", "[UNIVERSAL 16]") << " " 
            << quotes("TL", tl1) << " " << quotes("V", length - tl1) << " " << quotes("A", "SEQUENCE") << ">" << endl; 

        int offset = tl1;

        // adds each element to the sequence.
        for(int i = 0; i < params.size(); i++)
        {
            // Used to fix the ASN.1 Encoding for sizes divisible by 8.
            char adjust = 0;

            if(params[i] != 0)
            {
                // Detects if divisible by 8.
                adjust = blog2(params[i]) % 8;

                // Adjusts the value
                if(adjust) adjust = 0;
                else adjust = 1;
            }

            // Write the Integer Header Tag (for the Modulus).
            file << "<P " << quotes("O", offset) << " " << quotes("T", "[UNIVERSAL 2]") << " " 
                << quotes("TL", tls[i]) << " " << quotes("V", (int)(data[i].size() + adjust)) << " " << quotes("A", "INTEGER") << ">"; 

            // This exists because OpenSSL has some weird quirks with how they format their der data.
            if(adjust) file << "&#x00;";

            // Write the bytes for the Modulus.
            printByteArray(data[i], file);
            
            // Close the Integer Tag
            file << "</P>" << endl;

            // Adjusts the offset for the next item by the current item's length.
            offset += tls[i] + (int)(data[i].size()) + adjust;
        }

        // Close the sequence.
        file << "</C " << quotes("O", length) << " " << quotes("T", "[UNIVERSAL 16]") << " " 
            << quotes("A", "SEQUENCE") << " " << quotes("L", length) << ">" << endl;
            
    }

    // Exports the parameters.
    void exportParameters(const string& outFile, vector<cpp_int>& params, char convert)
    {
        // Creates a string stream for an easy memory buffer.
        ostringstream conversion;

        
        // creates the xml version of the parameters.
        createXML(params, conversion);

        #ifdef LINKASN1C
        // If ASN1C is linked, it checks if the conversion flag is enabled.
        if(convert)
        {
            // If so, it converts the parameters and outputs a .der
            char outputBuffer[8192*2];
            int size; 
            
            // Processes the buffer using the utility from enber. 
            processBuffer(conversion.str().c_str(), conversion.str().length(), outputBuffer, &size);

            if(convert & 1)
            {
                // Outputs the returned buffer.
                ofstream ofs((outFile + ".der").c_str(), ios::binary);
                ofs.write(outputBuffer, size);
                ofs.close();
            }

            if(convert & 2)
            {
                ofstream ofs((outFile + ".pem").c_str());
                string outputString = base64_encode((unsigned char*)outputBuffer, size);
                
                // Used for the correct PEM Header.
                string pemType;

                // Erases the first two bits, for easy comparisons.
                convert &= ~3; 

                // Sets the correct PEM Header
                if(convert == NSPDH_DHPARAM)
                {
                    pemType = "DH PARAMETERS";
                }
                else if (convert == NSPDH_DSAPARAM)
                {
                    pemType = "DSA PARAMETERS";
                }

                // Outputs the header, body, and footer.
                ofs << "-----BEGIN " << pemType << "-----" << endl;
                ofs << outputString << endl;
                ofs << "-----END " << pemType << "-----" << endl;

                ofs.close(); 
            }
           
        }
        #endif
        
        // There will always be an output xml file. 
        ofstream ofs((outFile + ".xml").c_str());
        ofs << conversion.str();
        ofs.close();
    }

    // Exports the parameters. (Wrapper function)
    void exportParameters(const string& outFile, cpp_int& modulusPrime, cpp_int& generator, char convert)
    {
        // Creates a vector for the parameters and pushes them in order.
        vector<cpp_int> params;
        params.push_back(modulusPrime);
        params.push_back(generator);

        // Exports the parameters.
        exportParameters(outFile, params, convert);
    }
}
