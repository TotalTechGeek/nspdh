
// Asn1c
Resource("http://lionet.info/soft/asn1c-0.9.28.tar.gz", "asn1c.tar.gz", function (f) 
{ 
    extract(f); 
    extract("asn1c.tar");
    copy("resources/enber.c", "asn1c-0.9.28/asn1c/enber.c");
    copy("resources/unber.c", "asn1c-0.9.28/asn1c/unber.c");
    copy("resources/getopt.h", "asn1c-0.9.28/asn1c/getopt.h");
});

// Boost
Resource("https://dl.bintray.com/boostorg/release/1.65.1/source/boost_1_65_1.zip", "boost.zip", function(f)
{
    extract(f);
});

function make_nspdh()
{
    var make = "make";
    if(detect("mingw32-make"))
    {
        make = "mingw32-make";
    }

    sys(make + " -j", function()
    {
        say("nspdh built.");       
        if(detect("upx")) 
            if(isWindows()) 
                sys("upx nspdh.exe --lzma")
            else 
                sys("upx nspdh --lzma")
    });
}

make_nspdh()
