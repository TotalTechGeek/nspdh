if(isMac())
{
    say("Warning: The default Mac clang compiler (even aliased gcc) will not work with this project, as it lacks OpenMP support.")
    say("If you have another compiler, you can define it with 'export CXX=g++-7' and 'export CCX=gcc-7' prior to executing the build.")
    say("")
}


// Asn1c
Resource("http://lionet.info/soft/asn1c-0.9.28.tar.gz", "asn1c.tar.gz", function (f) 
{ 
    extract(f); 
    extract("asn1c.tar");
    copy("resources/enber.c", "asn1c-0.9.28/asn1c/enber.c");
    copy("resources/unber.c", "asn1c-0.9.28/asn1c/unber.c");
    copy("resources/getopt.h", "asn1c-0.9.28/asn1c/getopt.h");
});


// cryptopp
Resource("https://www.cryptopp.com/cryptopp600.zip", "cryptopp.zip", function(f)
{
    extract2(f, "cryptopp")
})

// For cryptopp
if(isWindows())
{
    var make = "make"
    if(detect("mingw32-make")) make = "mingw32-make"
    sys("cd cryptopp & " + make + " libcryptopp.a")
}
else
{
    sys("cd cryptopp; make libcryptopp.a")
}

function make_nspdh()
{
    say("Building program.")
    var make = "make";
    if(detect("mingw32-make"))
    {
        make = "mingw32-make";
    }

    sys(make, function()
    {
        say("nspdh built.");       
        if(detect("upx")) 
             sys("upx nspdh.exe --lzma")
    });
}

waitAll()
make_nspdh()
