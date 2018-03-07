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


function make_cryptopp()
{
    // For cryptopp
    if(isWindows())
    {   
        // This will be modified later on to allow you to pick which build you want to execute.
        if(detect("msbuild"))
        {
            sys("cd cryptopp & msbuild cryptlib.vcxproj /p:Configuration=Release /p:Platform=x64")
        }
        else
        {
            var make = "make"
            if(detect("mingw32-make")) make = "mingw32-make"
            sys("cd cryptopp & " + make + " libcryptopp.a")
        }
    }
    else
    {
        sys("cd cryptopp; make libcryptopp.a")
    }
}

make_cryptopp()

function nspdhOut()
{
    say("nspdh built.");       
    if(detect("upx")) 
        sys("upx nspdh.exe --lzma")
}

function make_asn1c()
{
    if(detect("msbuild"))
    {
        sys('cd asn1c-0.9.28/asn1c & cl /I"../libasn1compiler" /I"../libasn1print" /I"../libasn1parser" /I"../libasn1fix" /I"../skeletons" /DBufferMode /c enber.c')
        waitAll()
    }
    else
    {
        // already executed in make_nspdh
    }
}

function make_nspdh()
{
    say("Building program.")

     // This will be modified later on to allow you to pick which build you want to execute.
    if(detect("msbuild"))
    {
        make_asn1c()
        sys("cl /DLINKASN1C /DREQUIRE_XML_EXPORT src/*.cpp /openmp /Ox cryptopp/x64/Output/Release/cryptlib.lib asn1c-0.9.28/asn1c/enber.obj /DForce2011 /Fenspdh", nspdhOut)
    }
    else
    {
        var make = "make";
        if(detect("mingw32-make"))
        {
            make = "mingw32-make";
        }

        sys(make, nspdhOut);
    }

    
}

waitAll()
make_nspdh()
