
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
    if(detect("unzip"))
    {
        // For accelerated extraction.
        var str = '/*'
        for(var i = 0; i < 6; i++)
        {
            sys("unzip boost.zip boost_1_65_1/boost" + str)
            str += '/*'
            waitAll()
        }
    }
    else if(detect("7za") || detect("7z") || detect("p7zip"))
    {
        // For accelerated extraction.
        var prog = "7za";
        if(detect("7z")) prog = "7z"
        if(detect("p7zip")) prog = "p7zip"

        sys(prog + " x boost.zip boost_1_65_1/boost")
    }
    else
    {
        say("This extraction might be slow.")
        extract(f);
    } 
});

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
            if(isWindows()) 
                sys("upx nspdh.exe --lzma")
            else 
                sys("upx nspdh --lzma")
    });
}

waitAll()
make_nspdh()
