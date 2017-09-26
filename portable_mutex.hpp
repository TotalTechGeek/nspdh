#ifndef _PORTABLE_MUTEX_
#define _PORTABLE_MUTEX_ 
#if __cplusplus <= 199711L && !defined(Force2011)
#include <pthread.h>
#else
#include <mutex>
#endif

// This exists so that the code is compatible with multiple compilers.
// Mainly to help me with server access, I am supporting compilers that lack full C++11 support.
// I don't care about supporting Old Windows compilers, which is why I'm supporting only pthreads.
class Mutex
{
    private:
    #if __cplusplus <= 199711L && !defined(Force2011)
    pthread_mutex_t mut;
    #else
    std::mutex mut; 
    #endif

    public:
    Mutex()
    {
            #if __cplusplus <= 199711L && !defined(Force2011)
            pthread_mutex_init(&mut, NULL);         
            #endif
    }

    ~Mutex()
    {
        #if __cplusplus <= 199711L && !defined(Force2011)
        pthread_mutex_destroy(&mut);
        #endif
    }

    // Locks the Mutex.
    void Lock()
    {
        #if __cplusplus <= 199711L && !defined(Force2011)
        pthread_mutex_lock(&mut);
        #else
        mut.lock();
        #endif
    }

    // Unlocks the Mutex.
    void Unlock()
    {
        #if __cplusplus <= 199711L && !defined(Force2011)
        pthread_mutex_unlock(&mut);
        #else
        mut.unlock();
        #endif
    }
};
#endif
