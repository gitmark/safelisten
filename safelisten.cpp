/***************************************************************************************
Copyright 2011 Mark Elrod. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of
      conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice, this list
      of conditions and the following disclaimer in the documentation and/or other materials
      provided with the distribution.

THIS SOFTWARE IS PROVIDED BY MARK ELROD ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MARK ELROD OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the
authors and should not be interpreted as representing official policies, either expressed
or implied, of Mark Elrod.
****************************************************************************************

10/01/11   Mark Elrod     SafeListen 

SafeListen is a simple program that allows you to safeley listen to a port to see who
is connecting and what they are sending. The app can help identify security threats
and troubleshoot network applicationsa. The app builds on Windows, OSX and Linux.


Usage:

safelisten 80


Example Output: (note, the IP addresses here have been changed for example purposes)	 

Enter q to quit.

2011/09/30 20:45:42 - 192.168.1.1
GET / HTTP/1.1..Host: 81.194.129.35..User-Agent: Mozilla/5.0 (iPod; U; CPU iPhone OS 4_3_5 like Mac OS X; en-us) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8L1 Safari/6533.18.5..Accept: application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,* / *;q=0.5..Accept-Language: en-us..Accept-Encoding: gzip, deflate..Connection: keep-alive....

2011/10/01 10:20:50 - 66.134.166.232
GET / HTTP/1.1..Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, * / *..Accept-Language: en-US..User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)..Accept-Encoding: gzip, deflate..Host: 78.194.129.95..Connection: Keep-Alive....


Design Goals:

A major design goal of the app was to give extremely limited power to the client app. Here 
is the initial set of rules that SafeListen followed:

- Don't allow the client to crash the app by sending an unlimited amount of data. The
app will read up to 1024 bytes and that's it. After that, the app closes the connection on the
client.

- Don't allow the client to hold the connection open forever. The app gives the client
up to one second to send some data. After that the app will close the connection. The
app was designed to be safe, not polite.

- Don't allow the client to overflow the app's input buffer. The app has a hard limit
on the number of bytes it will read to insure no chance of buffer overflow.

- Don't attempt to print binary or control characters sent by the client. The app
cleanses the data that is read by replacing all non-printable characters with a '.'
before printing.

- Don't allow the client to fill up the hard drive with log files. All output is sent
to standard out. The app has no direct file access, just standard out.

- Don't allow clients to over tax the app with an unlimited number of connections and
threads. The app is single threaded. The app has no obligation to accept every single
connection, and makes no attempt to do so. The app does not increase threads or 
resources used when an great number of connections are attempted simultaneously, thus
the app is not over taxed. The result is that some connections are not accepted, while
the app continues to work safely and comfortably.

The app will allow you to peek at how others are trying to connect to your system
without you worrying about them exploiting or crashing the app.

SafeListen has very few bells and whistles, so there is very little to break.


Build Instructions:

make
make install

****************************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WIN32
    #include <conio.h>
    #include <winsock2.h>
    #include <io.h>
    #define read	_read
    #define SHUT_RDWR	SD_SEND
    #define usleep(us)	Sleep(us/1000)
    int sizeNewSockAddr = 0;  
    class WSInit { 
    public: WSInit() { WSAStartup (MAKEWORD(2,2), &wsaData); }
            ~WSInit() { WSACleanup(); }
            WSAData wsaData;
    } wsInit;
    
    void PrintError(char *szError)
    {
        LPVOID pErrorMsg;
        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &pErrorMsg, 0, NULL );
        printf("%s: %s", szError, pErrorMsg);
        LocalFree(pErrorMsg);
    }    
#else
    #include <unistd.h>    
    #include <fcntl.h>
    #include <arpa/inet.h>
    #define     INVALID_SOCKET      -1
    #define	SOCKET_ERROR        -1
    #define     closesocket         close
    #define     PrintError(msg)     perror(msg) 
    socklen_t   sizeNewSockAddr     = 0;  
#endif

#define BACKLOG         5
#define READ_BUF_SIZE   1024
#define CMD_BUF_SIZE    1024
#define TIME_BUF_SIZE	1024
#define SOCKET          int

#define CHK(func) rc = func;\
error_code++;\
if(SOCKET_ERROR == rc){\
    PrintError("Error");\
    printf("%s\n", #func);\
    SafeClose(listenSocket);\
    SafeClose(newSocket);\
    return  error_code; \
}
 
int         on              = 1;
int         rc              = 0;
int         listenSocket    = INVALID_SOCKET;
int         newSocket       = INVALID_SOCKET;
int         error_code      = 1;
char        cleanAsciiMap [256];

void SafeClose(SOCKET s)
{
    if (s == INVALID_SOCKET)
        return;
    shutdown(s, SHUT_RDWR);
    closesocket(s);
}

void BuildCleanAsciiMap()
{
    for(int i = 0; i < 256; i++)
        cleanAsciiMap[i] = (i < 32 || i > 126)?46:i;
}

void CleanString(char* szString, int count)
{
    for(int i = 0; i < count; i++)
        szString[i] = cleanAsciiMap[(unsigned)szString[i]];
}
    
void ProcessConnection(SOCKET sock, sockaddr_in *sockAddr)
{
    time_t time1;
    char szTime[TIME_BUF_SIZE];
    char readBuf[READ_BUF_SIZE];
    
    time(&time1);
    strftime(szTime, TIME_BUF_SIZE-1, "%Y/%m/%d %H:%M:%S", localtime(&time1)); 
    printf("%s - %s\n", szTime, inet_ntoa(sockAddr->sin_addr));
    usleep(1000000);       // Wait 1 second for client to send something
    int actualReadCount = recv(sock, readBuf, READ_BUF_SIZE-1, 0); 

    if (actualReadCount < 0 || actualReadCount >= READ_BUF_SIZE){
        actualReadCount = 0;
        strcpy(readBuf, "(Nothing)");
    } else {
        CleanString(readBuf, actualReadCount);
        readBuf[actualReadCount] = 0;
    }

    printf("%s\n\n", readBuf);
    SafeClose(sock);
}

int SetNonBlocking(int sock)
{
    int rc = 0;
    #ifdef WIN32
	if (sock == 0) // Windows can't set stdin to non blocking with this command
            return 0;
        rc = ioctlsocket(sock, FIONBIO, (u_long*)&on);
    #else
        int options = fcntl(sock,F_GETFL);
        if (options < 0) 
            return -1;
	options |= O_NONBLOCK;
	if (fcntl(sock,F_SETFL,options) < 0) 
	    return -1;
    #endif
    return rc;
}

void ReadCmd(char* buf, int bufSize)
{   
    buf[0] = 0;
    #ifdef WIN32
	if (!_kbhit()) // The Windows version of nonblocking
            return;
    #endif

    int readCount = read(0, buf, bufSize-1);
    
    if (readCount < 0 || readCount >= bufSize)
        readCount = 0;
    
    buf[readCount] = 0;
    
    // Trim EOL
    char *ptr = buf + readCount - 1;
    while((*ptr == '\r' || *ptr == '\n') && ptr >= buf) 
        *ptr-- = 0;
}

int main(int argc, char* argv[])
{
    int             port         	= 80;
    char            cmd[CMD_BUF_SIZE]	= {0};
    sockaddr_in     newSockAddr;
    sockaddr_in     localSockAddr;
    
    if(argc < 2){
        printf("Usage: safelisten PORT\nEnter q to quit.\n\n");
        return error_code;
    }

    error_code++;
    port = atoi(argv[1]); 
    BuildCleanAsciiMap();

    localSockAddr.sin_family        = AF_INET;              
    localSockAddr.sin_addr.s_addr   = INADDR_ANY;           
    localSockAddr.sin_port          = htons(port);          
    sizeNewSockAddr                 = sizeof newSockAddr;

    CHK( listenSocket = socket(AF_INET, SOCK_STREAM, 0));
    CHK( setsockopt(listenSocket, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on)));
    CHK( bind(listenSocket, (sockaddr*)&localSockAddr, sizeof localSockAddr));
    CHK( listen(listenSocket, BACKLOG));
    CHK( SetNonBlocking(listenSocket));
    CHK( SetNonBlocking(0));		// Set STDIN to nonblocking for linux    
    printf ("Listening on port: %d\nEnter q to quit.\n\n", port);
    
    while(strcmp(cmd, "q")) // While the user has not entered q ...
    {
        newSocket = accept(listenSocket, (sockaddr*)&newSockAddr, &sizeNewSockAddr);
        ReadCmd(cmd, CMD_BUF_SIZE);

        if(newSocket == INVALID_SOCKET) { 
            // accept() would have blocked, thus we wait and try again
            usleep(10000);
            continue;	
        }
        
	// Set to nonblocking because we don't want the client to dictate how 
	// long we are connected.
        CHK( SetNonBlocking(newSocket)); 
        ProcessConnection(newSocket, &newSockAddr);
    }

    SafeClose(listenSocket);
    return 0;
}


