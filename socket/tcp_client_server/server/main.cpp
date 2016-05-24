#include <stdio.h>

//#define _LINUX_

#ifdef _LINUX_
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <netinet/in.h>

#else // windows platform

    #include <winsock2.h>
    #include <windows.h>
    // Need to link with Ws2_32.lib
    #pragma comment (lib, "Ws2_32.lib")
#endif

#define  TCP_PORT    8099  // 20131
unsigned char  achEndTag[] = {0x00, 0x00, 0x00, 0x01, 0x09, 0x50};
#define  END_TAG_LEN         ( sizeof(achEndTag) / sizeof(achEndTag[0]) )

typedef struct client_para_tag
{
    SOCKET			accept_socket;
    SOCKADDR_IN		addr_client;
    int				addr_len;
} client_para_t;

static char *IpToStr(unsigned int ipDat)
{
    static char ipAddr[16] = {0};
    unsigned char abyIp[4] =
    {
        (ipDat & 0xFF),
        ((ipDat >> 8) & 0xFF),
        ((ipDat >> 16) & 0xFF),
        ((ipDat >> 24) & 0xFF)
    };
    sprintf(ipAddr, "%d.%d.%d.%d%c", abyIp[0], abyIp[1], abyIp[2], abyIp[3], 0);
    return ipAddr;
}

unsigned char achSendBuf[10<<20];
DWORD WINAPI ThreadProc(
    LPVOID lpParameter
//DWORD WINAPI ThreadProc(
//	__in  LPVOID lpParameter
)
{
    client_para_t* pclt = (client_para_t*)lpParameter;
    SOCKET AcceptSocket = pclt->accept_socket;
    unsigned int dwIp = pclt->addr_client.sin_addr.S_un.S_addr;
    char* pchIp = IpToStr(dwIp);
    printf("input socket:%d, addrclt:%s[%08x]@%d, len:%d\n",
           pclt->accept_socket, pchIp, dwIp, pclt->addr_client.sin_port,
           pclt->addr_len);

    //SOCKET AcceptSocket=(SOCKET) lpParameter;
    //���ջ������Ĵ�С��50���ַ�

	int idx = 0;
	int count = 0;
    unsigned char recvBuf[128<<10];
	unsigned char rcvTag[END_TAG_LEN];
	int picSize = 0;

	// do recv
	printf("client-socketfd:%d do-recv-bef\n", AcceptSocket);
    while(1)
    {
        count = recv(AcceptSocket, (char *)recvBuf, sizeof(recvBuf), 0);
        if (0 == count)
        {
			printf("client-socketfd:%d closed\n", AcceptSocket);
            break; // ���Է��ر�
        }

        if (SOCKET_ERROR == count)
		{
			printf("client-socketfd:%d error\n", AcceptSocket);
			break; // ����count<0
		}
		
		printf("accept client:%5d, buffer length:%5d, index:%5d\n", AcceptSocket, count, idx++);
		if (END_TAG_LEN == count)
		{
			memcpy(rcvTag, recvBuf, count); 
			if (0 == memcmp(rcvTag, achEndTag, count))
			{
				printf("accept client:%5d, receive end tag\n", AcceptSocket);
				break;
			}
			else
			{
				memcpy((void *)&(achSendBuf[picSize]), recvBuf, count);
				picSize += count;
			}
		}
		else
		{
			memcpy((void *)&(achSendBuf[picSize]), recvBuf, count);
			picSize += count;
		}
    }
	printf("client-socketfd:%d do-recv-end, rcvdat-size:%d\n", AcceptSocket, picSize);

	// do process
	printf("client-socketfd:%d do-process-bef\n", AcceptSocket);
	// ProcessPicture();
	printf("client-socketfd:%d do-process-end\n", AcceptSocket);

	// do send
	printf("client-socketfd:%d do-send-bef\n", AcceptSocket);
    int sendCount;
	int currentPosition=0;
	//sendCount = send(AcceptSocket, (char *)&count, sizeof(int), 0);
	printf("client-socketfd:%d do-send-size:%d\n", AcceptSocket, picSize);
    while ( picSize > 0 && (sendCount = send(AcceptSocket, (char *)achSendBuf+currentPosition, picSize, 0)) != SOCKET_ERROR)
    {
        picSize -= sendCount;
        currentPosition += sendCount;
		printf("client-socketfd:%d do-send-current-snd:%d\n", AcceptSocket, sendCount);
    }

    if (SOCKET_ERROR == sendCount)
	{
		printf("client-socketfd:%d error\n", AcceptSocket);
		 // ����count<0
	}
	printf("client-socketfd:%d do-send-end\n", AcceptSocket);

    // ��������
    closesocket(AcceptSocket);
    return 0;
}

int main(int argc, char* argv[])
{
    //----------------------
    // Initialize Winsock.
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != NO_ERROR)
    {
        wprintf(L"WSAStartup failed with error: %ld\n", iResult);
        return 1;
    }
    //----------------------
    // Create a SOCKET for listening for
    // incoming connection requests.
    SOCKET ListenSocket;
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET)
    {
        wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    //----------------------
    // The sockaddr_in structure specifies the address family,
    // IP address, and port for the socket that is being bound.
    sockaddr_in addrServer;
    addrServer.sin_family = AF_INET;
    addrServer.sin_addr.s_addr = htonl(INADDR_ANY); //ʵ������0
    addrServer.sin_port = htons(TCP_PORT);


    //���׽��ֵ�һ��IP��ַ��һ���˿���
    if (bind(ListenSocket,(SOCKADDR *) & addrServer, sizeof (addrServer)) == SOCKET_ERROR)
    {
        wprintf(L"bind failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    //���׽�������Ϊ����ģʽ�ȴ���������
    //----------------------
    // Listen for incoming connection requests.
    // on the created socket
    if (listen(ListenSocket, 5) == SOCKET_ERROR)
    {
        wprintf(L"listen failed with error: %ld\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    SOCKADDR_IN addrClient;
    int len=sizeof(SOCKADDR);
    client_para_t in_clt;

    //��һ������ѭ���ķ�ʽ����ͣ�ؽ��տͻ���socket����
    while(1)
    {
        //�������󣬽����������󣬷���һ���µĶ�Ӧ�ڴ˴����ӵ��׽���
        SOCKET AcceptSocket=accept(ListenSocket,(SOCKADDR*)&addrClient,&len);
        if(AcceptSocket  == INVALID_SOCKET)break; //����

        in_clt.accept_socket = AcceptSocket;
        memcpy(&in_clt.addr_client, &addrClient, sizeof(addrClient));
        in_clt.addr_len = len;

        //�����߳�
        DWORD dwThread;
        HANDLE hThread = CreateThread(NULL,0,ThreadProc,(LPVOID)&in_clt,0,&dwThread);
        if(hThread==NULL)
        {
            closesocket(AcceptSocket);
            wprintf(L"Thread Creat Failed!\n");
            break;
        }

        CloseHandle(hThread);
    }

    closesocket(ListenSocket);
    WSACleanup();
    return 0;
}

#if 0
input socket:1924, addrclt:192.168.0.105[6900a8c0]@10987, len:16
client-socketfd:1924 do-recv-bef
accept client: 1924, buffer length:37472, index:    0
accept client: 1924, buffer length:    6, index:    1
accept client: 1924, receive end tag
client-socketfd:1924 do-recv-end, rcvdat-size:37472
client-socketfd:1924 do-process-bef
client-socketfd:1924 do-process-end
client-socketfd:1924 do-send-bef
client-socketfd:1924 do-send-size:37472
client-socketfd:1924 do-send-current-snd:37472
client-socketfd:1924 do-send-end
---------------------
input socket:1924, addrclt:192.168.0.105[6900a8c0]@24296, len:16
client-socketfd:1924 do-recv-bef
accept client: 1924, buffer length:37472, index:    0
accept client: 1924, buffer length:    6, index:    1
accept client: 1924, receive end tag
client-socketfd:1924 do-recv-end, rcvdat-size:37472
client-socketfd:1924 do-process-bef
client-socketfd:1924 do-process-end
client-socketfd:1924 do-send-bef
client-socketfd:1924 do-send-size:37472
client-socketfd:1924 do-send-current-snd:37472
client-socketfd:1924 do-send-end

#endif