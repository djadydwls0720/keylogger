#include <WinSock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib");
#define BUFSIZE 4000


int main() {
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    SOCKADDR_IN serverAddr, clinetAddr;

    int clientAddrSize;
    int recvSize;
    char buf[BUFSIZE];

    FILE* fp;



    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return -1;
    }

    serverSocket = socket(PF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverSocket));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(serverSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        return -1;
    }
    if (listen(serverSocket, 100) == SOCKET_ERROR) {
        return -1;
    }
    clientAddrSize = sizeof(clinetAddr);

    //(recvSize = recv(clientSocket, buf, BUFSIZE, 0)) != 0
    while (1) {
        clientSocket = accept(serverSocket, (SOCKADDR*)&clinetAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET)
            break;

        while (1) {
            recvSize = recv(clientSocket, buf, BUFSIZE, 0);

            if (recvSize <= 0)
                break;

            fopen_s(&fp, "recv.txt", "wb");
            if (fp == NULL) {
                printf("error\n");
                break;
            }

            fwrite((void*)buf, 1, recvSize, fp);
            printf("¼ö½Å ¿Ï·á %d\n", recvSize);
            fclose(fp);
        }
        closesocket(clientSocket);
    }


    closesocket(serverSocket);
    WSACleanup();
    printf("¿¬°á ²÷±è2\n");
    return 0;
}