#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
//#include <map>
//#include <vector>
#include "Packet.h"

using namespace std;

#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27016"
#define DEFAULT_HOST "127.0.0.1"

enum UserState {
	NEW,
	AUTHORIZED
};

struct IoOperationData {
	OVERLAPPED overlapped;
	WSABUF wsaBuf;
	CHAR buffer[DEFAULT_BUFLEN];
	DWORD bytesSent;
	DWORD bytesRecv;
};

struct ConnectionData {
	SOCKET socket;
	string userName;
	string currentChannel;
	UserState userState;
};

void PrintHelp();
DWORD WINAPI ClientWorkerThread(LPVOID pCompletionPort);
void HandleReceivedPacket(Packet *packet, ConnectionData *pConnectionData, IoOperationData *pIoData);

int __cdecl main(int argc, char *argv[])
{
	string host = DEFAULT_HOST;

	// Проверка параметров командной строки
	if (argc == 2) {
		host = argv[1];
		//char t;
		//scanf_s(&t);
		//return EXIT_FAILURE;
	}

	int error;

	// Запускаем Winsock
	WSADATA wsaData;
	error = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (error != 0) {
		printf("WSAStartup failed with error: %d\n", error);
		return EXIT_FAILURE;
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Определяем адрес порт сервера
	struct addrinfo *serverAddr;
	error = getaddrinfo(host.c_str(), DEFAULT_PORT, &hints, &serverAddr);
	if (error != 0) {
		printf("getaddrinfo failed with error: %d\n", error);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Пытаемся подключиться к серверу по одному из опреденных адресов
	SOCKET clientSocket;
	for (struct addrinfo *ptr = serverAddr; ptr != NULL; ptr = ptr->ai_next) {

		// Пытаемся создать SOCKET для подключения
		clientSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (clientSocket == INVALID_SOCKET) {
			printf("socket failed with error: %ld\n", WSAGetLastError());
			WSACleanup();
			return EXIT_FAILURE;
		}

		// Осуществлем подключение
		error = connect(clientSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (error == SOCKET_ERROR) {
			printf("socket connect error. closesocket");
			closesocket(clientSocket);
			clientSocket = INVALID_SOCKET;
			continue;
		}

		break;
	}

	freeaddrinfo(serverAddr);

	if (clientSocket == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Создаем порт завершения
	HANDLE hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (hCompletionPort == NULL) {
		printf("CreateIoCompletionPort failed with error %d\n", GetLastError());
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Связываем поток обрабатывающий входящие сообщения и порт завершения
	DWORD threadId;
	HANDLE hThread = CreateThread(NULL, 0, ClientWorkerThread, hCompletionPort, 0, &threadId);
	if (hThread == NULL) {
		printf("CreateThread() failed with error %d\n", GetLastError());
		WSACleanup();
		CloseHandle(hCompletionPort);
		return EXIT_FAILURE;
	}

	// Закрываем дескриптор потока, поток при этом не завершается
	CloseHandle(hThread);

	// Структура описывающая состояние клиента
	ConnectionData *pConnData = new ConnectionData;
	pConnData->socket = clientSocket;
	pConnData->userState = NEW;

	// Связываем клиентский сокет с портом завершения
	if (CreateIoCompletionPort((HANDLE)clientSocket, hCompletionPort, (ULONG_PTR)pConnData, 0) == NULL) {
		printf("CreateIoCompletionPort failed with error %d\n", GetLastError());
		return EXIT_FAILURE;
	}

	// Создаем структуру для операций ввода-вывода и запускаем обработку
	IoOperationData *pIoData = new IoOperationData;
	ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
	pIoData->bytesSent = 0;
	pIoData->bytesRecv = 0;
	pIoData->wsaBuf.len = DEFAULT_BUFLEN;
	pIoData->wsaBuf.buf = pIoData->buffer;

	DWORD flags = 0;
	DWORD bytesRecv;
	if (WSARecv(clientSocket, &(pIoData->wsaBuf), 1, &bytesRecv, &flags, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			printf("WSARecv failed with error %d\n", WSAGetLastError());
			return EXIT_FAILURE;
		}
	}

	// ----==== HELP ====----
	PrintHelp();

	// Обрабатываем ввод комманд с клавиатуры 
	char cmdline[492];
	string command;

	for (;;) {
		scanf_s(" %[^\n]s", cmdline, (unsigned)_countof(cmdline));
		command = string(cmdline);

		Packet *packet = new Packet(cmdline);
		if (packet->commandType == UNDEFINED)
			continue;

		// Отправляем пакет
		string rawPacket = packet->Encode();
		const char *sendbuf = rawPacket.c_str();
		
		printf("send: %s\n", rawPacket.c_str());

		int bytesSent = send(clientSocket, sendbuf, (int)strlen(sendbuf), 0);
		if (bytesSent == SOCKET_ERROR) {
			printf("send failed with error: %d\n", WSAGetLastError());
			closesocket(clientSocket);
			WSACleanup();
			return EXIT_FAILURE;
		}
	}

	// Очистка
	closesocket(clientSocket);
	WSACleanup();

	return EXIT_SUCCESS;
}

DWORD WINAPI ClientWorkerThread(LPVOID pCompletionPort)
{
	HANDLE hCompletionPort = (HANDLE)pCompletionPort;

	for (;;) {

		DWORD bytesTransferred;
		ConnectionData *pConnectionData;
		IoOperationData *pIoData;
		if (GetQueuedCompletionStatus(hCompletionPort, &bytesTransferred, (PULONG_PTR)&pConnectionData, (LPOVERLAPPED *)&pIoData, INFINITE) == 0) {
			printf("GetQueuedCompletionStatus() failed with error %d\n", GetLastError());
			return 0;
		}

		// Проверим, не было ли проблем с сокетом и не было ли закрыто соединение
		if (bytesTransferred == 0) {
			closesocket(pConnectionData->socket);
			delete pConnectionData;
			delete pIoData;
			continue;
		}

		// ---=== Handle received data ===---

		pIoData->bytesRecv = bytesTransferred;
		string rawPacket = string(pIoData->wsaBuf.buf, (size_t)pIoData->bytesRecv);
		Packet *packet = new Packet(rawPacket.c_str());
		HandleReceivedPacket(packet, pConnectionData, pIoData);

		// ---=== Keep receiving data ===---

		DWORD bytesRecv;
		pIoData->bytesRecv = 0;
		// Когда все данные отправлены, посылаем запрос ввода-вывода на чтение WSARecv()
		DWORD flags = 0;
		ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
		pIoData->wsaBuf.len = DEFAULT_BUFLEN;
		pIoData->wsaBuf.buf = pIoData->buffer;
		if (WSARecv(pConnectionData->socket, &(pIoData->wsaBuf), 1, &bytesRecv, &flags, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
			if (WSAGetLastError() != ERROR_IO_PENDING) {
				printf("WSARecv failed with error %d\n", WSAGetLastError());
				return 0;
			}
		}
	}
}

void HandleReceivedPacket(Packet *packet, ConnectionData *pConnectionData, IoOperationData *pIoData)
{
	//string rawPacket = 
	printf_s("recv: %s\n", packet->Encode().c_str());
}

void PrintHelp()
{
	const char *help =
		"\n"
		"Commands:\n"
		"ID|<username> - authorize or change username\n"
		"JOIN|<channel> - join or create channel\n"
		"CHANNELS - list of channels\n"
		"USERS|<channel> - get members of channel\n"
		"LEAVE|<channel> - leave chanel\n"
		"MSGC|<channel>|<message> - send message to channel\n"
		"MSGU|<username>|<message> - send message to other user\n\n";

	printf(help);
}