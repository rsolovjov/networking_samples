#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <string>
#include "Packet.h"

using namespace std;

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27016"

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
	UserState userState;
	string userName;
	string userId;
};

struct UserData {
	ConnectionData *connectionData;
	IoOperationData *ioOperationData;
};

int userCounter = 1;
map<string, string> usernames;
map<string, UserData*> users;
map<string, vector<string>> channels;

DWORD WINAPI ServerWorkerThread(LPVOID pCompletionPort);
void HandleClientCommand(Packet *packet, ConnectionData *pConnectionData, IoOperationData *pIoData);
void AddUserToChannel(string const &userName, string const &channel, int& statusCode, string &statusDescription, string &response);
void RemoveUserFromChannel(string const &userId, string const &channel, int& statusCode, string &statusDescription, string &response);
void ListUsers(string const &channel, int& statusCode, string &statusDescription, string &response);
void SendMessageToChannel(string const &channel, string const &from, string const &message, int& statusCode, string &statusDescription, string &response);
void SendMessageToUser(string const &channel, string const &from, string const &to, string const &message);
void ListChannels(int& statusCode, string &statusDescription, string &response);

int __cdecl main(void)
{
	int error;

	WSADATA wsaData;
	error = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (error != 0) {
		printf("WSAStartup failed with error: %d\n", error);
		return EXIT_FAILURE;
	}

	// Создаем порт завершения
	HANDLE hCompletionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (hCompletionPort == NULL) {
		printf("CreateIoCompletionPort failed with error %d\n", GetLastError());
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Определяеи количество процессоров в системе
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);

	// Создаем рабочие потоки в зависимости от количества процессоров, по два потока на процессор
	for (int i = 0; i < (int)systemInfo.dwNumberOfProcessors * 2; ++i) {
		// Создаем поток и передаем в него порт завершения
		DWORD threadId;
		HANDLE hThread = CreateThread(NULL, 0, ServerWorkerThread, hCompletionPort, 0, &threadId);
		if (hThread == NULL) {
			printf("CreateThread() failed with error %d\n", GetLastError());
			WSACleanup();
			CloseHandle(hCompletionPort);
			return EXIT_FAILURE;
		}

		// Закрываем дескриптор потока, поток при этом не завершается
		CloseHandle(hThread);
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Преобразуем адрес и номер порта
	struct addrinfo *localAddr = NULL;
	error = getaddrinfo(NULL, DEFAULT_PORT, &hints, &localAddr);
	if (error != 0) {
		printf("getaddrinfo failed with error: %d\n", error);
		WSACleanup();
		return EXIT_FAILURE;
	}

	SOCKET listenSocket = WSASocketW(localAddr->ai_family, localAddr->ai_socktype, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (listenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(localAddr);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Привязываем сокет TCP к адресу и ждем подключения
	error = bind(listenSocket, localAddr->ai_addr, (int)localAddr->ai_addrlen);
	if (error == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(localAddr);
		closesocket(listenSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}

	freeaddrinfo(localAddr);

	error = listen(listenSocket, SOMAXCONN);
	if (error == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(listenSocket);
		WSACleanup();
		return EXIT_FAILURE;
	}

	// Принимаем соединения и связываем их с портом завершения
	for ( ; ; ) {
		SOCKET clientSocket = WSAAccept(listenSocket, NULL, NULL, NULL, 0);
		if (clientSocket == SOCKET_ERROR) {
			printf("WSAAccept failed with error %d\n", WSAGetLastError());
			return EXIT_FAILURE;
		}

		ConnectionData *pConnData = new ConnectionData;
		pConnData->socket = clientSocket;
		pConnData->userState = NEW;

		printf("New client connected\n");

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
	}
}


DWORD WINAPI ServerWorkerThread(LPVOID pCompletionPort)
{
	HANDLE hCompletionPort = (HANDLE)pCompletionPort;

	for ( ; ; ) {
		DWORD bytesTransferred;
		ConnectionData *pConnectionData;
		IoOperationData *pIoData;
		if (GetQueuedCompletionStatus(hCompletionPort, &bytesTransferred, (PULONG_PTR)&pConnectionData, (LPOVERLAPPED *)&pIoData, INFINITE) == 0) {
			printf("GetQueuedCompletionStatus() failed with error %d\n", GetLastError());
			return 0;
		}

		// Проверим, не было ли проблем с сокетом и не было ли закрыто соединение
		if (bytesTransferred == 0) {
			printf("closesocket. bytesTransferred == 0\n");
			closesocket(pConnectionData->socket);
			delete pConnectionData;
			delete pIoData;
			continue;
		}

		// Если bytesRecv равно 0, то мы начали принимать данные от клиента
		// с завершением вызова WSARecv()
		if (pIoData->bytesRecv == 0) {
			pIoData->bytesRecv = bytesTransferred;

			string rawData = string(pIoData->wsaBuf.buf, (size_t)pIoData->bytesRecv);
			printf_s("received from: %s, packet: %s\n", pConnectionData->userName.c_str(), rawData.c_str());

			Packet *packet = new Packet(rawData.c_str());
			HandleClientCommand(packet, pConnectionData, pIoData);

			pIoData->bytesSent = 0;
		} else {
			pIoData->bytesSent += bytesTransferred;
		}
		
		if (pIoData->bytesRecv > pIoData->bytesSent) {

			DWORD bytesSent;
			// Посылаем очередно запрос на ввод-вывод WSASend()
			// Так как WSASend() может отправить не все данные, то мы отправляем
			// оставшиеся данные из буфера пока не будут отправлены все
			ZeroMemory(&(pIoData->overlapped), sizeof(OVERLAPPED));
			pIoData->wsaBuf.buf = pIoData->buffer + pIoData->bytesSent;
			pIoData->wsaBuf.len = pIoData->bytesRecv - pIoData->bytesSent;
			if (WSASend(pConnectionData->socket, &(pIoData->wsaBuf), 1, &bytesSent, 0, &(pIoData->overlapped), NULL) == SOCKET_ERROR) {
				if (WSAGetLastError() != ERROR_IO_PENDING) {
					printf("WSASend failed with error %d\n", WSAGetLastError());
					return 0;
				}
			}

		} else {

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
}

void HandleClientCommand(Packet *packet, ConnectionData *pConnectionData, IoOperationData *pIoData)
{
	UserData *userData;
	map<string, string>::iterator userNamesIt;
	map<string, UserData*>::iterator userIt;

	CommandType responseType;
	int statusCode = 0;
	string statusDescription = "OK";
	string response;

	string userName;
	string userId;

	switch (packet->commandType)
	{
	case ID:
		responseType = ID;

		userNamesIt = usernames.find(packet->arg1);
		if (userNamesIt != usernames.end()) {
			statusCode = 2;
			statusDescription = "user with given name already exists";
			break;
		}
		if (packet->arg1.empty()) {
			statusCode = 3;
			statusDescription = "invalid arguments";
			break;
		}

		if (pConnectionData->userState == NEW) {

			userName = packet->arg1;
			userId = to_string(userCounter++);

			pConnectionData->userId = userId;
			pConnectionData->userName = userName;
			pConnectionData->userState = AUTHORIZED;

			userData = new UserData;
			userData->connectionData = pConnectionData;
			userData->ioOperationData = pIoData;
	
			users[userId] = userData;
			usernames[userName] = userId;
		}
		else {

			userId = pConnectionData->userId;
			userName = packet->arg1;

			users[userId]->connectionData->userName = userName;
			usernames.erase(userName);
			usernames[userName] = userId;
		}

		break;
	case JOIN:
		responseType = JOIN;

		if (pConnectionData->userState != AUTHORIZED) {
			statusCode = 4;
			statusDescription = "not authorized";
			break;
		}
		if (packet->arg1.empty()) {
			statusCode = 3;
			statusDescription = "invalid arguments";
			break;
		}

		userId = pConnectionData->userId;
		AddUserToChannel(userId, packet->arg1, statusCode, statusDescription, response);

		break;
	case USERS:
		responseType = USERS;

		if (pConnectionData->userState != AUTHORIZED) {
			statusCode = 4;
			statusDescription = "not authorized";
			break;
		}
		if (packet->arg1.empty()) {
			statusCode = 3;
			statusDescription = "invalid arguments";
			break;
		}

		ListUsers(packet->arg1, statusCode, statusDescription, response);
		break;
	case MSGC:
		responseType = MSGC;

		if (pConnectionData->userState != AUTHORIZED) {
			statusCode = 4;
			statusDescription = "not authorized";
			break;
		}
		if (packet->arg1.empty() || packet->arg2.empty()) {
			statusCode = 3;
			statusDescription = "invalid arguments";
			break;
		}

		SendMessageToChannel(packet->arg1, pConnectionData->userId, packet->arg2, statusCode, statusDescription, response);
		break;
	case MSGU:
		responseType = MSGU;

		if (pConnectionData->userState != AUTHORIZED) {
			statusCode = 4;
			statusDescription = "not authorized";
			break;
		}
		if (packet->arg1.empty() || packet->arg2.empty()) {
			statusCode = 3;
			statusDescription = "invalid arguments";
			break;
		}

		userNamesIt = usernames.find(packet->arg1);
		if (userNamesIt == usernames.end()) {
			statusCode = 3;
			statusDescription = "receiver not found";
			break;
		}

		userId = pConnectionData->userId;

		SendMessageToUser("", userId, userNamesIt->second, packet->arg2);
		break;
	case CHANNELS:
		responseType = CHANNELS;

		if (pConnectionData->userState != AUTHORIZED) {
			statusCode = 4;
			statusDescription = "not authorized";
			break;
		}

		ListChannels(statusCode, statusDescription, response);
		break;
	case LEAVE:
		responseType = LEAVE;

		if (pConnectionData->userState != AUTHORIZED) {
			statusCode = 4;
			statusDescription = "not authorized";
			break;
		}
		if (packet->arg1.empty()) {
			statusCode = 3;
			statusDescription = "invalid arguments";
			break;
		}

		userId = pConnectionData->userId;
		RemoveUserFromChannel(userId, packet->arg1, statusCode, statusDescription, response);

		break;
	default:
		responseType = INVALID;
		statusCode = 1;
		statusDescription = "invalid command";
		break;
	}

	Packet *responsePacket = new Packet(responseType, to_string(statusCode), statusDescription, response);

	string rawResponse = responsePacket->Encode();
	strncpy_s(pIoData->buffer, rawResponse.c_str(), DEFAULT_BUFLEN);
	pIoData->bytesRecv = rawResponse.length();

	printf_s("send to: %s, packet: %s\n", pConnectionData->userName.c_str(), pIoData->buffer);
}

void AddUserToChannel(string const &userId, string const &channel, int& statusCode, string &statusDescription, string &response)
{
	auto channelsIt = channels.find(channel);
	if (channelsIt != channels.end()) {

		vector<string>* members = &(channelsIt->second);
		if (std::find(members->begin(), members->end(), userId) != members->end()) {
			statusCode = 5;
			statusDescription = "channel aready contains this user";
		}
		else {
			members->push_back(userId);
		}
	}
	else {
		channels.insert(std::pair<string, vector<string>>(channel, vector<string> {userId}));
	}
}

void RemoveUserFromChannel(string const &userId, string const &channel, int& statusCode, string &statusDescription, string &response)
{
	auto channelsIt = channels.find(channel);
	if (channelsIt != channels.end()) {

		vector<string>* members = &(channelsIt->second);
		auto membersIt = find(members->begin(), members->end(), userId);

		if (membersIt != members->end()) {
			members->erase(membersIt);
		}
		else {
			statusCode = 7;
			statusDescription = "channel does not contain user with id " + userId;
		}
	}
	else {
		statusCode = 8;
		statusDescription = "channel not found ";
	}
}

void ListUsers(string const &channel, int& statusCode, string &statusDescription, string &response)
{
	auto channelsIt = channels.find(channel);
	if (channelsIt != channels.end()) {
		string result;

		auto members = channelsIt->second;

		unsigned int members_size = members.size();

		for (int i = 0; i < members_size; i++) {
			string userId = members[i];
			result = result + users[userId]->connectionData->userName + ",";
		}
			
		if (result.size() > 0)
			result.pop_back();

		response = result;
	}
	else {
		statusCode = 6;
		statusDescription = "channel does not exists";
	}
}

void SendMessageToChannel(string const &channel, string const &from, string const &message, int& statusCode, string &statusDescription, string &response)
{
	auto channelsIt = channels.find(channel);
	if (channelsIt != channels.end()) {
		auto members = channelsIt->second;
		unsigned int members_size = members.size();

		for (int i = 0; i < members_size; i++)
			SendMessageToUser(channel, from, members[i], message);
	}
	else {
		statusCode = 6;
		statusDescription = "channel does not exists";
	}
}

void SendMessageToUser(string const &channel, string const &from, string const &to, string const &message)
{
	string fromUserName = users[from]->connectionData->userName;

	Packet *messagePacket = new Packet(MSGS, channel, fromUserName, message);
	string rawMessage = messagePacket->Encode();

	char buffer[DEFAULT_BUFLEN];
	strncpy_s(buffer, rawMessage.c_str(), DEFAULT_BUFLEN);
	
	DWORD buffLength = rawMessage.length();
	
	WSABUF wsaBuf;
	wsaBuf.buf = buffer;
	wsaBuf.len = buffLength;
	
	printf_s("send to %s, message: %s\n", to.c_str(), buffer);

	DWORD bytesSent = 0;
	if (WSASend(users[to]->connectionData->socket, &(wsaBuf), 1, &bytesSent, 0, NULL, NULL) == SOCKET_ERROR) {
		if (WSAGetLastError() != ERROR_IO_PENDING) {
			printf_s("WSASend failed with error %d\n", WSAGetLastError());

		}
	}
}

void ListChannels(int& statusCode, string &statusDescription, string &response)
{
	string result;

	for (auto it = channels.begin(); it != channels.end(); ++it)
		result += it->first + ",";

	if (result.size() > 0)
		result.pop_back();

	response = result;
}