#pragma once

#include <stdlib.h>
#include <stdio.h>

#include <string>
#include <sstream>
#include <vector>
#include <map>

#include <iostream>

using namespace std;

enum CommandType {
	UNDEFINED,
	ID,
	MSGC,
	MSGU,
	MSGS,
	USERS,
	JOIN,
	LEAVE,
	CHANNELS,
	INVALID
};

struct CommandTypeMapEnum : public map<unsigned int, string>
{
	CommandTypeMapEnum()
	{
		this->operator[](UNDEFINED) = "UNDEFINED";
		this->operator[](ID) = "ID";
		this->operator[](MSGC) = "MSGC";
		this->operator[](MSGU) = "MSGU";
		this->operator[](MSGS) = "MSGS";
		this->operator[](USERS) = "USERS";
		this->operator[](JOIN) = "JOIN";
		this->operator[](LEAVE) = "LEAVE";
		this->operator[](CHANNELS) = "CHANNELS";
		this->operator[](INVALID) = "INVALID";
	};
	~CommandTypeMapEnum() {}
};

struct CommandTypeMapString : public map<string, CommandType>
{
	CommandTypeMapString()
	{
		this->operator[]("UNDEFINED") = UNDEFINED;
		this->operator[]("ID") = ID;
		this->operator[]("MSGC") = MSGC;
		this->operator[]("MSGU") = MSGU;
		this->operator[]("MSGS") = MSGS;
		this->operator[]("USERS") = USERS;
		this->operator[]("JOIN") = JOIN;
		this->operator[]("LEAVE") = LEAVE;
		this->operator[]("CHANNELS") = CHANNELS;
		this->operator[]("INVALID") = INVALID;
	};
	~CommandTypeMapString() {}
};

class Packet
{
public:
	CommandType commandType;
	string arg1;
	string arg2;
	string arg3;

	string Encode();

	Packet();
	Packet(const char * raw);
	Packet(CommandType command, string arg1, string arg2, string arg3);
	~Packet();

private:
	CommandTypeMapString commandTypeFromString;
	CommandTypeMapEnum commandTypeToString;

	void Decode(const char * rawData);
	vector<string> Split(const string &s, char delim);
};

