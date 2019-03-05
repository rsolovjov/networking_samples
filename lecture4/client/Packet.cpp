#include "Packet.h"


Packet::Packet()
{
}

Packet::Packet(const char* raw)
{
	Decode(raw);
}

Packet::Packet(CommandType command, string arg1, string arg2, string arg3)
{
	this->commandType = command;
	this->arg1 = arg1;
	this->arg2 = arg2;
	this->arg3 = arg3;
}

Packet::~Packet()
{
}

string Packet::Encode()
{
	if (this->commandType == UNDEFINED)
		return "";

	string result = commandTypeToString[this->commandType];
	if (this->arg1 != "") result += "|" + this->arg1;
	if (this->arg2 != "") result += "|" + this->arg2;
	if (this->arg3 != "") result += "|" + this->arg3;

	return result;
}

void Packet::Decode(const char* raw)
{
	vector<string> split1 = Packet::Split(raw, '\n');
	vector<string> split2 = Packet::Split(split1[0], '|');

	if (split2.size() > 0)
		this->commandType = commandTypeFromString[split2[0]];

	if (this->commandType == UNDEFINED)
		return;

	if (split2.size() > 1)
		this->arg1 = split2[1];
	if (split2.size() > 2)
		this->arg2 = split2[2];
	if (split2.size() > 3)
		this->arg3 = split2[3];
}

vector<string> Packet::Split(const string &s, char delim)
{
	stringstream test(s);
	string segment;
	vector<string> seglist;

	while (std::getline(test, segment, delim))
		seglist.push_back(segment);

	return seglist;
}