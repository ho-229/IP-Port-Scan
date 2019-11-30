#pragma once

#include<thread>
#include<iostream>
#include<winsock.h>
#include<string>
#include<fstream>
#include<sstream>
#include<vector>
#include<atomic>
#include<Windows.h>
#include<mutex>
#pragma comment(lib,"Ws2_32.lib")
using namespace std;

inline void color(int c);						//控制台颜色函数
bool init_WSA();								//SOCKET初始化函数
void Get_IPs(vector<string>& IPs, string& Start_IP_Addr, string& End_IP_Addr);//IP整理函数
void Scan_IP_Port(vector<string>& IPs, ofstream & out_IP, const size_t & size);//IP扫描函数
