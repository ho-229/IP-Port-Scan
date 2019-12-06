#include"main.h"

unsigned Port;						//扫描端口

atomic_int32_t Search_Compelet;		//扫描完成数
atomic_int32_t Open_IP;				//开放端口数
mutex mtx;							//线程互斥锁

void color(int c)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), c);
	return;
}

void Get_IPs(vector<string>& IPs, string& Start_IP_Addr, string& End_IP_Addr)
{
	color(11);
	cout << endl << "正在整理IP地址. . ." << endl;
	unsigned long Start_IP = htonl(inet_addr(Start_IP_Addr.c_str()));
	unsigned long End_IP = htonl(inet_addr(End_IP_Addr.c_str()));
	if (Start_IP > End_IP)
	{
		color(12);
		cout << "Error : Start_IP must be smaller than End_IP!";
	}
	else
	{
		in_addr addr;
		for (unsigned long Index = Start_IP; Index <= End_IP; Index++)
		{
			addr.S_un.S_addr = ntohl(Index);
			IPs.push_back(inet_ntoa(addr));
		}
	}
}

bool init_WSA()
{
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(1, 1);
	if (WSAStartup(wVersionRequested, &wsaData))
	{
		color(12);
		cout << "Winsock Initialization failed." << endl;
		system("pause");
		return false;
	}
	else
		return true;
}

void Scan_IP_Port(vector<string>& IPs,ofstream& out_IP, const size_t& size)
{
	SOCKET mysocket = NULL;
	sockaddr_in my_addr;
	while (Search_Compelet != size)
	{
		string& IP = IPs[Search_Compelet];
		Search_Compelet++;
		size_t TimeOut = 1000;								//设置超时1s
		if ((mysocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET && 
			setsockopt(mysocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&TimeOut, sizeof(size_t) == SOCKET_ERROR))
		{
			color(12);
			cout << "socket is invalid." << endl;
		}
		my_addr.sin_family = AF_INET;
		my_addr.sin_port = htons(Port);
		my_addr.sin_addr.s_addr = inet_addr(IP.c_str());
		if (connect(mysocket, (sockaddr *)&my_addr, sizeof sockaddr) != SOCKET_ERROR)
		{
			Open_IP++;
			lock_guard<mutex>temp(mtx);
			color(11);
			cout << IP << " Port " << Port << " is open\n";
			out_IP << IP << endl;
		}
		else
		{
			lock_guard<mutex>temp(mtx);
			color(14);
			cout << IP << " connect failed!\n";
		}
	}
	closesocket(mysocket);
	return;
}

int main()
{
	unsigned thread_number;
	color(14);
	cout << "欢 迎 使 用 IP 段 扫 描 器（ BY : Ho229 ）" << endl;
	if (init_WSA())
	{
		ifstream in_IP("IP.txt", ios::in);
		if (in_IP.is_open())
		{
			vector<string>IPs;
			ofstream out_IP("Result.txt", ios::trunc);
			string Start_IP_Addr, End_IP_Addr;
			cout << "请输入扫描线程数 ( WARNING ) :";
			cin >> thread_number;
			thread_number > 1400 ? thread_number = 1400 : NULL;		//设置最大线程数1400
			cout << "请输入要扫描的端口:";
			cin >> Port;
			while (!in_IP.eof())
			{
				in_IP >> Start_IP_Addr >> End_IP_Addr;
				Get_IPs(IPs, Start_IP_Addr, End_IP_Addr);
				color(13);
				cout << "Normal Seach: About To Seach " << IPs.size() << " IP Using " << thread_number << " Threads" << endl;
				color(11);
				Open_IP = 0;
				Search_Compelet = 0;
				thread*Scan_Thread = new thread[thread_number];
				
				try
				{
					/*创建扫描线程*/
					for (size_t i = 0; i < thread_number; i++)
					{
						Scan_Thread[i] = thread([&]() {
							Scan_IP_Port(IPs, out_IP, IPs.size());
						});
					}
					/*等待扫描线程*/
					for (size_t i = 0; i < thread_number; i++)
					{
						if (Scan_Thread[i].joinable())
							Scan_Thread[i].join();
					}
				}
				catch (const exception& err)
				{
					color(12);
					cout << "System Error:" << err.what() << endl;
				}

				IPs.clear();
				delete[]Scan_Thread;
				color(13);
				cout << Start_IP_Addr << " -->> " << End_IP_Addr << " Search Complete.Found " << Open_IP << "Result." << endl;
			}
			in_IP.close();
			out_IP.close();
			cout << "==================  扫描完成! =================" << endl;
		}
		else
		{
			color(12);
			cout << "无法打开文件（ IP.txt ）！" << endl;
		}
		WSACleanup();
		system("pause");
	}
	return EXIT_SUCCESS;
}