#pragma once

#ifndef __MYRSA_H
#define __MYRSA_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "prime.h"
#include "vlong.h"
#include "rsa.h"

#define MODE_256  0//256位密码强度
#define MODE_512  1//512位密码强度
#define MODE_1024 2//1024位密码强度
#define MODE_2048 3//2048位密码强度
#define MODE_4096 4//4096位密码强度

#define MODE_CREATEPRIVATEKEY                     0//加密时产生密匙
#define MODE_NOCREATEPRIVATEKEY_CHECKPRIVATEKEY   1//加密时不产生密匙，使用给定的密匙，但检测给定的密匙的合法性
#define MODE_NOCREATEPRIVATEKEY_NOCHECKPRIVATEKEY 2//加密时不产生密匙，使用给定的密匙，也不检测给定的密匙的合法性，用于批量加密前已检测玩密匙合法性的情况

private_key MakePrime(const unsigned long mode);//生成大质数p,q及n,e
vlong Encrypt(const private_key pkey, const vlong m);//加密
vlong Decrypt(const private_key pkey, const vlong c);//解密
void print_privatekey(const private_key pkey);//显示私钥
void print_vlong(const vlong vl);//显示vlong型数
bool rsa1024_checkprivatekey(const private_key pkey);//检测密匙是否符合要求(过程较慢，时间较长)
long rsa1024_MyGetFileSize(const char* filename);//获取文件大小，调用此函数时此文件必须处于未打开读写状态
int rsa1024_file_code(const char* readfilename, const char* writefilename, private_key &pkey, const unsigned long mode);//RSA算法1024位密码强度加密，文件头部写入3个byte标志位
int rsa1024_file_decode(const char* readfilename, const char* writefilename, const private_key pkey);//RSA算法1024位密码强度解密，校检文件头部写入的3个byte标志位
int rsa1024_privatekey_outtofile(const char* writefilename, const private_key pkey);//导出密匙到文件
int rsa1024_privatekey_loadfromfile(const char* readfilename, private_key &pkey);//从文件中导入密匙

#endif