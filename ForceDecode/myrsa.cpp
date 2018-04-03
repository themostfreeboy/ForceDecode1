/*
第1版说明(含有严重bug)：
由于MakePrime函数产生的密匙有时有问题，并不符合要求，所以要通过rsa1024_checkprivatekey函数验证产生的密匙是否符合要求，函数内部分为理论检测(不准确)和实际数据测试检测(较准确)两部分进行。
经过大量的数据测试，发现此版本有一个非常严重的bug。
此程序采用RSA的1024位加密强度的算法处理，采用分组处理，每组1024位，即1024/8=128byte，也就是128/4=32(int)，对每组的内容分别进行RSA算法的加密操作，最后一组中不全的数据采用(128-left_byte)的方式补全，为了避免left_byte(范围0~127)为0，所以采用(128-left_byte)(范围1~128)，然后再对最后一组加密处理。而且程序写入文件时，在文件头写入了3个byte的标志位，用于标志此文件是否为此软件所处理。所有解密过程对应进行逆操作即可。
但是，当文件为纯文本文档且文档内容均为ASC2码时一般无问题，但当含有中文时，或者处理其他数据文件时，当读取每组1024位(即128byte)的最后一个byte时，如果此字节数据的二进制最高位为1而不为0，即对应的十六进制范围为0x80~0xff时，也即读入的temp_in[31]为0x80~0xff时，在进行RSA算法的核心操作时，即vlong型数的与数论相关的指数运算与取模运算时，会将此数作为有符号数的负数处理，而不是作为无符号数处理，这时算完的数是有问题的，当再把此数逆运算解密回去会导致解密的结果与原数不一致。(当然，如果是文本文档或者其他数据文档，如果填充数128-left_byte=128时也落入此范围内，也会导致此bug。)
经过代码的查看，并没有发现具体在何处将此数作为了有符号数处理，只是觉得问题出现在vlong类中，具体的操作中所调用到的函数或类Encrypt，encrypt，modexp，monty，modinv，exp，monty_exp，docopy，copy，clear中，均未发现具体在何处作为了有符号数处理。
所以此bug无法通过修改相应的vlong型数的核心计算部分解决。
所以最终决定在下一版本中将文件加解密的分组算法修改，而不修改RSA算法的核心计算部分。
具体修改方案，目前打算，将每组分成127byte，而引发此bug的最高位temp_in[31]强制置为0x00，最后补充数据部分的插入值变为(127-left_byte)，其他插入值相关特殊极端情况的细节部分也作相应的单独处理，这样可以解决上述此版本的严重bug。解密过程仍为此新方案的逆过程。

第2版说明：
此版本中修复了上述的bug，整体采用的方法就是上述的解决方案。

第3版说明(当前版)：
由于private_key中只保存了p，q，n，e，并没有保存d，所以每次解密时都是要根据这些参数算出d后再进行相应操作，这样再批量解密时每次解密都会重复计算d的值，耗费了大量的无用时间，所以改进方案，d的值在产生密匙时就已经计算出来，存储在private_key类中，相应的类的设计以及其他相关函数都做相应的改变。
*/

#include "stdafx.h"

#include "myrsa.h"

private_key MakePrime(const unsigned long mode)//生成大质数p,q及n,e,d
{
	private_key pkey;
	char prand[2][512],tc;
	DWORD i,j,nn, nCount;
	srand((unsigned)time(NULL));
	if(mode == MODE_256)              nCount = 16;//生成256位
	    else if(mode == MODE_512)     nCount = 32;//生成512位
	    else if(mode == MODE_1024)    nCount = 64;//生成1024位
		else if(mode == MODE_2048)    nCount = 128;//生成2048位
		else if(mode == MODE_4096)    nCount = 256;//生成4096位

	for(i=0; i<2; i++)
	{
		for(j=0; j<nCount; j++)
		{
			tc = (char)(0x41+rand()%0xaf);
			prand[i][j] = tc;
		}
		prand[i][j]=0;
	}
	pkey.create(prand[0], prand[1]);//计算生成两个大质数p,q,以及n,e,d
	return pkey;
}

vlong Encrypt(const private_key pkey, const vlong m)//加密
{
	private_key temppkey;
	temppkey.p = pkey.p;
	temppkey.q = pkey.q;
	temppkey.n = pkey.n;
	temppkey.e = pkey.e;
	temppkey.d = pkey.d;
	vlong c = temppkey.encrypt(m);
	return c;
}

vlong Decrypt(const private_key pkey, const vlong c)//解密
{
	private_key temppkey;
	temppkey.p = pkey.p;
	temppkey.q = pkey.q;
	temppkey.n = pkey.n;
	temppkey.e = pkey.e;
	temppkey.d = pkey.d;
	vlong m = temppkey.decrypt(c);
	return m;
}

void print_privatekey(const private_key pkey)//显示私钥
{
	printf("p.length=%u\n",pkey.p.value->n);
	for(int i=0;i<pkey.p.value->n;i++)
	{
		printf("p[%u]=%08x\n",i,pkey.p.value->a[i]);
	}
	printf("q.length=%u\n",pkey.q.value->n);
	for(int i=0;i<pkey.q.value->n;i++)
	{
		printf("q[%u]=%08x\n",i,pkey.q.value->a[i]);
	}
	printf("n.length=%u\n",pkey.n.value->n);
	for(int i=0;i<pkey.n.value->n;i++)
	{
		printf("n[%u]=%08x\n",i,pkey.n.value->a[i]);
	}
	printf("e.length=%u\n",pkey.e.value->n);
	for(int i=0;i<pkey.e.value->n;i++)
	{
		printf("e[%u]=%08x\n",i,pkey.e.value->a[i]);
	}
	printf("d.length=%u\n",pkey.d.value->n);
	for(int i=0;i<pkey.d.value->n;i++)
	{
		printf("d[%u]=%08x\n",i,pkey.d.value->a[i]);
	}
}

void print_vlong(const vlong vl)//显示vlong型数
{
	printf("vl.length=%u\n",vl.value->n);
	for(int i=0;i<vl.value->n;i++)
	{
		printf("vl[%u]=%08x\n",i,vl.value->a[i]);
	}
}

bool rsa1024_checkprivatekey(const private_key pkey)//检测密匙是否符合要求(过程较慢，时间较长)
{
	//规则检测(实际此处规则检测即此软件产生密匙的算法，若用此软件产生密匙，再用此规则检测冗余，此规则检测主要检测其他外界导入的密匙是否符合规则，如果不符合则避免了下面更费时间的实际检测数据的加密解密。)
	if(is_probable_prime(pkey.p)==0)                        return false;//is_probable_prime函数检测质数并不全，只检测了能否被100以内的25个质数整除
	if(is_probable_prime(pkey.q)==0)                        return false;
	if(pkey.p*pkey.q!=pkey.n)                               return false;
	if(gcd(pkey.p-1,pkey.e)!=1||gcd(pkey.q-1,pkey.e)!=1)    return false;
	if(pkey.d!=modinv(pkey.e,(pkey.p-1)*(pkey.q-1)))        return false;

	 //采用实际数据检测
	vlong m;
	vlong c;
	vlong mm;
	unsigned long a[32]={0x61626364,0x65666779};
	for(int i=2;i<32;i++)   a[i]=0x79797979;
	m.load(a,32);
	c=Encrypt(pkey,m);
	mm=Decrypt(pkey,c);
	if(m!=mm)    return false;
	return true;
}

long rsa1024_MyGetFileSize(const char* filename)//获取文件大小，调用此函数时此文件必须处于未打开读写状态
{
	FILE *fp = NULL;
	errno_t err;
	err = fopen_s(&fp, filename, "rb");
	if (err != 0)
	{
		return -1;//文件打开失败
	}
    fseek(fp,0,SEEK_SET);
    fseek(fp,0,SEEK_END);
    long filesize=ftell(fp);
    rewind(fp);
	fclose(fp);
	return filesize;
}

int rsa1024_file_code(const char* readfilename, const char* writefilename, private_key &pkey, const unsigned long mode)//RSA算法1024位密码强度加密，文件头部写入3个byte标志位
{
	//检测readfilename文件是否存在
	errno_t err_read;
	FILE *fp_read = NULL;
	err_read = fopen_s(&fp_read, readfilename, "rb");
	if (err_read != 0)
	{
		return -1;//文件打开失败
	}
	fclose(fp_read);

	long read_filesize=rsa1024_MyGetFileSize(readfilename);//获取readfilename文件大小
	if(read_filesize == -1)
	{
		return -6;//文件打开失败
	}
	if(mode==MODE_CREATEPRIVATEKEY)//加密时产生密匙
	{
		pkey=MakePrime(MODE_1024);//产生1024位密钥
		while(rsa1024_checkprivatekey(pkey)==false)//产生的密匙不符合要求
		{
			pkey=MakePrime(MODE_1024);//重新产生1024位密钥
		}
	}
	else if(mode==MODE_NOCREATEPRIVATEKEY_CHECKPRIVATEKEY)//加密时不产生密匙，使用给定的密匙，但检测给定的密匙的合法性
	{
		if(rsa1024_checkprivatekey(pkey)==false)//密匙不符合要求
		{
			return -7;//密匙不符合要求
		}
	}
	else if(mode==MODE_NOCREATEPRIVATEKEY_NOCHECKPRIVATEKEY)//加密时不产生密匙，使用给定的密匙，也不检测给定的密匙的合法性，用于批量加密前已检测玩密匙合法性的情况
	{
		//不执行任何操作
	}
	unsigned long temp_in[32];
	unsigned long temp_out[32];
	vlong m;
	vlong c;
	long read_time=read_filesize/127+1;

	//readfilename文件存在
	errno_t err_write;
	FILE *fp_write = NULL;
	err_read = fopen_s(&fp_read, readfilename, "rb");
	if (err_read != 0)
	{
		return -3;//文件打开失败
	}
	err_write = fopen_s(&fp_write, writefilename, "wb");
	if (err_write != 0)
	{
		fclose(fp_read);
		return -4;//文件打开失败
	}

	//头部写入3个byte标志位
	fprintf(fp_write,"%c",('r')&(0xff));//代表rsa算法加密
	fprintf(fp_write,"%c",('2')&(0xff));//代表MODE_1024=2的1024位秘钥强度
	fprintf(fp_write,"%c",('c')&(0xff));//代表code加密处理

	unsigned char tempchar=0;
	unsigned int tempint=0;

	//前(read_time-1)次的加密处理
	for(int i=0;i<read_time-1;i++)
	{
		for(int j=0;j<32;j++)
		{
			if(j==31)//解决上一版本bug的对temp_in[31]的单独处理
			{
				tempint=0;
			    for(int k=0;k<3;k++)
		        {
			        fscanf(fp_read,"%c",&tempchar);
		            tempint=(tempint<<8)|(tempchar&(0xff));
		        }
			    temp_in[j]=tempint;
			}
			else
			{
				tempint=0;
			    for(int k=0;k<4;k++)
		        {
			        fscanf(fp_read,"%c",&tempchar);
		            tempint=(tempint<<8)|(tempchar&(0xff));
		        }
			    temp_in[j]=tempint;
			}
		}
		m.load(temp_in,32);
		c=Encrypt(pkey,m);
		c.store(temp_out,32);
		for(int j=0;j<32;j++)
		{
			tempint=temp_out[j];
			for(int k=0;k<4;k++)
			{
				tempchar=(tempint>>(24-8*k))&(0xff);
			    fprintf(fp_write,"%c",tempchar);
			}
		}
	}

	//最后一次的加密处理
	//最后一部分有数据部分的处理
	unsigned long left_byte=read_filesize-(read_time-1)*127;
	int j=0;
	for(j=0;j<left_byte/4;j++)
	{
		tempint=0;
		for(int k=0;k<4;k++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		temp_in[j]=tempint;
	}

	//最后一部分有数据但是最后不足一个int型(4 byte)的数据部分处理
	tempint=0;
	tempchar=127-left_byte;//为了避免填充的数据为0(left_byte数范围0~126)，所以采用(127-left_byte)这个数填充(此数范围1~127)
	for(int i=0;i<4;i++)
	{
		tempint=(tempint<<8)|(tempchar&(0xff));
	}
    for(int i=0;i<left_byte%4;i++)
	{
		fscanf(fp_read,"%c",&tempchar);
		tempint=(tempint<<8)|(tempchar&(0xff));
	}
	temp_in[j]=tempint;
	

	//最后一部分无数据部分自行填充数据处理
	tempint=0;
	tempchar=127-left_byte;
	for(int i=0;i<4;i++)
	{
		tempint=(tempint<<8)|(tempchar&(0xff));
	}
	for(int i=j+1;i<32;i++)
	{
		temp_in[i]=tempint;
	}

	//最后一部分的加密处理
	m.load(temp_in,32);
	c=Encrypt(pkey,m);
	c.store(temp_out,32);
	for(int j=0;j<32;j++)
	{
		tempint=temp_out[j];
		for(int k=0;k<4;k++)
		{
			tempchar=(tempint>>(24-8*k))&(0xff);
			fprintf(fp_write,"%c",tempchar);
		}
	}

	fclose(fp_read);
	fclose(fp_write);
	return 1;//加密成功
}

int rsa1024_file_decode(const char* readfilename, const char* writefilename, const private_key pkey)//RSA算法1024位密码强度解密，校检文件头部写入的3个byte标志位
{
	//检测readfilename文件是否存在
	errno_t err_read;
	FILE *fp_read = NULL;
	err_read = fopen_s(&fp_read, readfilename, "rb");
	if (err_read != 0)
	{
		return -1;//文件打开失败
	}
	fclose(fp_read);

	long read_filesize=rsa1024_MyGetFileSize(readfilename);//获取readfilename文件大小
	if(read_filesize == -1)
	{
		return -6;//文件打开失败
	}
	if(read_filesize%128!=3)//待解密文件错误
	{
		return -2;//待解密文件错误
	}

	unsigned long temp_in[32];
	unsigned long temp_out[32];
	vlong m;
	vlong c;
	unsigned long read_time=(read_filesize-3)/128;

	//readfilename文件存在
	errno_t err_write;
	FILE *fp_write = NULL;
	err_read = fopen_s(&fp_read, readfilename, "rb");
	if (err_read != 0)
	{
		return -3;//文件打开失败
	}

	//校检头部写入的3个byte标志位
	unsigned char tempchar1=0,tempchar2=0,tempchar3=0;
	fscanf(fp_read,"%c",&tempchar1);//代表rsa算法加密
	fscanf(fp_read,"%c",&tempchar2);//代表MODE_1024=2的1024位秘钥强度
	fscanf(fp_read,"%c",&tempchar3);//代表code加密处理
	if(tempchar1!='r' || tempchar2!='2' || tempchar3!='c')//待解密文件错误
	{
		fclose(fp_read);
		return -5;
	}

	err_write = fopen_s(&fp_write, writefilename, "wb");
	if (err_write != 0)
	{
		fclose(fp_read);
		return -4;//文件打开失败
	}

	unsigned char tempchar=0;
	unsigned int tempint=0;

	//前(read_time-1)次的解密处理
	for(int i=0;i<read_time-1;i++)
	{
		for(int j=0;j<32;j++)
		{
			tempint=0;
			for(int k=0;k<4;k++)
		    {
			    fscanf(fp_read,"%c",&tempchar);
		        tempint=(tempint<<8)|(tempchar&(0xff));
		    }
			temp_in[j]=tempint;
		}
		c.load(temp_in,32);
		m=Decrypt(pkey,c);
		m.store(temp_out,32);
		for(int j=0;j<32;j++)
		{
			if(j==31)//解决上一版本bug的对temp_out[31]的单独处理
			{
				tempint=temp_out[j];
			    for(int k=1;k<4;k++)
		        {
			        tempchar=(tempint>>(24-8*k))&(0xff);
			        fprintf(fp_write,"%c",tempchar);
		        }
			}
			else
			{
				tempint=temp_out[j];
			    for(int k=0;k<4;k++)
		        {
			        tempchar=(tempint>>(24-8*k))&(0xff);
			        fprintf(fp_write,"%c",tempchar);
		        }
			}
		}
	}

	//最后一次的解密处理
	for(int j=0;j<32;j++)
	{
		tempint=0;
		for(int k=0;k<4;k++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		temp_in[j]=tempint;
	}
	c.load(temp_in,32);
	m=Decrypt(pkey,c);
	m.store(temp_out,32);

	//最后一部分有数据部分的处理
	unsigned long left_byte=127-(temp_out[31]>>24)&(0xff);
	int j=0;
	for(j=0;j<left_byte/4;j++)
	{
		tempint=temp_out[j];
		for(int k=0;k<4;k++)
		{
			tempchar=(tempint>>(24-8*k))&(0xff);
			fprintf(fp_write,"%c",tempchar);
		}
	}

	//最后一部分有数据但是最后不足一个int型(4 byte)的数据部分处理
	tempint=temp_out[j];
	for(int i=0;i<left_byte%4;i++)
	{
		tempchar=(tempint>>(8*(left_byte%4-i-1)))&(0xff);
		fprintf(fp_write,"%c",tempchar);
	}

	fclose(fp_read);
	fclose(fp_write);
	return 1;//解密成功
}

int rsa1024_privatekey_outtofile(const char* writefilename, const private_key pkey)//导出密匙到文件
{
	//检测writefilename文件能否打开
	errno_t err_write;
	FILE *fp_write = NULL;
	err_write = fopen_s(&fp_write, writefilename, "wb");
	if (err_write != 0)
	{
		return -1;//文件打开失败
	}

	//头部写入3个byte标志位
	fprintf(fp_write,"%c",('r')&(0xff));//代表rsa算法加密
	fprintf(fp_write,"%c",('2')&(0xff));//代表MODE_1024=2的1024位秘钥强度
	fprintf(fp_write,"%c",('k')&(0xff));//代表key密匙文件

	unsigned char tempchar=0;
	unsigned int tempint=0;

	//写入p
	tempint=pkey.p.value->n;
	tempchar=tempint&(0xff);
	fprintf(fp_write,"%c",tempchar);
	for(int i=0;i<pkey.p.value->n;i++)
	{
		tempint=pkey.p.value->a[i];
		for(int j=0;j<4;j++)
		{
			tempchar=(tempint>>(24-8*j))&(0xff);
		    fprintf(fp_write,"%c",tempchar);
		}
	}

	//写入q
	tempint=pkey.q.value->n;
	tempchar=tempint&(0xff);
	fprintf(fp_write,"%c",tempchar);
	for(int i=0;i<pkey.q.value->n;i++)
	{
		tempint=pkey.q.value->a[i];
		for(int j=0;j<4;j++)
		{
			tempchar=(tempint>>(24-8*j))&(0xff);
		    fprintf(fp_write,"%c",tempchar);
		}
	}

	//写入n
	tempint=pkey.n.value->n;
	tempchar=tempint&(0xff);
	fprintf(fp_write,"%c",tempchar);
	for(int i=0;i<pkey.n.value->n;i++)
	{
		tempint=pkey.n.value->a[i];
		for(int j=0;j<4;j++)
		{
			tempchar=(tempint>>(24-8*j))&(0xff);
		    fprintf(fp_write,"%c",tempchar);
		}
	}

	//写入e
	tempint=pkey.e.value->n;
	tempchar=tempint&(0xff);
	fprintf(fp_write,"%c",tempchar);
	for(int i=0;i<pkey.e.value->n;i++)
	{
		tempint=pkey.e.value->a[i];
		for(int j=0;j<4;j++)
		{
			tempchar=(tempint>>(24-8*j))&(0xff);
		    fprintf(fp_write,"%c",tempchar);
		}
	}

	//写入d
	tempint=pkey.d.value->n;
	tempchar=tempint&(0xff);
	fprintf(fp_write,"%c",tempchar);
	for(int i=0;i<pkey.d.value->n;i++)
	{
		tempint=pkey.d.value->a[i];
		for(int j=0;j<4;j++)
		{
			tempchar=(tempint>>(24-8*j))&(0xff);
		    fprintf(fp_write,"%c",tempchar);
		}
	}

	fclose(fp_write);
	return 1;//导出成功
}

int rsa1024_privatekey_loadfromfile(const char* readfilename, private_key &pkey)//从文件中导入密匙
{
	//检测readfilename文件是否存在
	errno_t err_read;
	FILE *fp_read = NULL;
	err_read = fopen_s(&fp_read, readfilename, "rb");
	if (err_read != 0)
	{
		return -1;//文件打开失败
	}

	//校检头部写入的3个byte标志位
	unsigned char tempchar1=0,tempchar2=0,tempchar3=0;
	fscanf(fp_read,"%c",&tempchar1);//代表rsa算法加密
	fscanf(fp_read,"%c",&tempchar2);//代表MODE_1024=2的1024位秘钥强度
	fscanf(fp_read,"%c",&tempchar3);//代表key密匙文件
	if(tempchar1!='r' || tempchar2!='2' || tempchar3!='k')//待导入文件错误
	{
		fclose(fp_read);
		return -2;
	}

	unsigned char tempchar=0;
	unsigned int tempint=0;
	unsigned int templength=0;
	unsigned long tempdata[128];

	//导入p
	fscanf(fp_read,"%c",&templength);
	for(int i=0;i<templength;i++)
	{
		tempint=0;
		for(int j=0;j<4;j++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		tempdata[i]=tempint;
	}
	pkey.p.load(tempdata,templength);

	//导入q
	fscanf(fp_read,"%c",&templength);
	for(int i=0;i<templength;i++)
	{
		tempint=0;
		for(int j=0;j<4;j++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		tempdata[i]=tempint;
	}
	pkey.q.load(tempdata,templength);

	//导入n
	fscanf(fp_read,"%c",&templength);
	for(int i=0;i<templength;i++)
	{
		tempint=0;
		for(int j=0;j<4;j++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		tempdata[i]=tempint;
	}
	pkey.n.load(tempdata,templength);

	//导入e
	fscanf(fp_read,"%c",&templength);
	for(int i=0;i<templength;i++)
	{
		tempint=0;
		for(int j=0;j<4;j++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		tempdata[i]=tempint;
	}
	pkey.e.load(tempdata,templength);

	//导入d
	fscanf(fp_read,"%c",&templength);
	for(int i=0;i<templength;i++)
	{
		tempint=0;
		for(int j=0;j<4;j++)
		{
			fscanf(fp_read,"%c",&tempchar);
		    tempint=(tempint<<8)|(tempchar&(0xff));
		}
		tempdata[i]=tempint;
	}
	pkey.d.load(tempdata,templength);

	fclose(fp_read);
	return 1;//导入成功
}