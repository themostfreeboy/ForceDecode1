
// ForceDecodeDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "ForceDecode.h"
#include "ForceDecodeDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif



private_key pkey;
static int threadnum=0;
static bool threadstart=false;



// CForceDecodeDlg 对话框




CForceDecodeDlg::CForceDecodeDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CForceDecodeDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CForceDecodeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CForceDecodeDlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BFOLDER, &CForceDecodeDlg::OnBnClickedBfolder)
	ON_BN_CLICKED(IDC_BKEY, &CForceDecodeDlg::OnBnClickedBkey)
	ON_BN_CLICKED(IDC_BDECODE, &CForceDecodeDlg::OnBnClickedBdecode)
	ON_BN_CLICKED(IDC_BEXIT, &CForceDecodeDlg::OnBnClickedBexit)
END_MESSAGE_MAP()


// CForceDecodeDlg 消息处理程序

BOOL CForceDecodeDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CForceDecodeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CForceDecodeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CForceDecodeDlg::OnBnClickedBfolder()
{
	// TODO: 在此添加控件通知处理程序代码
	TCHAR szFolderPath[MAX_PATH] = {0};//存放选择的目录路径
    CString strFolderPath = _T("");

    ZeroMemory(szFolderPath, sizeof(szFolderPath));

    BROWSEINFO bi;
    bi.hwndOwner = m_hWnd;//父窗口句柄
    bi.pidlRoot = NULL;//要显示的文件目录对话框的根(Root)
    bi.pszDisplayName = szFolderPath;//保存被选取的文件夹路径的缓冲区
    bi.lpszTitle = _T("请选择文件夹");//显示位于对话框左上部的标题
    bi.ulFlags = 0;//指定对话框的外观和功能的标志
    bi.lpfn = NULL;//处理事件的回调函数
    bi.lParam = 0;//应用程序传给回调函数的参数
    bi.iImage = 0;//文件夹对话框的图片索引

    LPITEMIDLIST lpidlBrowse = SHBrowseForFolder(&bi);//弹出选择目录对话框

    if(lpidlBrowse && SHGetPathFromIDList(lpidlBrowse, szFolderPath))
    {
        strFolderPath.Format(_T("%s"), szFolderPath);
		SetDlgItemText(IDC_EFOLDER,strFolderPath);
    }
}


void CForceDecodeDlg::OnBnClickedBkey()
{
	// TODO: 在此添加控件通知处理程序代码
	CString szPath = _T("");
	CString strPath = _T("");

    CFileDialog dlgFile(TRUE, NULL, NULL, OFN_HIDEREADONLY, _T("密匙数据文件(*.dat)|*.dat|所有文件(*.*)|*.*||"), NULL);

    if (dlgFile.DoModal())
    {
        szPath = dlgFile.GetPathName();
    }
	if(!szPath.IsEmpty())
	{
		strPath.Format(_T("%s"),szPath);
	    SetDlgItemText(IDC_EKEY,strPath);
	}
}


void CForceDecodeDlg::OnBnClickedBdecode()
{
	// TODO: 在此添加控件通知处理程序代码
	CString cstr_folder;
	CString cstr_key;
	GetDlgItemText(IDC_EFOLDER,cstr_folder);
	GetDlgItemText(IDC_EKEY,cstr_key);
	if(cstr_folder.IsEmpty())
	{
		AfxMessageBox(_T("待解密文件夹路径不能为空"),MB_OK,NULL);
		return;
	}
	if(cstr_key.IsEmpty())
	{
		AfxMessageBox(_T("所需密匙文件路径不能为空"),MB_OK,NULL);
		return;
	}
	if(!PathFileExists(cstr_folder))//判断待解密文件夹路径是否存在
	{
		AfxMessageBox(_T("待解密文件夹路径不存在"),MB_OK,NULL);
		return;
	}
	if(!PathFileExists(cstr_key))//判断所需密匙文件是否存在
	{
		AfxMessageBox(_T("所需密匙文件不存在"),MB_OK,NULL);
		return;
	}
	int result_load=rsa1024_privatekey_loadfromfile(MyCStringToConstChar(cstr_key),pkey);
	if(result_load==-1)
	{
		AfxMessageBox(_T("所需密匙文件打开失败"),MB_OK,NULL);
		return;
	}
	else if(result_load==-2)
	{
		AfxMessageBox(_T("所需密匙文件数据格式错误，可能不是标准的密匙数据文件"),MB_OK,NULL);
		return;
	}
	else//导入成功(result_load==1)
	{
		CEdit *edit = (CEdit*)GetDlgItem(IDC_BDECODE);
	    edit->EnableWindow(FALSE);
		SetDlgItemText(IDC_BDECODE,_T("正在解密中"));
		int filenumber=-1;
		//while(filenumber!=0)
	    {
		    if(PathFileExists(cstr_folder))//判断待解密文件夹路径是否存在
	        {
		        SetCurrentDirectory(cstr_folder);//设置当前目录
		        filenumber=FindFile(cstr_folder);
	        }
			while(threadnum!=0);//等待所有线程结束
	    }
		threadstart=false;
		edit = (CEdit*)GetDlgItem(IDC_BDECODE);
		SetDlgItemText(IDC_BDECODE,_T("解密"));
	    edit->EnableWindow(TRUE);
		AfxMessageBox(_T("所有该文件夹下的文件已经全部解密完成"),MB_OK,NULL);
		return;
	}
}


void CForceDecodeDlg::OnBnClickedBexit()
{
	// TODO: 在此添加控件通知处理程序代码
	exit(0);
}


int CForceDecodeDlg::FindFile(CString Curdir)
{
	int filenumber=0;
	CFileFind  finder;
    BOOL bWorking = finder.FindFile(_T("*.*"));
    while(bWorking)
    {
		bWorking = finder.FindNextFile();
        if(finder.IsDirectory()&&!finder.IsDots())//文件夹
		{
			
			LPWSTR oldDir=new WCHAR[512];//保存原始的当前路径
			GetCurrentDirectory(512,oldDir);//获取当前路径
			SetCurrentDirectory(finder.GetFilePath());
			FindFile(finder.GetFilePath());//继续遍历子文件夹
			SetCurrentDirectory(oldDir);//恢复当前目录
			delete oldDir;
		}
        else if(!finder.IsDirectory())//文件
		{
			CString FileName=finder.GetFileName();
			int Where=FileName.ReverseFind('//');
            if(Where==-1)
            {
                Where=FileName.ReverseFind('/');
            }
            CString FileTitle=FileName.Right(FileName.GetLength()-1-Where);
            int Which=FileTitle.ReverseFind('.');
            CString ExtendName=FileTitle.Right(FileTitle.GetLength()-Which-1);
			if(ExtendName=="rsa1024")
			{
				filenumber++;
				CString FileName=finder.GetFilePath();
			    char charfilename[512];
			    strcpy_s(charfilename,512,MyCStringToConstChar(FileName));
			    HANDLE thread = ATL::Win32ThreadTraits::CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)proc,charfilename,0,NULL);//启动多线程
				if(thread)
				{
					CloseHandle(thread);
				}
			}
		}
    }
	finder.Close();
	return filenumber;
}

UINT proc(LPVOID pParam)
{
	threadstart=true;
	threadnum++;
	char filename_in[512];
	char filename_out[512];
	strcpy_s(filename_in,512,(const char*)pParam);
	strncpy_s(filename_out,512,filename_in,strlen(filename_in)-8);
	CString cstr(filename_in);
	OutputDebugString(cstr);
	OutputDebugString(_T("\nhello\n"));
	int result_decode=rsa1024_file_decode(filename_in, filename_out, pkey);
	for(int i=0;i<10&&result_decode!=1;i++)//如果解密失败，则再尝试10次
	{
		result_decode=rsa1024_file_decode(filename_in, filename_out, pkey);
	}
	if(result_decode!=1)//如果仍然解密失败，则放弃
	{
		threadnum--;
		return 1;
	}
	DeleteFile(MyCharToLPCTSTR(filename_in));
	threadnum--;
	return NULL;
}

