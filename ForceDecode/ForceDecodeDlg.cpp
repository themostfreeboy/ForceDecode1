
// ForceDecodeDlg.cpp : ʵ���ļ�
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



// CForceDecodeDlg �Ի���




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


// CForceDecodeDlg ��Ϣ�������

BOOL CForceDecodeDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ���ô˶Ի����ͼ�ꡣ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CForceDecodeDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CForceDecodeDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CForceDecodeDlg::OnBnClickedBfolder()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	TCHAR szFolderPath[MAX_PATH] = {0};//���ѡ���Ŀ¼·��
    CString strFolderPath = _T("");

    ZeroMemory(szFolderPath, sizeof(szFolderPath));

    BROWSEINFO bi;
    bi.hwndOwner = m_hWnd;//�����ھ��
    bi.pidlRoot = NULL;//Ҫ��ʾ���ļ�Ŀ¼�Ի���ĸ�(Root)
    bi.pszDisplayName = szFolderPath;//���汻ѡȡ���ļ���·���Ļ�����
    bi.lpszTitle = _T("��ѡ���ļ���");//��ʾλ�ڶԻ������ϲ��ı���
    bi.ulFlags = 0;//ָ���Ի������ۺ͹��ܵı�־
    bi.lpfn = NULL;//�����¼��Ļص�����
    bi.lParam = 0;//Ӧ�ó��򴫸��ص������Ĳ���
    bi.iImage = 0;//�ļ��жԻ����ͼƬ����

    LPITEMIDLIST lpidlBrowse = SHBrowseForFolder(&bi);//����ѡ��Ŀ¼�Ի���

    if(lpidlBrowse && SHGetPathFromIDList(lpidlBrowse, szFolderPath))
    {
        strFolderPath.Format(_T("%s"), szFolderPath);
		SetDlgItemText(IDC_EFOLDER,strFolderPath);
    }
}


void CForceDecodeDlg::OnBnClickedBkey()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString szPath = _T("");
	CString strPath = _T("");

    CFileDialog dlgFile(TRUE, NULL, NULL, OFN_HIDEREADONLY, _T("�ܳ������ļ�(*.dat)|*.dat|�����ļ�(*.*)|*.*||"), NULL);

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
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	CString cstr_folder;
	CString cstr_key;
	GetDlgItemText(IDC_EFOLDER,cstr_folder);
	GetDlgItemText(IDC_EKEY,cstr_key);
	if(cstr_folder.IsEmpty())
	{
		AfxMessageBox(_T("�������ļ���·������Ϊ��"),MB_OK,NULL);
		return;
	}
	if(cstr_key.IsEmpty())
	{
		AfxMessageBox(_T("�����ܳ��ļ�·������Ϊ��"),MB_OK,NULL);
		return;
	}
	if(!PathFileExists(cstr_folder))//�жϴ������ļ���·���Ƿ����
	{
		AfxMessageBox(_T("�������ļ���·��������"),MB_OK,NULL);
		return;
	}
	if(!PathFileExists(cstr_key))//�ж������ܳ��ļ��Ƿ����
	{
		AfxMessageBox(_T("�����ܳ��ļ�������"),MB_OK,NULL);
		return;
	}
	int result_load=rsa1024_privatekey_loadfromfile(MyCStringToConstChar(cstr_key),pkey);
	if(result_load==-1)
	{
		AfxMessageBox(_T("�����ܳ��ļ���ʧ��"),MB_OK,NULL);
		return;
	}
	else if(result_load==-2)
	{
		AfxMessageBox(_T("�����ܳ��ļ����ݸ�ʽ���󣬿��ܲ��Ǳ�׼���ܳ������ļ�"),MB_OK,NULL);
		return;
	}
	else//����ɹ�(result_load==1)
	{
		CEdit *edit = (CEdit*)GetDlgItem(IDC_BDECODE);
	    edit->EnableWindow(FALSE);
		SetDlgItemText(IDC_BDECODE,_T("���ڽ�����"));
		int filenumber=-1;
		//while(filenumber!=0)
	    {
		    if(PathFileExists(cstr_folder))//�жϴ������ļ���·���Ƿ����
	        {
		        SetCurrentDirectory(cstr_folder);//���õ�ǰĿ¼
		        filenumber=FindFile(cstr_folder);
	        }
			while(threadnum!=0);//�ȴ������߳̽���
	    }
		threadstart=false;
		edit = (CEdit*)GetDlgItem(IDC_BDECODE);
		SetDlgItemText(IDC_BDECODE,_T("����"));
	    edit->EnableWindow(TRUE);
		AfxMessageBox(_T("���и��ļ����µ��ļ��Ѿ�ȫ���������"),MB_OK,NULL);
		return;
	}
}


void CForceDecodeDlg::OnBnClickedBexit()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
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
        if(finder.IsDirectory()&&!finder.IsDots())//�ļ���
		{
			
			LPWSTR oldDir=new WCHAR[512];//����ԭʼ�ĵ�ǰ·��
			GetCurrentDirectory(512,oldDir);//��ȡ��ǰ·��
			SetCurrentDirectory(finder.GetFilePath());
			FindFile(finder.GetFilePath());//�����������ļ���
			SetCurrentDirectory(oldDir);//�ָ���ǰĿ¼
			delete oldDir;
		}
        else if(!finder.IsDirectory())//�ļ�
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
			    HANDLE thread = ATL::Win32ThreadTraits::CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)proc,charfilename,0,NULL);//�������߳�
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
	for(int i=0;i<10&&result_decode!=1;i++)//�������ʧ�ܣ����ٳ���10��
	{
		result_decode=rsa1024_file_decode(filename_in, filename_out, pkey);
	}
	if(result_decode!=1)//�����Ȼ����ʧ�ܣ������
	{
		threadnum--;
		return 1;
	}
	DeleteFile(MyCharToLPCTSTR(filename_in));
	threadnum--;
	return NULL;
}

