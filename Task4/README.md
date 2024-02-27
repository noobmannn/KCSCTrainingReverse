# Task 4

```
Task: VEH.exe
Yêu cầu: viết wu
```

# VEH.exe

Mở file bằng die, đây là 1 file PE64

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/89aaa551fcd11c7185be6fb9ebb640d8bc189a54/Task4/Img/1.png)

Chạy thử thì chương trình yêu cầu ta nhập vào Flag, sai thì trả về ```[+] Wrong!```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/41faaa7950f696b020e2f5d4511c31dab4ba4e02/Task4/Img/2.png)

Mở file bằng IDA64, chương trình dường như bị Undefine ở khá nhiều đoạn. Sau khi Make Code lại và thử debug, chương trình gặp Exception ở rất nhiều nơi, lý do là bởi gặp nhiều cấu trúc như trong hình dưới đây: Thanh ghi rax đã bị làm sạch trước khi gặp lệnh div dẫn đến gặp lỗi phép chia cho 0

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/68900ebd65da085761684b312622d547a8fa5898/Task4/Img/3.png)

Để ý kĩ ta thấy chương trình chạy hàm ```init``` trước cả hàm main

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/bbcf3b8c876d714ee97fb405167b370b9498d560/Task4/Img/4.png)

Vào hàm ```AllNameDlls```, đầu tiên chương trình gọi tới hàm ```resolveapi``` với hai tham số truyền vào như hình dưới

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/091ff413355fc90823fdaa99f501eb57e1638bf4/Task4/Img/5.png)

### Resolve API in PEB by Hash

Xem thử hàm ```resolveapi```, có vẻ đây là nơi Resolve các API để chương trình sử dụng

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/008f122d86f43d67c0b053d1f7d33237b4e3f03b/Task4/Img/6.png)

Hàm ```resolveapi``` có hai tham số truyền vào lần lượt là:
- Tham số thứ nhất: FNV1A32 hash của tên API, ví dụ ```0x41B1EAB9``` là hash của ```LoadLibraryW```
- Tham số thứ hai: FNV1A32 hash của tên DLL chứa API trên tham số thứ nhất, ví dụ ```0x29CDD463``` là hash của ```KERNEL32.DLL```

Hàm này lấy địa chỉ của ```InMemoryOrderModuleList``` bằng cách sử dụng cấu trúc [PEB](https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html), sau đó thực hiện hai việc:
- Tìm địa chỉ DLL: Hash tất cả tên của tất cả các DLL có trong InMemoryOrderModuleList bằng thuật toán hash [FNV1A32](https://gist.github.com/ruby0x1/81308642d0325fd386237cfa3b44785c), sau đó so sánh với giá trị tham số thứ hai
- Tìm địa chỉ API: Sau khi tìm được địa chỉ DLL, tiến hành Hash tất cả tên của tất cả các API có trong DLL vừa tìm được ở trên, sau đó so sánh với giá trị tham số thứ nhất

Có thể tham khảo các giá trị hash của các API trong Kernel32.dll và ntdll.dll ở [đây](https://gist.github.com/Sinclairq/8d746cdbff92cdb21a057742cee36e5e#file-export_list-md)

Dưới đây là đoạn code FNV1A32 dùng để hash tên các DLL, việc hash tên các API trong DLL cũng dùng cấu trúc tương tự

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/d16cb94c6e598ad73d638fe576f299c07e783e81/Task4/Img/7.png)

Kết quả trả về của hàm là địa chỉ của API cần tìm, được lưu ở RAX

### Load Library

Quay trở lại hàm ```AllNameDlls```, sau khi thực hiện ```resolveapi```, kết quả rax là địa chỉ của hàm ```LoadLibraryW```, sau đó hàm này chỉ tính các String là tên các dll và sau đó đẩy nó làm tham số để gọi ```LoadLibraryW```. Mục đích của việc này là load các thư viện trên vào chương trình để sử dụng cho các API sau này. Các dll được load vào là: ```NTDLL.dll```, ```USER32.dll```, ```CRYPT32.dll```, ```Advapi32.dll```. Dưới đây là đoạn tính ra String ```USER32.dll``` và dùng String đó làm tham số để gọi hàm ```LoadLibraryW``` để load ```USER32.dll```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/89895078df218b69b6f227596b415f721ffc09cb/Task4/Img/8.png)

### VEH

Quay lại hàm ```init```, sau khi load các dll, chương trình gọi ```resolveapi``` để lấy địa chỉ của ```RtlAddVectoredExceptionHandler```, sau đó truyền hai tham số gồm địa chỉ của hàm ```VEHHandler``` và 1 rồi gọi hàm trên.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/fb2212d8ca567d1c372c69e26ddc309c6fe5187f/Task4/Img/17.png)

Mục đích của hàm [RtlAddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler) là để tạo một VEH (Vectored Exception Handler) mới nhằm mục đích để xử lý ngoại lệ. Hiểu đơn giản là kể từ sau khi gọi hàm trên, nếu chương trình gặp Exception, chương trình sẽ xử lý Exception trên bằng cách gọi hàm ```VEHHandler```.

Dưới đây là một đoạn code C đơn giản mô phỏng lại cách VEH hoạt động

```C
#include <windows.h>
#include <stdio.h>

LONG NTAPI MyVEHHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    printf("MyVEHHandler (0x%x)\n", ExceptionInfo->ExceptionRecord->ExceptionCode);
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        printf("Divide by zero at 0x%p\n", ExceptionInfo->ExceptionRecord->ExceptionAddress);
        ExceptionInfo->ContextRecord->Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{
    AddVectoredExceptionHandler(1, MyVEHHandler);
    int except1 = 3;
    except1 /= 0;
    printf("1st Except\n");
    int except2 = 6;
    except2 /= 0;
    printf("2nd Except\n");
    int except3 = 9;
    except3 /= 0;
    printf("3rd Except\n");
    return 0;
}
```

Đây là kết quả khi chạy đoạn code mô phỏng trên, có thể thấy mỗi khi gặp except, chương trình sẽ nhảy vào hàm ```MyVEHHandler```

```
MyVEHHandler (0xc0000094)
Divide by zero at 0x0000000000401603
1st Except
MyVEHHandler (0xc0000094)
Divide by zero at 0x0000000000401624
2nd Except
MyVEHHandler (0xc0000094)
Divide by zero at 0x0000000000401645
3rd Except
```

Quay trở lại bài, phân tích lại hàm ```VEHHandler```, có thể thấy hàm này có vai trò giống như hàm ```MyVEHHandler``` trong ví dụ ở trên

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ee551939a962de87e7139afd0c76fcb7961235ab/Task4/Img/18.png)

Sử dụng Convert to Struct * để đổi kiểu dữ liệu của a1 (tham số của hàm) thành ```_EXCEPTION_POINTERS```, có cấu trúc cụ thể như dưới đây

```
typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
```

Đây là cấu trúc dùng để chứa thông tin về ngoại lệ và trạng thái của chương trình khi đang xảy ra ngoại lệ, với ```ExceptionRecord``` chứa thông tin về ngoại lệ đang xảy ra, còn ```ContextRecord``` chứa trạng thái của chương trình khi đang xảy ra ngoại lệ, trong đó có cả giá trị của các thanh ghi tại thời điểm xảy ra ngoại lệ. Có thể tham khảo kĩ hơn ở [đây](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers), [đây](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context) và [đây](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ee551939a962de87e7139afd0c76fcb7961235ab/Task4/Img/19.png)

Sau khi chuyển đổi struct xong, có thể dễ dàng hiểu được những gì chương trình sẽ thực hiện khi xảy ra ngoại lệ:
- Gọi hàm ```resolveapi``` với hai tham số truyền vào lần lượt là giá trị của hai thanh ghi ```r8``` và ```r9```, kết quả trả về là địa chỉ của API sẽ được lưu vào thanh ghi ```rax```
- Tăng giá trị của thanh ghi RIP thêm 4, tức là câu lệnh tiếp theo sau lệnh ```div rax``` sẽ được thực hiện sau khi hàm kết thúc

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/2e4c91111b58045873a2317b66dce47167991f1d/Task4/Img/20.png)

Ví dụ như đoạn code ở trên đây, sau khi đẩy hai giá trị hash vào r8 và r9, chương trình clear thanh ghi rax sau đó thực hiện div rax, điều này sẽ tạo ra Exception do lỗi chia cho 0, chương trình sẽ xử lý Exception trên bằng cách gọi hàm ```VEHHandler```. Hàm này sẽ lấy hai giá trị của r8 và r9 trên kia làm tham số cho hàm ```resolveapi``` để lấy địa chỉ API. Như ở ví dụ trên hình là địa chỉ của ```GetStdHandle```. Sau đó hàm tăng RIP thêm 4, tức là câu lệnh tiếp theo được thực hiện sẽ là ```mov     rsi, rax```. 

Từ sau đây trở đi, cấu trúc dạng này sẽ được lặp đi lặp lại nhiều lần nhằm mục đích để lấy địa chỉ API cần thiết ra sử dụng. Tuy nhiên khi chúng ta debug, chương trình sẽ raise thông báo lỗi và dừng lại ở đó, và sau đó khi chúng ta bypass, chương trình sẽ không dừng lại ở RIP tiếp theo mà sẽ load một mạch cho đến khi gặp breakpoint, gặp exception hoặc kết thúc chương trình.

Vì vậy để hỗ trợ việc Debug các đoạn code với cấu trúc như trên, mình sẽ sử dụng idapython để mô phỏng lại hai chức năng của hàm ```VEHHandler```

```python
set_reg_value(Appcall.resolveapi(get_reg_value('r8') ,get_reg_value('r9')).value, 'rax')
set_reg_value(get_reg_value('rip') + 4, 'rip')
```

Từ đây mỗi khi trace đến lệnh ```div rax```, vào File->Script Command và Run đoạn script trên, ta lấy được địa chỉ api cần tìm tại rax, và RIP cũng được chỉnh đến lệnh tiếp theo để chúng ta tiếp tục trace

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ac6a97da1fa8f35a810a254b4aa890019c067186/Task4/Img/21.png)

Kết thúc hàm ```init```, chương trình gọi hàm ```GetStdHandle``` vừa được lấy API ở trên kia để tạo các HandleRead và HandleWrite dùng cho đoạn sau.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/f4f517b83aef956bb5aa7e727a1c7559188648c4/Task4/Img/22.png)

### Encrypt Flag

Vào Hàm ```main```, đầu tiên chương trình tính ra String ```Enter flag:```, sau đó chương trình sử dụng HandleWrite được tính trên kia và gọi hàm WriteFile để in chuỗi ```Enter flag:``` ra màn hình, sau đó dùng HandleRead và gọi hàm ReadFile để yêu cầu người dùng nhập vào 1 chuỗi từ bàn phím. Sau đó chương trình gọi đến hàm ```encFlag```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ec4e72ad005d50c0ae682829a5edb0df7c437bc0/Task4/Img/12.png)

Tại hàm ```encFlag``` chương trình tiếp tục gọi hàm ```initEncrypt```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ec4e72ad005d50c0ae682829a5edb0df7c437bc0/Task4/Img/13.png)

Sau khi đọc kĩ và debug qua, mình thấy hàm này nhằm mục đích để tạo 1 hash SHA-256 từ chuối ```https://www.youtube.com/watch?v=dQw4w9WgXcQ``` (link Rick Roll :))))

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/12b6936c727b7a96536034cdcbbc32a7e284cc12/Task4/Img/23.png)

Để thuận tiện cho việc Reverse, mình đã code lại hàm ```initEncrypt``` bằng C nhưng bỏ qua các bước Resolve API bằng VEH và một vài bước nhỏ khác. Các API chính phục vụ cho việc tạo hash được lấy từ ```Advapi32.dll```

```C
void initEncrypt()
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, 0xF0000000))
    {
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return;
    }
    const char *data = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
    DWORD dataSize = strlen(data);
    if (!CryptHashData(hHash, (BYTE *)data, dataSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    DWORD hashSize = sizeof(hashValue);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}
```

Sau đó chương trình quay trở lại hàm ```encFlag```, ở đây chương trình tạo 1 Key dựa trên chuỗi hash link rick roll trên kia, sau đó dùng Key vừa tạo để mã hoá input mình nhập vào bằng thuật toán ```AES-256```. Các API chính để dùng cho việc tạo khoá và mã hoá cũng được lấy từ ```Advapi32.dll```. 

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/12b6936c727b7a96536034cdcbbc32a7e284cc12/Task4/Img/24.png)

Mình cũng code lại hàm trên bằng C nhưng bỏ qua các bước Resolve API bằng VEH và một vài bước nhỏ khác để phục vụ việc Reverse

```C
void encFlag()
{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    if (!CryptAcquireContextA(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
    {
        return;
    }
    typedef struct
    {
        BLOBHEADER hdr;
        DWORD cbKeySize;
        BYTE rgbKeyData[32];
    } KeyBLOB;
    KeyBLOB kb;
    kb.hdr.bType = PLAINTEXTKEYBLOB;
    kb.hdr.bVersion = CUR_BLOB_VERSION;
    kb.hdr.reserved = 0;
    kb.hdr.aiKeyAlg = CALG_AES_256;
    kb.cbKeySize = 0x20;
    CopyMemory(kb.rgbKeyData, hashValue, 0x20);
    if (!CryptImportKey(hProv, (BYTE *)&kb, 0x2C, 0, 0, &hKey))
    {
        CryptReleaseContext(hProv, 0);
        return;
    }
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&mode, 0))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE iv[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE buf[] = "siuuuuuuuuuuu";   //input
    BYTE len = strlen(buf);
    DWORD dwCount = len;
    if (!CryptEncrypt(hKey, 0, 1, 0, buf, &dwCount, 0x400))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}
```

Sau khi Encrypt lại input xong, chương trình so sánh input bị Encrypt với ```encryptFlag``` dưới đây. Nếu đúng thì tính chuỗi ```[+] Correct!``` và in ra màn hình, sai thì in ra ```[+] Wrong!```

```C
BYTE enc[] = {0xE5, 0x60, 0x44, 0x09, 0x42, 0xC4, 0xBB, 0xDE, 0xF6, 0xA1,
                  0x2D, 0x93, 0xD9, 0x1D, 0x13, 0x72, 0xAF, 0x8D, 0x4C, 0xF7,
                  0xA7, 0x9F, 0x1F, 0xB9, 0x99, 0x68, 0x9C, 0xB8, 0xC2, 0x4C,
                  0x4F, 0x85};
```

### Reverse

Từ những phân tích ở trên, mình sẽ viết Script để tính ra Flag bằng cách sử dụng hàm ```CryptDecrypt``` trong thư viện ```Advapi32.dll```.

```C
#include <windows.h>
#include <stdio.h>

BYTE hashValue[32];

void initEncrypt()
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, 0xF0000000))
    {
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return;
    }
    const char *data = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
    DWORD dataSize = strlen(data);
    if (!CryptHashData(hHash, (BYTE *)data, dataSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    DWORD hashSize = sizeof(hashValue);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
}

void encFlag()
{
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    if (!CryptAcquireContextA(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0))
    {
        return;
    }
    typedef struct
    {
        BLOBHEADER hdr;
        DWORD cbKeySize;
        BYTE rgbKeyData[32];
    } KeyBLOB;
    KeyBLOB kb;
    kb.hdr.bType = PLAINTEXTKEYBLOB;
    kb.hdr.bVersion = CUR_BLOB_VERSION;
    kb.hdr.reserved = 0;
    kb.hdr.aiKeyAlg = CALG_AES_256;
    kb.cbKeySize = 0x20;
    CopyMemory(kb.rgbKeyData, hashValue, 0x20);
    if (!CryptImportKey(hProv, (BYTE *)&kb, 0x2C, 0, 0, &hKey))
    {
        CryptReleaseContext(hProv, 0);
        return;
    }
    DWORD mode = CRYPT_MODE_CBC;
    if (!CryptSetKeyParam(hKey, KP_MODE, (BYTE *)&mode, 0))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE iv[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    if (!CryptSetKeyParam(hKey, KP_IV, iv, 0))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE buf[] = "Kanavi";
    BYTE len = strlen(buf);
    DWORD dwCount = len;
    if (!CryptEncrypt(hKey, 0, 1, 0, buf, &dwCount, 0x400))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    BYTE enc[] = {0xE5, 0x60, 0x44, 0x09, 0x42, 0xC4, 0xBB, 0xDE, 0xF6, 0xA1,
                  0x2D, 0x93, 0xD9, 0x1D, 0x13, 0x72, 0xAF, 0x8D, 0x4C, 0xF7,
                  0xA7, 0x9F, 0x1F, 0xB9, 0x99, 0x68, 0x9C, 0xB8, 0xC2, 0x4C,
                  0x4F, 0x85};
    DWORD dwCount2 = 0x20;
    if(!CryptDecrypt(hKey, 0, 1, 0, enc, &dwCount2)){
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    for (DWORD i = 0; i < dwCount2; ++i) {
        printf("%c", enc[i]);
    }
    printf("\n");
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

int main()
{
    initEncrypt();
    encFlag();
    return 0;
}
```

Kết quả thu được từ Script trên là chuỗi ```KMACTF{3Xc3pTI0n_3v3rYwh3R3@_@}```. Đây là kết quả khi chạy lại VEH.exe với chuỗi trên.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/1afe7df19ca3e18cc79cea794315ff9b8781d1d2/Task4/Img/14.jpg)

# Flag

```KMACTF{3Xc3pTI0n_3v3rYwh3R3@_@}```
