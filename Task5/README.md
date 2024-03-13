# Task 5

```Viết WU bài FlagChecker.exe```

# Flag Checker

Run thử file, chương trình yêu cầu nhập flag, sai thì trả về message box có chữ Incorrect!

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/1.png)

Mở file bằng die, có thể thấy file này đã bị pack bằng UPX

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/2.png)

Lên trang chủ của [UPX](https://upx.github.io/) để tải tool về rồi thực hiện Unpack, sau đó ném file vừa được Unpack xong vào IDA và debug thử. Chương trình hiện lên MessageBox với nội dung như dưới đây

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/3.png)

Có vẻ file trên được compile bằng ``AutoIt``. Có thể tham khảo thêm thông tin về ``AutoIt`` ở [đây](https://github.com/V1V1/OffensiveAutoIt?tab=readme-ov-file). Sử dụng tool [này](https://github.com/nazywam/AutoIt-Ripper) để decompile file trên, mình thu được 1 Script AutoIt rất dài. Tuy nhiên ta chỉ cần chú ý đến đoạn Script dưới đây

```AutoIt
Func CHECKER ( )
	Local $INPUT = GUICtrlRead ( $IFLAG )
	Local $LEN_INPUT = StringLen ( $INPUT )
	Local $OPCODE = "0x558bec83ec6c8d45d850e8aa05000083c4048d4d94518d55d8" & "52e8cb03000083c408e80c0000007573657233322e646c6c00" & "00ff55d88945f8837df8007505e9fb000000e80c0000004d65" & "7373616765426f7841008b45f850e8b306000083c4088945f0" & "8b4d0851ff55e883f81c740b8b550cc60200e9c4000000c645" & "bcf8c645bd50c645beccc645bfefc645c0e6c645c13cc645c2" & "35c645c396c645c41dc645c561c645c6aec645c7c0c645c8c5" & "c645c931c645cacec645cbb0c645cce7c645cd1dc645ceedc6" & "45cfbcc645d05dc645d181c645d269c645d38ac645d435c645" & "d574c645d657c645d7b68b4508508d4d94518d55d852e84700" & "000083c40c8945f4c745fc00000000eb098b45fc83c0018945" & "fc837dfc1c7d1f8b4df4034dfc0fb6118b45fc0fb64c05bc3b" & "d174088b550cc60200eb08ebd28b450cc600018be55dc3558b" & "ec83ec445657b90b000000e82c00000068747470733a2f2f77" & "77772e796f75747562652e636f6d2f77617463683f763d6451" & "773477395767586351005e8d7dbcf3a5c745f800000000c745" & "f400000000c745fc000000008b4510508b4d088b5110ffd289" & "45ec6a006a016a006a008d45f8508b4d0c8b11ffd285c07507" & "33c0e91b0200008d45f4506a006a0068048000008b4df8518b" & "550c8b420cffd085c075156a008b4df8518b550c8b4224ffd0" & "33c0e9e9010000837df40075156a008b4df8518b550c8b4224" & "ffd033c0e9ce0100006a008d4dbc518b55088b4210ffd0508d" & "4dbc518b55f4528b450c8b4808ffd185c075218b55f4528b45" & "0c8b481cffd16a008b55f8528b450c8b4824ffd133c0e98a01" & "00008d55fc526a008b45f45068016800008b4df8518b550c8b" & "4214ffd085c075218b4df4518b550c8b421cffd06a008b4df8" & "518b550c8b4224ffd033c0e94a0100008b4df4518b550c8b42" & "1cffd06a008d4dec516a006a006a016a008b55fc528b450c8b" & "4810ffd185c07527837dfc0074218b55fc528b450c8b4820ff" & "d16a008b55f8528b450c8b4824ffd133c0e9f90000006a0468" & "001000008b55ec83c201526a008b45088b4808ffd18945e883" & "7de8007527837dfc0074218b55fc528b450c8b4820ffd16a00" & "8b55f8528b450c8b4824ffd133c0e9b10000008b55ec83c201" & "528b45e850e8cc06000083c408c745f000000000eb098b4df0" & "83c101894df08b55f03b55ec73128b45e80345f08b4d10034d" & "f08a118810ebdd8b4510508b4d088b5110ffd2508d45ec508b" & "4de8516a006a016a008b55fc528b450c8b4810ffd185c07524" & "837dfc00741e8b55fc528b450c8b4820ffd16a008b55f8528b" & "450c8b4824ffd133c0eb23837dfc00741a8b55fc528b450c8b" & "4820ffd16a008b55f8528b450c8b4824ffd18b45e85f5e8be5" & "5dc3558bec51e81000000061647661706933322e646c6c0000" & "00008b45088b08ffd18945fc837dfc00750732c0e99b010000" & "e818000000437279707441637175697265436f6e7465787441" & "000000008b55fc52e8d102000083c4088b4d0c8901e8100000" & "00437279707443726561746548617368008b55fc52e8ab0200" & "0083c4088b4d0c89410ce8100000004372797074496d706f72" & "744b657900008b55fc52e88402000083c4088b4d0c894104e8" & "1000000043727970744465726976654b657900008b55fc52e8" & "5d02000083c4088b4d0c894114e81000000043727970744861" & "7368446174610000008b55fc52e83602000083c4088b4d0c89" & "4108e8100000004372797074456e6372797074000000008b55" & "fc52e80f02000083c4088b4d0c894110e81400000043727970" & "7447657448617368506172616d0000008b55fc52e8e4010000" & "83c4088b4d0c894118e814000000437279707444657374726f" & "7948617368000000008b55fc52e8b901000083c4088b4d0c89" & "411ce810000000437279707444657374726f794b6579008b55" & "fc52e89201000083c4088b4d0c894120e81400000043727970" & "7452656c65617365436f6e74657874008b55fc52e867010000" & "83c4088b4d0c894124b0018be55dc3558bec83ec18e81c0000" & "006b00650072006e0065006c00330032002e0064006c006c00" & "00000000e88602000083c4048945fc837dfc00750732c0e915" & "010000e8100000004c6f61644c69627261727941000000008b" & "45fc50e8fb00000083c4088945f8837df800750732c0e9e400" & "0000e81000000047657450726f634164647265737300008b4d" & "fc51e8ca00000083c4088945f4837df400750732c0e9b30000" & "00e8100000005669727475616c416c6c6f63000000008b55fc" & "52e89900000083c4088945f0837df000750732c0e982000000" & "e80c0000005669727475616c46726565008b45fc50e86c0000" & "0083c4088945ec837dec00750432c0eb58e80c0000006c7374" & "726c656e41000000008b4dfc51e84200000083c4088945e883" & "7de800750432c0eb2e8b55088b45f889028b4d088b55f48951" & "048b45088b4df08948088b55088b45ec89420c8b4d088b55e8" & "895110b0018be55dc3558bec83ec3c8b45088945ec8b4dec0f" & "b71181fa4d5a0000740733c0e9350100008b45ec8b4d080348" & "3c894de4ba080000006bc2008b4de48d5401788955e88b45e8" & "833800750733c0e9080100008b4de88b118955e08b45e00345" & "088945f48b4df48b51188955dc8b45f48b481c894dd08b55f4" & "8b42208945d88b4df48b51248955d4c745f800000000eb098b" & "45f883c0018945f88b4df83b4ddc0f83b30000008b55080355" & "d88b45f88d0c82894dc88b55080355d48b45f88d0c42894dcc" & "8b55080355d08b45cc0fb7088d148a8955c48b45c88b4d0803" & "08894df0c745fc00000000c745fc00000000eb098b55fc83c2" & "018955fc8b450c0345fc0fbe0885c974278b55f00355fc0fbe" & "0285c0741a8b4d0c034dfc0fbe118b45f00345fc0fbe083bd1" & "7402eb02ebc38b550c0355fc0fbe0285c075198b4df0034dfc" & "0fbe1185d2750c8b45c48b4d0803088bc1eb07e938ffffff33" & "c08be55dc3558bec83ec34c745e40000000064a13000000089" & "45e48b4de48b510c8955d88b45d88b480c8b5010894dcc8955" & "d08b45cc8945d48b4dd4894de8837de8000f845a0100008b55" & "e8837a18000f844d0100008b45e8837830007502ebde8b4de8" & "8b51308955ecc745f000000000c745f000000000eb098b45f0" & "83c0018945f08b4df08b55080fb7044a85c00f84dd0000008b" & "4df08b55ec0fb7044a85c00f84cb0000008b4df08b55080fb7" & "044a83f85a7f378b4df08b55080fb7044a83f8417c288b4df0" & "8b55080fb7044a83c0208945e08b4df08b5508668b45e06689" & "044a668b4de066894dfeeb0e8b55f08b4508668b0c5066894d" & "fe668b55fe668955f88b45f08b4dec0fb7144183fa5a7f378b" & "45f08b4dec0fb7144183fa417c288b45f08b4dec0fb7144183" & "c2208955dc8b45f08b4dec668b55dc66891441668b45dc6689" & "45fceb0e8b4df08b55ec668b044a668945fc668b4dfc66894d" & "f40fb755f80fb745f43bd07402eb05e908ffffff8b4df08b55" & "080fb7044a85c075168b4df08b55ec0fb7044a85c075088b4d" & "e88b4118eb0f8b55e88b028945e8e99cfeffff33c08be55dc3" & "558bec518b45088945fc837d0c00741a8b4dfcc601008b55fc" & "83c2018955fc8b450c83e80189450cebe08b45088be55dc300" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000000000" & "00000000000000000000000000000000000000000000"
	Local $OPCODE_BUF = DllStructCreate ( "byte[" & BinaryLen ( $OPCODE ) & "]" )
	DllStructSetData ( $OPCODE_BUF , 1 , Binary ( $OPCODE ) )
	Local $INPUT_BUF = DllStructCreate ( "byte[" & BinaryLen ( $INPUT ) + 1 & "]" )
	DllStructSetData ( $INPUT_BUF , 1 , Binary ( $INPUT ) )
	Local $IS_FLAG = DllStructCreate ( "byte[1]" )
	DllStructSetData ( $IS_FLAG , 1 , Binary ( "0x00" ) )
	DllCall ( "user32.dll" , "none" , "CallWindowProcA" , "ptr" , DllStructGetPtr ( $OPCODE_BUF ) , "ptr" , DllStructGetPtr ( $INPUT_BUF ) , "ptr" , DllStructGetPtr ( $IS_FLAG ) , "int" , 0 , "int" , 0 )
	If DllStructGetData ( $IS_FLAG , 1 ) == "0x01" Then
		MsgBox ( 0 , "" , "Correct!" )
	Else
		MsgBox ( $MB_ICONERROR , "" , "Incorrect!" )
	EndIf
EndFunc
```

Đọc kĩ có thể thấy chương trình sử dụng một đoạn Opcode dài ngoằng trên kia để tiến hành Check Flag. Và chương trình sử dụng hàm ``CallWindowProcA`` trong ``user32.dll`` để thực thi đoạn Opcode trên.

Để phân tích Opcode dễ dàng hơn thì ta cần đặt Breakpoint bên trong hàm CallWindowProcA rồi tìm Opcode, sau đó sử dụng các chức năng Make Code và Make Function để phân tích Opcode dễ dàng hơn.

Đầu tiên ta cần đặt một breakpoint ở dưới đây để bypass Antidebug

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/4.png)

Tiến hành debug, sau đó sử dụng chức năng Modify Value hoặc Zero Value để Set cho thanh ghi eax về 0 là ta đã bypass thành công. Tiếp theo sử dụng subview Module để tìm ``user32.dll``, rồi tìm hàm ``CallWindowProcA``

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/5.png)

Đặt 1 breakpoint tại hàm ``CallWindowProcA`` như dưới đây, sau đó F9 đến đó.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/6.png)

Lúc này ta có thể thấy được Opcode ở một trong những tham số truyền vào của hàm. Bây giờ tiến hành phân tích nó

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/52a35140fb16b3b32e107a4600d3a0b3a596c2ee/Task5/Img/7.png)


## Phân tích cách Opcode Resolve API

Sau khi define lại Opcode. Bây giờ mình sẽ tiến hành phân tích nó

Đầu tiên chương trình tiến hành Load Kernel32.dll bằng cách push String "kernel32.dll" lên stack, sau đó gọi hàm ``loadKernel32``

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/8.png)

Đọc qua mã giả hàm ``loadKernel32``, có thể thấy hàm này sử dụng PEB để tìm địa chỉ của Kernel32.dll rồi trả về eax. Tiếp theo chương trình lưu lại địa chỉ của Kernel32.dll vừa tìm được vào stack để sau này sử dụng

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/9.png)

Sau khi Load kernel32.dll, chương trình tiến hành load API LoadLibraryA bằng cách push String "LoadLibraryA" lên stack, sau đó push thêm địa chỉ của Kernel32.dll rồi gọi hàm ``loadAPI`` 

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/10.png)

Đọc qua mã giả hàm ``loadAPI``, có thể thấy hàm này duyệt toàn bộ API trong thư viện được truyền vào và nếu thấy API cần tìm thì sẽ trả địa chỉ của nó ra eax. Sau khi có địa chỉ của hàm LoadLibraryA trong eax thì chương trình lưu lại địa chỉ này trong stack để sau này sử dụng

 ![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/11.png)
 
Tiếp theo chương trình load API GetProcAddress bằng cách thức cách tương tự như trên. Và Sau khi có địa chỉ của hàm GetProcAddress trong eax thì chương trình cũng lưu lại trong stack để sau này sử dụng

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/e1b283c01889148098f7eea2e08760b7589a4e3f/Task5/Img/15.png)

Với việc đã lấy được địa chỉ của LoadLibraryA và GetProcAddress, từ đây việc load dll và load API đều thực hiện theo cách như sau:
- load dll: push String là tên của dll, sau đó gọi hàm LoadLibraryA đã được lưu trước đó trong Stack ra sử dụng. Kết quả trả về là địa chỉ của dll cần tìm, được lưu ở eax. Sau đó chương trình lưu địa chỉ này vào stack để sau này sử dụng. Như trong trường hợp ở ví dụ dưới đây, chương trình đang tìm địa chỉ của ``Advapi32.dll`` rồi sau đó lưu vào Stack.
  
  ![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/12.png)
- load api: push String là tên của API, sau đó push thêm địa chỉ của dll chứa API đó rồi gọi hàm loadAPI. Kêt quả trả về là địa chỉ của API lưu ở eax, sau đó chương trình lưu địa chỉ này vào stack để sau này sử dụng. Như trong trường hợp ở ví dụ dưới đây, chương trình đang tìm địa chỉ của ``CryptAcquireContextA`` rồi sau đó lưu vào Stack.
  
  ![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/13.png)

Việc load các dll và API khác của Opcode cũng sẽ sử dụng cách thức tương tự như trên. Đặt thử một breakpoint ở sau các đoạn chương trình Resolve API, F9 đến rồi theo dõi Stack, ta có thể thấy một loạt API đã được load và lưu vào trong Stack

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/c3123cb09e9a08c1919f2912ff8bca94788ee3dc/Task5/Img/14.png)

## Encrypt Flag

Sau khi đã load hết các API cần thiết, chương trình tiến hành Encrypt Flag. Để thuận tiện cho việc Reverse, mình đã dựng lại 1 cách tương đối bằng C cách thức mà Opcode sử dụng để Encrypt input mình nhập vào từ bàn phím

```C
CryptAcquireContextA(&hProv, 0, 0, 1, 0);
CryptCreateHash(hProv, 0x8004, 0, 0, &hHash); //CALG_SHA
const char *data = "https://www.youtube.com/watch?v=dQw4w9WgXcQ";
DWORD dataSize = strlen(data);
CryptHashData(hHash, (BYTE *)data, dataSize, 0);
CryptDeriveKey(hProv, 0x6801, hHash, 0, &hKey); //CALG_RC4
CryptDestroyHash(hHash);
CryptEncrypt(hKey, 0, 1, 0, 0, &dwCount, 0);  //???????????????????
VirtualAlloc(0, len, MEM_COMMIT, 4);
CryptEncrypt(hKey, 0, 1, 0, buf, &dwCount2, 0);
CryptDestroyKey(hKey);
CryptReleaseContext(hProv, 0);
```

Sau khi Encrypt input xong, chương trình so sánh input bị Encrypt với ``encFlag`` dưới đây.

```C
encFlag = { 0xF8, 0x50, 0xCC, 0xEF, 0xE6, 0x3C, 0x35, 0x96, 0x1D, 0x61, 
  0xAE, 0xC0, 0xC5, 0x31, 0xCE, 0xB0, 0xE7, 0x1D, 0xED, 0xBC, 
  0x5D, 0x81, 0x69, 0x8A, 0x35, 0x74, 0x57, 0xB6};
```

## Reverse

Từ những phân tích ở trên, mình sẽ viết Script để gen ra Flag bằng cách sử dụng ``CryptDecrypt`` trong ``Advapi32.dll``

```C
#include <windows.h>
#include <stdio.h>

BYTE hashValue[32];

void EncFlag()
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;
    if (!CryptAcquireContextA(&hProv, 0, 0, 1, 0))
    {
        return;
    }
    if (!CryptCreateHash(hProv, CALG_SHA, 0, 0, &hHash))
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
    if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hKey))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return;
    }
    CryptDestroyHash(hHash);
    BYTE enc[] = {0xF8, 0x50, 0xCC, 0xEF, 0xE6, 0x3C, 0x35, 0x96, 0x1D, 0x61,
                  0xAE, 0xC0, 0xC5, 0x31, 0xCE, 0xB0, 0xE7, 0x1D, 0xED, 0xBC,
                  0x5D, 0x81, 0x69, 0x8A, 0x35, 0x74, 0x57, 0xB6};
    DWORD dwCount2 = 0x1c;
    if (!CryptDecrypt(hKey, 0, 1, 0, enc, &dwCount2))
    {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return;
    }
    for (DWORD i = 0; i < dwCount2; ++i)
    {
        printf("%c", enc[i]);
    }
    printf("\n");
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
}

int main()
{
    EncFlag();
    return 0;
}
```

Kết quả thu được là chuỗi ``KCSC{rC4_8uT_1T_L00k2_W31Rd}``. Dưới đây là kết quả của chương trình khi chạy lại với input nhập vào là chuỗi trên

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ddf533c66609a9d8cdafef4dbcb00f527ebfff42/Task5/Img/16.png)

# Flag

``KCSC{rC4_8uT_1T_L00k2_W31Rd}``

