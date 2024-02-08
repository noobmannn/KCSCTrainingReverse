# Task 3

```
Task: antidebug
Yêu cầu: viết wu
```

## antidebug_3.exe

Mở file bằng die, đây là 1 file PE32

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/1.png)

Load vào ida32 và bắt đầu từ hàm main

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/2.png)

Nhìn qua hàm main ta thấy có hàm [SetUnhandledExeptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter). Hàm này thường được dùng để xử lý ngoại lệ. Trong main hàm này có tham số truyền vào là địa chỉ của hàm ```TopLevelExceptionFilter```. Điều đó có nghĩa là nếu như có lỗi xảy ra, chương trình sẽ chạy vào hàm  ```TopLevelExceptionFilter```. 

Nhìn vào đoạn code asm ở dưới có thể dễ dàng thấy giá trị của biến ```[ebp+var_4]``` chắc chắn bằng 0, việc thực hiện lệnh idiv ở đây chắc chắn sẽ gây ra lỗi. Có thể thấy đây chính là ý đồ của tác giả để điều hướng luồng chương trình vào hàm ```TopLevelExceptionFilter```.

Hàm ```SetUnhandledExeptionFilter``` có đặc điểm là nếu có lỗi nào thì chương trình sẽ gọi một trình gỡ lỗi để xử lý, nhưng nếu đang chạy trong debug, thì trình gỡ lỗi sẽ không được gọi. Khi mình thử debug đến đoạn này, chương trình chỉ raise ra thông báo lỗi, kể cả có cố gắng bỏ qua lỗi đó cũng không được. Đây là cách mà tác giả sử dụng hàm ```SetUnhandledExeptionFilter``` để anti-debug. Lúc này để có thể chạy vào hàm ```TopLevelExceptionFilter``` như đúng luồng của chương trình, ta chỉ còn cách là sửa lại giá trị thanh ghi EIP (Extended Instruction Pointer) trở thành địa chỉ của hàm  ```TopLevelExceptionFilter```.

Ta vào thẳng hàm ```TopLevelExceptionFilter```. Có thể thấy một dãy byte lạ mà ida không chuyển đổi thành code được

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/3.png)

Có vẻ chương trình đã nhét thêm byte vào để ida không detect được. Mình sẽ Undefine Code bắt đầu từ lệnh ```call    near ptr 1385A99h``` (nơi ida báo đỏ lỗi). Ở đây mình nhận thấy hai lệnh nhảy ở trên đã trỏ đến đúng địa chỉ. Byte được thêm vào là ```E8```.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/4.png)

Ấn C để Make Code từ đoạn ```unk_4014CE```. Sau khi Make Code đoạn dưới có một byte không detect được ```88```, để xử lý ta chỉ cần Undifine lệnh or ở dưới rồi Make Code lại từ ```88``` là được. Sau đó ta patch byte ```E8``` -> ```90``` (lệnh nop) rồi ấn P để Make Function lại là code sẽ dễ đọc hơn nhiều.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/5.png)

Bây giờ đọc kĩ hàm ```TopLevelExceptionFilter```, đầu tiên lệnh ```mov     eax, large fs:30h``` sẽ lấy địa chỉ của PEB trong [TIB](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) (Thread Information Block). Có thể thấy chương trình đang sử dụng ```BeingDebugged``` trong cấu trúc [PEB](https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html). Nếu chương trình không bị debug, giá trị của trường này là 0. Khi đó giá trị của biến ```byte_D74082``` là ```0xAB```. Mình đổi tên biến này thành ```isAB```

Còn giá trị của ```byte_D74083``` phụ thuộc vào biến ```v4```. Đọc qua code có vẻ giống như chương trình đang check [NtGlobalFlag](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-ntglobalflag) (```and     eax, 70h```), tuy nhiên nếu đúng là check NtGlobalFlag thì đoạn trên phải add thanh ghi ecx với 0x68. Vì thế đoạn này đơn giản chỉ là tính toán bình thường và sau khi kết thúc đoạn trên thì ```v4``` bằng 0. Khi đó giá trị biến ```byte_D74083``` là ```0xCD```. Mình đổi tên biến này thành ```isCD```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/6.png)

Sau khi thiết lập hai biến ```isAB``` và ```isCD```, chương trình yêu cầu nhập flag rồi copy sang một biến khác, sau đó gọi hàm ```sub_D71400```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/7.png)

Ở đây có một đoạn gọi đến ```loc_D71330```, mình xem qua thì có vẻ đây là một hàm mà ida không detect được, mình Undefine từ ```0x00D71340``` sau đó Make Code từ ```0x00D71343``` (bỏ qua hai lệnh nhảy lỗi). Patch lại 3 byte bị thêm vào thành các lệnh nop rồi Make Function lại là được. Lúc này đoạn code trên sẽ trở thành hàm ```sub_D71330```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/8.png)

Quay lại hàm ```sub_D71400```, hàm này đang check xem ta có đang đặt breakpoint trong hàm ```sub_D71330``` hay không? Nếu có, giá trị tại vị trí đó là 0xCC([int 3](https://anti-debug.checkpoint.com/techniques/assembly.html#int3)), khi ấy xor với 0x55 là 0x99, i sẽ được tăng lên, và làm thay đổi giá trị trả về. Nếu không có breakpoint nào trong hàm trên thì ```sub_D71400``` sẽ trả về ```0xbeef```. Mình sửa tên biến để lưu giá trị trả về của hàm trên thành ```isBEEF```

Sau khi check 0xcc xong, chương trình Xor 17 kí tự đầu (từ 0 đến 16) của flag với 0x1, rồi gọi hàm ```sub_D71460``` với tham số truyền vào là địa chỉ kí tự thứ 18 của flag

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/9.png)

Vào hàm ```sub_D71460```, chương trình gọi đến hàm ```sub_D71330``` với tham số truyền vào tương tự

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/10.png)

Hàm này cơ bản là xor kí tự 18 đến 25 của flag với 0xAB, sau đó biến đổi các kí tự từ 27 đến 38 của Flag, kết thúc quá trình trên ```a1``` trỏ đến kí tự thứ 40 của flag

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ab56d6302a2359c63bf89911fa25dad59fa7a900/Task3/Img/11.png)

Sau đó chương quay lại hàm ```sub_D71460```, ở đây sẽ biến đổi các kí tự từ 40 đến 57 của flag bằng cách xor hai kí tự liên tiếp với biến ```isBEEF```, cuối cùng gọi hàm ```sub_D711D0``` với giá trị truyền vào là kí tự thứ 59 của flag

Ở hàm này chúng ta có hai nơi Antidebug mình cần phải xử lý, là [int 2d](https://anti-debug.checkpoint.com/techniques/assembly.html#int2d) và [int 3](https://anti-debug.checkpoint.com/techniques/assembly.html#int3) (được mình đánh breakpoint)

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/12.png)

Đầu tiên là về int2d, về cơ bản thì cơ chế hoạt động khá giống với SetUnhandledExeptionFilter ở trên: nếu như ở lệnh ```ms_exc.registration.TryLevel``` gặp ngoại lệ, chương trình sẽ điều hướng vào block chứa lệnh ```ms_exc.old_esp```, tuy nhiên nếu dubug thì trình gỡ lỗi không được gọi và không thể xử lý, nếu cố gắng bỏ qua thì sẽ đi vào luồng sai. Ở hình trên mình đã đánh dấu những block có màu xanh là luồng đúng, còn block có màu vàng là luồng sai. Đoạn này là đoạn biến đổi các kí tự của flag từ 59 đến 63, cụ thể cách biến đổi thì như dưới đây

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/13.png)

Đoạn int3 ở dưới cũng tương tự: nếu ở lệnh ```ms_exc.registration.TryLevel``` gặp ngoại lệ, chương trình sẽ điều hướng thẳng vào ```loc_D712E1```, còn nếu debug và bỏ qua lỗi, chương trình sẽ thực hiện lệnh ```xor edx, 0EFC00CFEh``` ở dưới sau đó chạy thẳng đến ```loc_D712FD```. Về cơ bản đoạn này biến đổi các kí tự từ 65 đến 68 bằng cách xor chúng với ```0xC0FE1337```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/14.png)

Đây là mã giả của hàm, nó chỉ gồm các block màu vàng, nếu theo luồng này chúng ta sẽ sai hoàn toàn

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/15.png)

Sau khi mã hoá xong, chương trình gọi ```sub_D71190``` và truyền vào kí tự thứ 70 của flag. Hàm này biến đổi các kí tự của flag từ 70 đến 99 bằng cách xor kí tự hiện tại với kí tự đứng trước nó

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/16.png)

Cuối cùng chương trình gọi hàm ```sub_D71100``` để check Flag sau khi bị encrypt với ```byte_D74118```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/17.png)

Dưới đây là giá trị của ```byte_D74118```

```
0x74, 0x6F, 0x69, 0x35, 0x4F, 0x65, 0x6D, 0x32, 0x32, 0x79,
0x42, 0x32, 0x71, 0x55, 0x68, 0x31, 0x6F, 0x5F, 0xDB, 0xCE,
0xC9, 0xEF, 0xCE, 0xC9, 0xFE, 0x92, 0x5F, 0x10, 0x27, 0xBC,
0x09, 0x0E, 0x17, 0xBA, 0x4D, 0x18, 0x0F, 0xBE, 0xAB, 0x5F,
0x9C, 0x8E, 0xA9, 0x89, 0x98, 0x8A, 0x9D, 0x8D, 0xD7, 0xCC,
0xDC, 0x8A, 0xA4, 0xCE, 0xDF, 0x8F, 0x81, 0x89, 0x5F, 0x69,
0x37, 0x1D, 0x46, 0x46, 0x5F, 0x5E, 0x7D, 0x8A, 0xF3, 0x5F,
0x59, 0x01, 0x57, 0x67, 0x06, 0x41, 0x78, 0x01, 0x65, 0x2D,
0x7B, 0x0E, 0x57, 0x03, 0x68, 0x5D, 0x07, 0x69, 0x23, 0x55,
0x37, 0x60, 0x14, 0x7E, 0x1D, 0x2F, 0x62, 0x5F, 0x62, 0x5F
```

Có thể thấy những kí tự bị bỏ qua là ```0x5F``` (kí tự ```_```). Vậy thì mình sẽ viết script để reverse lại những phần ở trên để lấy flag

```python
enc = [0x74, 0x6F, 0x69, 0x35, 0x4F, 0x65, 0x6D, 0x32, 0x32, 0x79,
       0x42, 0x32, 0x71, 0x55, 0x68, 0x31, 0x6F, 0x5F, 0xDB, 0xCE,
       0xC9, 0xEF, 0xCE, 0xC9, 0xFE, 0x92, 0x5F, 0x10, 0x27, 0xBC,
       0x09, 0x0E, 0x17, 0xBA, 0x4D, 0x18, 0x0F, 0xBE, 0xAB, 0x5F,
       0x9C, 0x8E, 0xA9, 0x89, 0x98, 0x8A, 0x9D, 0x8D, 0xD7, 0xCC,
       0xDC, 0x8A, 0xA4, 0xCE, 0xDF, 0x8F, 0x81, 0x89, 0x5F, 0x69,
       0x37, 0x1D, 0x46, 0x46, 0x5F, 0x5E, 0x7D, 0x8A, 0xF3, 0x5F,
       0x59, 0x01, 0x57, 0x67, 0x06, 0x41, 0x78, 0x01, 0x65, 0x2D,
       0x7B, 0x0E, 0x57, 0x03, 0x68, 0x5D, 0x07, 0x69, 0x23, 0x55,
       0x37, 0x60, 0x14, 0x7E, 0x1D, 0x2F, 0x62, 0x5F, 0x62, 0x5F]

flag = []

for i in range(17):
    flag.append(enc[i] ^ 0x1)

flag.append(enc[17])

for i in range(18, 26):
    flag.append(enc[i] ^ 0xab)

flag.append(enc[26])

for i in range(27, 39):
    flag.append(((((i - 27) + 0xcd) ^ enc[i]) | 1) // 2)

flag.append(enc[39])

for i in range(40, 58, 2):
    flag.append(enc[i] ^ 0xef)
    flag.append(enc[i + 1] ^ 0xbe)

flag.append(enc[58])

for i in range(59, 64):
    flag.append(((enc[i] << (i - 59)) & 0xff) |
                ((enc[i] >> (8 - (i - 59))) & 0xff))

flag.append(enc[64])

flag.append(enc[65] ^ 0x37)
flag.append(enc[66] ^ 0x13)
flag.append(enc[67] ^ 0xfe)
flag.append(enc[68] ^ 0xc0)

flag.append(enc[69])

for i in range(70, 100):
    if i == 70:
        flag.append(enc[i])
    else:
        flag.append(enc[i] ^ enc[i - 1])

for c in flag:
    print(chr(c), end='')
print()
```

Kết quả thu được của script trên là chuỗi ```unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===```, run file với input là chuỗi trên, ta lấy được flag của bài

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/59d2f1005da014142586471d94c3146fb177f1d0/Task3/Img/18.png)

# Flag

```kcsc{unh4Ndl33xC3pTi0n_pebDebU9_nt9lob4Lfl49_s0F7w4r38r34Kp01n7_int2d_int3_YXV0aG9ydHVuYTk5ZnJvbWtjc2M===}```
