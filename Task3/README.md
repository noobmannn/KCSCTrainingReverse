# Task 3

```
Task: antidebug
Yêu cầu: viết wu
```

## antidebug_3.exe

Mở file bằng die, đây là 1 file PE32

![]()

Load vào ida32 và bắt đầu từ hàm main

![]()

Nhìn qua hàm main ta thấy có hàm [SetUnhandledExeptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter). Hàm này thường được dùng để xử lý ngoại lệ. Trong main hàm này có tham số truyền vào là địa chỉ của hàm ```TopLevelExceptionFilter```. Điều đó có nghĩa là nếu như có lỗi xảy ra, chương trình sẽ chạy vào hàm  ```TopLevelExceptionFilter```. 

Nhìn vào đoạn code asm ở dưới có thể dễ dàng thấy giá trị của biến ```[ebp+var_4]``` chắc chắn bằng 0, việc thực hiện lệnh idiv ở đây chắc chắn sẽ gây ra lỗi. Có thể thấy đây chính là ý đồ của tác giả để điều hướng luồn chương trình vào hàm ```TopLevelExceptionFilter```.

Hàm ```SetUnhandledExeptionFilter``` có đặc điểm là nếu có lỗi nào thì chương trình sẽ gọi một trình gỡ lỗi để xử lý, nhưng nếu đang chạy trong debug, thì trình gỡ lỗi sẽ không được gọi. Khi mình thử debug đến đoạn này, chương trình chỉ raise ra thông báo lỗi, kể cả có cố gắng bỏ qua lỗi đó cũng không được. Đây là cách mà tác giả sử dụng hàm ```SetUnhandledExeptionFilter``` để anti-debug. Lúc này để có thể chạy vào hàm ```TopLevelExceptionFilter``` như đúng luồng của chương trình, ta chỉ còn cách là sửa lại giá trị thanh ghi EIP (Extended Instruction Pointer) trở thành địa chỉ của hàm  ```TopLevelExceptionFilter```.

Ta vào thẳng hàm ```TopLevelExceptionFilter```. Có thể thấy một dãy byte lạ mà ida không chuyển đổi thành code được

![]()

Có vẻ chương trình đã nhét thêm byte vào để ida không detect được. Mình sẽ Undefine Code bắt đầu từ lệnh ```call    near ptr 1385A99h``` (nơi ida báo đỏ lỗi). Ở đây mình nhận thấy hai lệnh nhảy ở trên đã trỏ đến đúng địa chỉ. Byte được thêm vào là ```E8```.

![]()

Ấn C để Make Code từ đoạn ```unk_4014CE```. Sau khi Make Code đoạn dưỡi có một byte không detect được ```88```, để xử lý ta chỉ cần Undifine lệnh or ở dưới rồi Make Code lại từ ```88``` là được. Sau đó ta patch byte ```E8``` -> ```90``` (lệnh nop) rồi ấn P để Make Function lại là code sẽ dễ đọc hơn nhiều.

![]()

Bây giờ đọc kĩ hàm ```TopLevelExceptionFilter```, đầu tiên lệnh ```mov     eax, large fs:30h``` sẽ lấy địa chỉ của PEB trong [TIB](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block) (Thread Information Block). Có thể thấy chương trình đang sử dụng ```BeingDebugged``` trong cấu trúc [PEB](https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html). Nếu chương trình không bị debug, giá trị của trường này là 0. Khi đó giá trị của biến ```byte_D74082``` là ```0xAB```. Mình đổi tên biến này thành ```isAB```

byte_D74083 // chưa viết xong

![]()

Sau khi thiết lập hai biến ```isAB``` và ```isCD```, chương trình yêu cầu nhập flag rồi copy sang một biến khác, sau đó gọi hàm ```sub_D71400```

![]()

Ở đây có một đoạn gọi đến ```loc_D71330```, mình xem qua thì có vẻ đây là một hàm mà ida không detect được, mình Undefine từ ```0x00D71340``` sau đó Make Code từ ```0x00D71343``` (bỏ qua hai lệnh nhảy lỗi). Patch lại 3 byte bị thêm vào thành các lệnh nop rồi Make Function lại là được. Lúc này đoạn code trên sẽ trở thành hàm ```sub_D71330```

![]()

Quay lại hàm ```sub_D71400```, hàm này đang check xem ta có đang đặt breakpoint trong hàm ```sub_D71330``` hay không? Nếu có, giá trị tại vị trí đó là 0xCC([int 3](https://anti-debug.checkpoint.com/techniques/assembly.html#int3), khi ấy xor với 0x55 là 0x99, i sẽ được tăng lên, và làm thay đổi giá trị trả về. Nếu không có breakpoint nào trong hàm trên thì ```sub_D71400``` sẽ trả về ```0xbeef```. Mình sửa tên biến để lưu giá trị trả về của hàm trên thành ```isBEEF```

Sau khi check 0xcc xong, chương trình Xor 16 kí tự đầu của flag với 0x1, rồi gọi hàm ```sub_D71460``` với tham số truyền vào là địa chỉ kí tự thứ 18 của flag

![]()

Vào hàm ```sub_D71460```, chương trình gọi đến hàm ```sub_D71330``` với tham số truyền vào tương tự

![]()

Hàm này cơ bản là xor kí tự 18 đến 25 của flag với 0xAB, sau đó biến đổi các kí tự từ 27 đến 38 của Flag, kết thúc quá trình trên ```a1``` trỏ đến kí tự thứ 40 của flag

Sau đó chương quay lại hàm ```sub_D71460```, ở đây sẽ biến đổi các kí tự từ 40 đến 57 của flag bằng cách xor hai kí tự liên tiếp với biến ```isBEEF```, cuối cùng gọi hàm ```sub_D711D0``` với giá trị truyền vào là kí tự thứ 59 của flag

