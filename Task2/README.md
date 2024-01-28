# Task 2

```
Task2: làm bài vmcode.exe
Yêu cầu: viết wu
```

## vmcode.exe

Mở file bằng die, đây là một file PE32

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/d369460dee2e98e2083982848a96a467875c1ad5/Task2/Images/001.png)

Mở bằng IDA32 và xem qua hàm main, chương trình ban đầu khởi tạo các giá trị, sau đó yêu cầu nhập input, sau đó chương trình dùng lệnh ```memset``` để khởi tạo một vùng nhớ cho biến ```this```, tiếp theo là cho biến ```this``` vào hàm ```vm``` để đẩy các giá trị và hàm cần thiết vào đó, sau đó đẩy luôn input vào ```this``` rồi cho vào hàm ```runvm``` để xử lý, xử lý xong thì giải phóng bộ nhớ được cấp phát

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/98d1aac980d89123521b5dda97a3f3df9dfd7b05/Task2/Images/002.png)

Để thuận tiện cho việc đọc code, mình sẽ tạo một struct để đọc biến ```this``` và 1 struct khác để đọc các hàm của VM

Đầu tiên mình tạo 1 Struct để đọc các hàm của VM, Vào View->Open SubView->Local Types (hoặc Shift+F1) sau đó chuột trái chọn Insert. Nhập struct vào rồi ấn OK

```
struct func
{
  DWORD NAME;
  BYTE cipher;
  BYTE step;
  WORD unk1in28;
  DWORD addrFunc;
  BYTE is0x0in60;
  BYTE unkin61;
  WORD unkin62;
};
```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/38375f69b56e91ff0dce06a9603716131ed614af/Task2/Images/003.png)

Làm tương tự như vậy để tạo tiếp một struct khác đọc biến ```this```

```
struct Thiss
{
  DWORD loadInput;
  DWORD this1;
  DWORD loadOperand;
  DWORD this3;
  DWORD step;
  DWORD checker;
  DWORD is0x100in6;
  DWORD maxStep;
  DWORD is0x100in8;
  DWORD is0;
  DWORD vmcode;
  DWORD userinput;
  func function[48];
};
```

Sau khi đã tạo xong hai Struct cần thiết, bây giờ mình sẽ đọc chi tiết hàm ```vm```. Ở tham số ```this``` của hàm, nhấp chuột trái chọn Convert to struct * rồi chọn struct ```Thiss``` vừa tạo ở trên kia, lúc này code đã dễ đọc hơn nhiều.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/2660ca872f836211336d690952345724d30dfe5a/Task2/Images/004.png)

Về hàm ```vm```, đầu tiên hàm này khởi tạo các giá trị đầu tiên của ```this```, sau đó gọi hàm ```sub_9F2C10``` để khởi tạo ```vftable``` (Virtual Function Table), tiếp tục lần lượt đẩy các tham số của mỗi hàm vào ```this``` theo thứ tự: đầu tiên là tên hàm, giá trị ```step```, tiếp đó là địa chỉ hàm và cuối cùng là biến ```is0x0in60```

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/2660ca872f836211336d690952345724d30dfe5a/Task2/Images/005.png)

Sau khi đẩy hết 1 số giá trị của hàm vào ```this```, hàm tiếp tục đẩy ```v8``` là các giá trị được khởi tạo ở đầu hàm ```main``` vào ```this->vmcode```, tiếp đó đặt cho ```this->step``` và ```this->checker``` bằng 0. Cuối cùng là gọi hàm ```sub_9F1590```, hàm này sẽ dựa vào chuỗi được đưa vào ```KMACTF``` để tính giá trị ```cipher``` cho các hàm của VM

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/ae8382c60d3f7d3da9da0c5870f51c6b56a084ed/Task2/Images/006.png)

Sau khi thực hiện xong hàm ```vm```, ở hàm main chương trình đẩy biến ```Src``` là Input vào ```this.userinput```, sau đó thực hiện hàm ```runvm```

Để thuận tiện cho các bước sau, mình sẽ lấy giá trị của ```this``` trước khi thực hiện hàm ```runvm```. Đặt breakpoint tại lệnh gọi ```runvm``` sau đó tiến hành debug, lúc này biến ```this``` sẽ bắt đầu từ địa chỉ ```0x00EFF748``` (tuỳ theo máy). Mình sẽ viết script để lấy giá trị của ```this```

```python
addr = 0x00EFF748
funcs = []

for i in range(12):
    a = addr + i*0x4
    if i != 10:
        funcs.append(get_wide_dword(a))
    else:
        funcs.append(get_wide_dword(get_wide_dword(a)))
addr = addr + 0x30
for i in range(48):
    a = addr + i*0x10
    func = []
    func.append(bytes.fromhex(format(get_wide_dword(
        get_wide_dword(a)), 'x')).decode('utf-8')[::-1])
    func.append(get_wide_byte(a + 4))
    func.append(get_wide_byte(a + 5))
    func.append(get_wide_word(a + 6))
    func.append(get_wide_dword(a + 8))
    func.append(get_wide_byte(a + 0xc))
    func.append(get_wide_byte(a + 0xd))
    func.append(get_wide_word(a + 0xe))
    funcs.append(func)

print(funcs)
```

Vào File->Script Command, đổi Script Language sang python, dán code trên vào rồi thực hiện, giá trị của biến ```this``` sẽ được in ra Console Output

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/edcc5b469907231757fc707617e51a72952087e0/Task2/Images/007.png)

Quay trở lại chương trình, vào hàm ```runvm```, tiếp tục Convert to struct * để sửa lại các biến ```this``` theo Thiss và ```v2```, ```result``` theo struct func mình tạo ở trên kia

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/0a5ac44a255a6ca0921ba9d8c59cdeed236299e4/Task2/Images/008.png)

Đầu tiên hàm này sẽ thực hiện lặp While(1) để run VM. Trong vòng while này, hàm sẽ thực hiện một vòng lặp 48 lần để tìm địa chỉ cùa hàm cần gọi: đặt result là địa chỉ của hàm đầu tiên (MOVI) trong ```this``` (```this->function```). Sau đó kiểm tra giá trị ```result->cipher``` với offset ```this->step``` của ```this->vmcode```, nếu hai giá trị này bằng nhau thì gán ```result``` vào ```v2```. Sau đó tiếp tục tăng ```result``` và giảm biến đếm để tìm tiếp. Kết thúc vòng lặp thì gọi hàm ```v2``` ra để thực hiện. Thực hiện xong thì tiến hành cộng ```v2->step``` vào ```this->step``` để tiếp tục kiểm tra các hàm tiếp theo

Tuy nhiên nếu chỉ có vậy thì vòng lặp trên sẽ chạy mãi không dừng được, vì vậy phải có một nơi nào đó thay đổi giá trị step để nó kết thúc vòng lặp While(1) ở ngoài cùng.

Các hàm trong VM hầu hết đều khai báo hai giá trị chính: v4 là offset ```this->step + 1``` của ```this->vmcode```, còn v5 là offset ```this->step + 2``` của ```this->vmcode```. Ví dụ như với hàm ```movi```, giá trị v4 sẽ luôn bằng 2, khi đó offset 2 của ```this``` chính là ```loadOperand```, hàm này sẽ đẩy v5 vào ```this->loadOperand```; hay là với hàm ```lodi```, v4 sẽ luôn bằng 0, offset 0 của ```this``` là ```loadInput```, hàm này đẩy 1 word (2 kí tự) offset v5 của ```this->userinput``` vào ```this->loadInput```. Với hầu hết các hàm khác cũng vậy, cách thể hiện có thể khác nhưng đều là xoay quanh làm việc với các giá trị ```this->loadInput``` và ```this->loadOperand```

Tuy nhiên sẽ có 1 vài sự khác biệt ở hai hàm ```jpni``` và ```cmpw```

Về hàm ```cmpw```, hàm này sẽ so sánh ```this->loadInput``` đã được biến đổi ở các hàm trước đó với giá trị v4 được lấy từ ```this->vmcode```, nếu đúng điều kiện trong if, ```this->checker``` sẽ có giá trị là ước của ```0x10000```, còn nếu điều kiện sai thì sẽ 0 

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/4802d4ad763b85f83b4733e606192cab07801660/Task2/Images/009.png)

Về hàm ```jpni```, đầu tiên giá trị ```v2``` sẽ là bước nhảy đến hàm ```PRINT_WRONGGGG```, sau đó này sẽ kiểm tra ```this->checker``` có phải là ước của ```0x10000``` hay không, nếu đúng thì ```v2``` sẽ được tính lại là bước nhảy đến hàm tiếp theo. Đây chính là nơi quyết định chương trình có thể chạy tiếp hoặc dừng lại, ```v2``` được gán vào ```this->step``` và sau đó hàm ```jpni``` kết thúc. Khi này nếu v2 là bước nhảy đến hàm ```PPRINT_WRONGGGG```, chương trình sẽ in ra ```Wrong!``` và sau đó sẽ nhảy tiếp đến hàm ```shit```, tại đây có lệnh ```return 0``` để kết thúc hoàn toàn chương trình.

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/4802d4ad763b85f83b4733e606192cab07801660/Task2/Images/010.png)

Vậy để chương trình có thể chạy đến hàm ```YESSSSSSSSSSSSSSSSSSSSSSSSS``` thì ở hàm ```jpni``` ta chỉ cần đảm bảo cho ```v2``` không phải là bước nhảy đến hàm ```PRINT_WRONGGGG``` . Dựa vào đó mình sẽ viết thử một Script để lấy tất cả các hàm được gọi và các Operand đi kèm nó.

```python
vmcode = [0xDC, 0x00, 0x00, 0x00, 0x28, 0x00, 0xBD, 0x03, 0x0F, 0x00, 
  0x13, 0x51, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x02, 0x00, 0xB7, 
  0x02, 0x2E, 0x00, 0x29, 0x02, 0x0F, 0x00, 0x6D, 0x30, 0x18, 
  0x33, 0x01, 0xDC, 0x00, 0x04, 0x00, 0xB7, 0x02, 0x0B, 0x00, 
  0x29, 0x02, 0x0F, 0x00, 0x6F, 0x33, 0x18, 0x33, 0x01, 0xDC, 
  0x00, 0x06, 0x00, 0x28, 0x00, 0x69, 0x03, 0x0F, 0x00, 0xC8, 
  0x34, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x08, 0x00, 0xB7, 0x02, 
  0x2B, 0x00, 0x29, 0x02, 0xB7, 0x02, 0x57, 0x00, 0x29, 0x02, 
  0x0F, 0x00, 0x0F, 0x5F, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x0A, 
  0x00, 0xB7, 0x02, 0x61, 0x00, 0x29, 0x02, 0xB7, 0x02, 0x61, 
  0x00, 0x29, 0x02, 0xB7, 0x02, 0x40, 0x00, 0x29, 0x02, 0x0F, 
  0x00, 0x23, 0x68, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x0C, 0x00, 
  0xFB, 0x00, 0x4F, 0x03, 0x0F, 0x00, 0xE5, 0x2D, 0x18, 0x33, 
  0x01, 0xDC, 0x00, 0x0E, 0x00, 0xB7, 0x02, 0x46, 0x00, 0x29, 
  0x02, 0x0F, 0x00, 0x77, 0x33, 0x18, 0x33, 0x01, 0xDC, 0x00, 
  0x10, 0x00, 0xB7, 0x02, 0x1F, 0x00, 0x29, 0x02, 0xB7, 0x02, 
  0x1C, 0x00, 0x29, 0x02, 0xB7, 0x02, 0x26, 0x00, 0x29, 0x02, 
  0x0F, 0x00, 0x4B, 0x39, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x12, 
  0x00, 0xB7, 0x02, 0x0F, 0x00, 0x29, 0x02, 0xB7, 0x02, 0x57, 
  0x00, 0x29, 0x02, 0xB7, 0x02, 0x3F, 0x00, 0x29, 0x02, 0x0F, 
  0x00, 0x54, 0x5F, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x14, 0x00, 
  0xB7, 0x02, 0x37, 0x00, 0x29, 0x02, 0xB7, 0x02, 0x58, 0x00, 
  0x29, 0x02, 0xB7, 0x02, 0x4C, 0x00, 0x29, 0x02, 0x0F, 0x00, 
  0x41, 0x31, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x16, 0x00, 0xB7, 
  0x02, 0x24, 0x00, 0x29, 0x02, 0x0F, 0x00, 0x1D, 0x5F, 0x18, 
  0x33, 0x01, 0xDC, 0x00, 0x18, 0x00, 0xB7, 0x02, 0x1A, 0x00, 
  0x29, 0x02, 0xB7, 0x02, 0x1C, 0x00, 0x29, 0x02, 0x0F, 0x00, 
  0x6E, 0x34, 0x18, 0x33, 0x01, 0xDC, 0x00, 0x1A, 0x00, 0xFB, 
  0x00, 0x80, 0x03, 0x0F, 0x00, 0xEE, 0x60, 0x18, 0x33, 0x01, 
  0xDC, 0x00, 0x1C, 0x00, 0xFB, 0x00, 0x09, 0x01, 0x0F, 0x00, 
  0x6A, 0x20, 0x18, 0x33, 0x01, 0x34, 0xCE, 0x50, 0xCE]

this = [0, 0, 0, 0, 0, 0, 256, 768, 256, 12311528, vmcode, 12311248, ['MOVI', 183, 4, 0, 1908032, 0, 0, 0], ['MOVR', 78, 2, 0, 1908096, 0, 0, 0], ['LODI', 220, 4, 0, 1908192, 0, 0, 0], ['LODR', 103, 2, 0, 1908272, 0, 0, 0], ['STRI', 150, 4, 0, 1908384, 0, 0, 0], ['STRR', 12, 2, 0, 1908464, 0, 0, 0], ['ADDI', 40, 4, 0, 1908576, 0, 0, 0], ['ADDR', 106, 2, 0, 1908640, 0, 0, 0], ['SUBI', 251, 4, 0, 1908736, 0, 0, 0], ['SUBR', 255, 2, 0, 1908800, 0, 0, 0], ['ANDB', 93, 3, 0, 1908896, 0, 0, 0], ['ANDW', 108, 4, 0, 1908976, 0, 0, 0], ['ANDR', 46, 2, 0, 1909040, 0, 0, 0], ['YORB', 95, 3, 0, 1909136, 0, 0, 0], ['YORW', 11, 4, 0, 1909216, 0, 0, 0], ['YORR', 99, 2, 0, 1909280, 0, 0, 0], ['XORB', 87, 3, 0, 1909376, 0, 0, 0], ['XORW', 1, 4, 0, 1909456, 0, 0, 0], ['XORR', 41, 2, 0, 1909520, 0, 0, 0], ['NOTR', 74, 2, 0, 1909616, 0, 0, 0], ['MULI', 143, 4, 0, 1909712, 0, 0, 0], ['MULR', 37, 2, 0, 1909792, 0, 0, 0], ['DIVI', 114, 4, 0, 1909888, 0, 0, 0], ['DIVR', 131, 2, 0, 1909984, 0, 0, 0], ['SHLI', 57, 4, 0, 1910096, 0, 0, 0], ['SHLR', 159, 2, 0, 1910160, 0, 0, 0], ['SHRI', 250, 4, 0, 1910256, 0, 0, 0], ['SHRR', 88, 2, 0, 1910320, 0, 0, 0], ['PUSH', 62, 2, 0, 1910416, 0, 0, 0], ['POOP', 16, 2, 0, 1910512, 0, 0, 0], ['CMPB', 89, 3, 0, 1910592, 0, 0, 0], ['CMPW', 15, 4, 0, 1910688, 0, 0, 0], ['CMPR', 85, 2, 0, 1910784, 0, 0, 0], ['JMPI', 5, 3, 0, 1910912, 1, 0, 0], ['JMPR', 171, 2, 0, 1910944, 1, 0, 0], ['JPAI', 20, 3, 0, 1911008, 1, 0, 0], ['JPAR', 79, 2, 0, 1911056, 1, 0, 0], ['JPBI', 84, 3, 0, 1911120, 1, 0, 0], ['JPBR', 189, 2, 0, 1911168, 1, 0, 0], ['JPEI', 39, 3, 0, 1911232, 1, 0, 0], ['JPER', 13, 2, 0, 1911280, 1, 0, 0], ['JPNI', 24, 3, 0, 1911344, 1, 0, 0], ['JPNR', 135, 2, 0, 1911392, 1, 0, 0], ['CALL', 29, 3, 0, 1911456, 1, 0, 0], ['RETN', 249, 1, 0, 1911552, 1, 0, 0], ['SHIT', 206, 1, 0, 1911584, 0, 0, 0], ['NOPE', 80, 1, 0, 1911632, 0, 0, 0], ['GRMN', 52, 1, 0, 1911600, 0, 0, 0]]

def runvm(this):
    v2 = []
    while 1:
        v3 = 0x30
        cnt = 12
        while v3:
            res = this[cnt]
            if this[10][this[4]] == res[1]:
                v2 = res
                break
            cnt += 1
            v3 -= 1
        if v2[0] == 'LODI':
            # vmcode[this[4] + 1] = 0
            # this[vmcode[this[4] + 1]] = this[11][vmcode[this[4] + 2]]
            # load user input, 2 kí tự 1 lần
            print('lodi')
        elif v2[0] == 'ADDI':
            # vmcode[this[4] + 1] = 0
            # this[vmcode[this[4] + 1]] += hex(vmcode[this[4] + 2 + 1] * 0x100 + vmcode[this[4] + 2])
            print('addi ' + hex(vmcode[this[4] + 2 + 1] * 0x100 + vmcode[this[4] + 2]))
        elif v2[0] == 'SUBI':
            # vmcode[this[4] + 1] = 0
            # this[vmcode[this[4] + 1]] -= hex(vmcode[this[4] + 2 + 1] * 0x100 + vmcode[this[4] + 2])
            print('subi ' + hex(vmcode[this[4] + 2 + 1] * 0x100 + vmcode[this[4] + 2]))
        elif v2[0] == 'MOVI':
            # vmcode[this[4] + 1] = 2
            this[vmcode[this[4] + 1]] = hex(vmcode[this[4] + 2 + 1] * 0x100 + vmcode[this[4] + 2])
            print('movi ' + this[vmcode[this[4] + 1]])
        elif v2[0] == 'XORR':
            # vmcode[this[4] + 1] & 0xf = 2
            # vmcode[this[4] + 1] >> 4 = 0
            # this[vmcode[this[4] + 1] >> 4] ^= this[vmcode[this[4] + 1] & 0xf]
            print('xorr ' + this[vmcode[this[4] + 1] & 0xf])
        elif v2[0] == 'CMPW':
            print('cmpw ' + hex(vmcode[this[4] + 2 + 1] * 0x100 + vmcode[this[4] + 2]))
        elif v2[0] == 'JPNI':
            print('jpni')
            print()
            this[4] += 3
        elif v2[0] == 'GRMN':
            print('YESSSSSSSSSSSSSS')
        elif v2[0] == 'SHIT':
            print('SHIT')
            return
        if v2[5] == 0:
            this[4] += v2[2]

runvm(this)
```

Kết quả thu được của đoạn Script trên mình lưu ở file [result.txt](https://github.com/noobmannn/KCSCTrainingReverse/blob/e32c832cb2103dce0ebae5403ff5c9c32fa45552/Task2/Chal/result.txt)

Kết quả trên là 15 đoạn chương trình với cấu trúc: đầu tiên là lodi, tiếp đến là các lệnh xử lý và cuối cùng là lệnh jpni; đều có dạng giống như thế này

```
lodi
movi 0x2e
xorr 0x2e
cmpw 0x306d
jpni
```

Ví dụ như đoạn trên: lệnh ```lodi``` sẽ load 1 word input (2 kí tự) vào ```this->loadInput```, lệnh ```movi 0x2e``` sẽ gán ```0x2e``` vào ```this->loadOperand```, lệnh ```xorr 0x2e``` sẽ thực hiện ```this->loadInput ^= this->loadOperand```(```this->loadOperand = 0x2e```), lệnh ```cmpw 0x306d``` sẽ so sánh ```this->loadInput``` với ```0x306d```, sau đó lệnh ```jpni``` sẽ nhảy đến các hàm tiếp theo. Bây giờ chỉ cần reverse lại để lấy ```this->loadInput``` ban đầu ra xem

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/5c93df3bdc2059279c829f008dec1a1eb24d8cfc/Task2/Images/011.png)

Tiếp tục reverse 14 đoạn còn lại và ghép chúng lại theo thứ tự, ta thu được Flag

## Flag

```VMC0d3_1s_ch4113n93_b19_h4nds!```

