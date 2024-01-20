# Task 1

```
Task 1: Code thuật toán mã hóa RC4 bằng masm
Yêu cầu: -  Chạy được
         -  Input: Plain Text + Key
         -  Output: Hex 
         -  Giải thích comment code rõ ràng 
         -  Không được dùng các thư viện có sẵn (print hex, kể cả kernel32.dll để gọi API,...) 
         -  Bài này chỉ sử dụng 3 WinAPI là GetStdHandle, WriteConsole vầ ReadConsole, sử dụng PEB để resolve 3 API này
Suggested IDE: https://www.masm32.com/
```

### Code

[pebRC4.asm](https://github.com/noobmannn/KCSCTrainingReverse/blob/main/Task1/Code/pebRC4.asm)
[pebRC4.exe](https://github.com/noobmannn/KCSCTrainingReverse/blob/main/Task1/Code/pebRC4.exe)

### Demo

![](https://github.com/noobmannn/KCSCTrainingReverse/blob/855d60f25f38192aa230ac730f10ef1e6ef0de22/Task1/Img/Demo%20pebRC4.png)
