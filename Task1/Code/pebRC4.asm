.386 
.model flat, stdcall 
.stack 4096
assume fs:nothing

.data
    key db 300 dup(0)
    plainText db 300 dup(0)
    Sbox db 256 dup(0)
    keyStream db 300 dup(0)
    cipherText db 300 dup(0)
	hexCipherText db 600 dup(0)
    lenInput dd 0
    realOut dd 0
    realIn dd 0
    msg1 db "Key: ", 0
    msg1len dd $-msg1
    msg2 db "Plaintext: ", 0
    msg2len dd $-msg2
	msg3 db "Ciphertext (hex): ", 0
	msg3len dd $-msg3
    lenKey dd 0
    lenPlaintext dd 0

.code 
	main proc
		; Nhập Key và tính lenKey
        push offset msg1
        push msg1len
        call WriteConsole
        push offset key
        call ReadConsole
        push offset key
        call getStrLen
        mov lenKey, eax

		; Nhập Plaintext và tính lenPlaintext
        push offset msg2
        push msg2len
        call WriteConsole
        push offset plainText
        call ReadConsole
        push offset plainText
        call getStrLen
        mov lenPlaintext, eax
        
		; Tính Sbox
        push offset key
        call KSA

		; Tính KeyStream
		push lenPlaintext
		call PRGA

		; Tính CipherText
		push lenPlaintext
		push offset plainText
		call RC4_encrypted

		; Tính chuỗi hex để in kết quả
		push lenPlaintext
		push offset cipherText
		call strToHex

		; In kết quả ra màn hình
		push offset msg3
		push msg3len
		call WriteConsole
		push offset hexCipherText
		call getStrLen
		add eax, 01h 
		push offset hexCipherText
		push eax
		call WriteConsole

		; Exit Process
        call extProc
	main endp

    getStrLen proc
        push ebp
		mov ebp, esp			

        mov eax, [ebp + 08h]
        xor ecx, ecx
        xor edx, edx
        L1:
            mov dl, byte ptr [eax + ecx]
            inc ecx
            cmp dl, 0Dh
            jnz L1

        dec ecx
        mov eax, ecx
              
        mov esp, ebp
        pop ebp
        ret
    getStrLen endp

    KSA proc
        push ebp
		mov ebp, esp

        ;S = list(range(256))
        xor ebx, ebx
        mov edi, offset Sbox
        L2:
	        mov byte ptr [edi + ebx], bl
	        inc ebx
	        cmp ebx, 256
	        jl L2

        ; lặp 256 vòng tính Sbox
        xor ecx, ecx 						; i = 0
        xor ebx, ebx 						; j = 0
        L3:
            ; j = (j + S[i] + key[i % key_length]) % 256
        	mov esi, [ebp + 08h]			; key
        	mov edi, offset Sbox	    
        	xor eax, eax
        	add edi, ecx
        	mov al, byte ptr [edi]	
        	add ebx, eax                	; j + S[i]
        	xor eax, eax
        	mov eax, ecx
        	mov ch, byte ptr [lenKey]  
        	div ch							; i % len(key) | ch chia eax => q tại al, r tại ah
        	xor ch, ch
        	xor edx, edx
        	mov dl, ah
        	add esi, edx					; key[i % len(key)]
        	xor eax, eax
        	mov al, byte ptr [esi]		
        	add ebx, eax	            	; j + S[i] + key[i % key_length]			
        	mov eax, ebx
        	mov ebx, 256
        	div bx							; r tại dx	            
        	xor ebx, ebx
        	mov bx, dx                  	; (j + S[i] + key[i % key_length]) % 256

        	; S[i], S[j] = S[j], S[i]
        	xor eax, eax
        	mov eax, edi
        	mov dh, byte ptr [eax]      	; S[i]	
        	mov eax, offset Sbox
        	add eax, ebx
        	mov dl, byte ptr [eax]      	; S[j]	
        	mov byte ptr[eax], dh       	; swap
        	mov eax, edi
        	mov byte ptr[eax], dl

        	inc ecx                     	; i++
        	cmp ecx, 256			    
        	jl L3

        mov esp, ebp
        pop ebp
        ret
    KSA endp

	PRGA proc
		push ebp
		mov ebp, esp

		xor eax, eax						; i = 0
		xor edi, edi						; j = 0
		xor ecx, ecx						; biến đếm để lặp theo len(plaintext)
		L4:
			; i = (i + 1) % 256
			; j = (j + S[i]) % 256
			mov esi, offset Sbox
			inc eax
			mov ebx, 100h
			xor edx, edx
			div ebx							; edx = (i + 1) % 256
			mov eax, edi					; j
			xor ebx, ebx
			mov bl, byte ptr [esi + edx]	; S[i]
			add eax, ebx					; j + S[i]
			mov ebx, 100h
			mov edi, edx					; edi = (i + 1) % 256
			xor edx, edx
			div ebx 						; edx = (j + S[i]) % 256 
			mov eax, edi					; i = (i + 1) % 256
			mov edi, edx					; j = (j + S[i]) % 256

			; S[i], S[j] = S[j], S[i]
			xor ebx, ebx
			xor edx, edx
			mov bl, byte ptr [esi + eax]
			mov dl, byte ptr [esi + edi]
			mov byte ptr [esi + eax], dl
			mov byte ptr [esi + edi], bl

			; key_byte = S[(S[i] + S[j]) % 256]
			add ebx, edx					; ebx = S[i] + S[j]
			mov esi, eax
			mov eax, ebx					
			mov ebx, 100h
			xor edx, edx
			div ebx							; edx = (S[i] + S[j]) % 256
			mov eax, esi
			mov esi, offset Sbox
			mov bl, byte ptr [esi + edx]	; bl = S[(S[i] + S[j]) % 256]
			mov esi , offset keyStream
			mov byte ptr [esi + ecx], bl	; keystream.append(key_byte)

			; check với key(plaintext) và tăng biến đếm
			xor ebx, ebx
			mov ebx, [ebp + 8]
			inc ecx							
			cmp ecx, ebx
			jnz L4
		mov esp, ebp
        pop ebp
        ret
	PRGA endp

	RC4_encrypted proc
		push ebp
		mov ebp, esp

		mov esi, offset keyStream				
		mov edi, [ebp + 08h]					; offset plainText
		mov edx, [ebp + 0ch]					; lenPlainText
		xor ecx, ecx							; i = 0
		L5:
			xor eax, eax
			xor ebx, ebx
			mov al, byte ptr [esi + ecx]
			mov bl, byte ptr [edi + ecx]
			xor al, bl							; encrypted_byte = plaintext[i] ^ keystream[i]
			xor ebx, ebx
			mov ebx, offset cipherText
			mov byte ptr [ebx + ecx], al		; ciphertext.append(encrypted_byte)
			inc ecx
			cmp ecx, edx
			jnz L5
		mov esp, ebp
        pop ebp
        ret
	RC4_encrypted endp

	strToHex proc
		push ebp
		mov ebp, esp

		mov esi, [ebp + 08h]					; offset cipherText
		mov edi, offset hexCipherText
		mov edx, [ebp + 0ch]
		xor ecx, ecx
		L6:
			xor ebx, ebx
			movzx ebx, byte ptr [esi + ecx]
			shr ebx, 4							; lấy A trong AH
			call addHex
			movzx ebx, byte ptr [esi + ecx]
			and ebx, 0fh						; lấy H trong AH
			call addHex
			inc ecx
			cmp ecx, edx
			jnz L6
		mov byte ptr [edi], 0Dh
		mov esp, ebp
        pop ebp
        ret
	strToHex endp

	addHex proc
		push ebp
		mov ebp, esp
		cmp bl, 9
		jle add0to9
		add bl, 37h								; giá trị A cộng 0x37 thành kí tự 'A'
		mov byte ptr [edi], bl
		inc edi
		jmp ext
		add0to9:
			add bl, 30h							; giá trị 2 cộng 0x30 thành kí tự '2'
			mov byte ptr [edi], bl				
			inc edi
			jmp ext
	ext:
		mov esp, ebp
        pop ebp
        ret
	addHex endp

	; https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
    peb_getFunc proc
		push ebp
		mov ebp, esp

        sub esp, 14h
		xor eax, eax
		mov [ebp - 04h], eax			; lưu số lượng hàm trong kernel32.dll
		mov [ebp - 08h], eax			; lưu địa chỉ của EXPORT Address Table
		mov [ebp - 0ch], eax			; lưu địa chỉ của EXPORT Name Pointer Table
		mov [ebp - 10h], eax			; lưu địa chỉ của EXPORT Ordinal Table
		mov [ebp - 14h], eax			

		; lấy địa chỉ kernel32.dll
		; TEB->PEB->Ldr->InMemoryOrderLoadList->currentProgram->ntdll->kernel32.BaseDll
		mov eax, [fs:30h]		    	; Trỏ đến PEB (https://en.wikipedia.org/wiki/Win32_Thread_Information_Block)
		mov eax, [eax + 0ch]			; Trỏ đến Ldr
		mov eax, [eax + 14h]			; Trỏ đến InMemoryOrderModuleList
		mov eax, [eax]				  	; Trỏ đến currentProgram module
		mov eax, [eax]  				; Trỏ đến ntdll module
		mov eax, [eax -8h + 18h]		; eax = kernel32.dll base
		mov ebx, eax					; lưu địa chỉ của kernel32.dll vào ebx

		; lấy địa chỉ của PE signature
		mov eax, [ebx + 3ch]			; offset 0x30 sau kernel32.dll - data là RVA của PE signature (0xf8)
		add eax, ebx				    ; địa chỉ của PE signature: eax = 0xf8 + kernel32 base

		; lấy địa chỉ của Export Table
		mov eax, [eax + 78h]			; offset 0x78 sau PE signature là RVA của Export Table - data là RVA của IMAGE_EXPORT_DIRECTORY (0x93e40)
		add eax, ebx					; địa chỉ của  IMAGE_EXPORT_DIRECTORY = 0x93e40 + kernel32 base
  
		; lấy số lượng các hàm trong kernel32.dll
		mov ecx, [eax + 14h]			; 0x93e40 + 0x14 = 0x93e54 - data là số hàm có trong kernel32.dll (0x66b)
		mov [ebp - 4h], ecx				; [ebp - 4h] = 0x66b

		; lấy địa chỉ của EXPORT Address Table (nơi chứa địa chỉ các hàm của kernel32.dll)
		mov ecx, [eax + 1ch]			; 0x93e40 + 0x1c = 0x93e5c - data là địa chỉ của EXPORT Address Table (0x93e68)
		add ecx, ebx				   	; cộng thêm địa chỉ kernel32.dll
		mov [ebp - 8h], ecx				; [ebp - 8h] = 0x93e68 + kernel32 base

		; lấy địa chỉ của EXPORT Name Pointer Table (so sánh tên hàm với giá trị của cái này)
		mov ecx, [eax + 20h]			; 0x93e40 + 0x20 = 0x93e60 - data là địa chỉ của EXPORT Name Pointer Table (0x95814)
		add ecx, ebx					; cộng thêm địa chỉ kernel32.dll
		mov [ebp - 0ch], ecx			; [ebp - 0ch] = 0x95814 + kernel32 base

		; lấy địa chỉ của EXPORT Ordinal Table
		mov ecx, [eax + 24h]			; 0x93e40 + 0x24 = 0x93e64 - data là địa chỉ của EXPORT Name Pointer Table (0x971c0)
		add ecx, ebx					; cộng thêm địa chỉ kernel32.dll
		mov [ebp - 10h], ecx			; [ebp - 10h] = 0x971c0 + kernel32 base
	
		; vòng lặp tìm địa chỉ của hàm cần gọi trong kernel32.dll
		xor eax, eax
		xor ecx, ecx
			
		findYourFunctionPosition:
			mov esi, [ebp + 08h]		; esi = địa chỉ của chuỗi tên hàm cần tìm
			mov edi, [ebp - 0ch]		; edi = địa chỉ của EXPORT Name Pointer Table
			cld							; set cho Direction Flag bằng 0 (https://en.wikipedia.org/wiki/Direction_flag)
			mov edi, [edi + eax*4]		; edi + eax*4 để tính RVA của hàm tiếp theo => data của nó là địa chỉ hàm tiếp theo
			add edi, ebx				; cộng thêm với địa chỉ kernel32.dll

			mov cx, 8					; so sánh 8 byte đầu
			repe cmpsb					; so sánh [esi] và [edi]
				
			jz GetYourFunctionFound
			inc eax						; i++
			cmp eax, [ebp - 4h]			; kiểm tra xem check hết các hàm chưa
			jne findYourFunctionPosition	
				
		GetYourFunctionFound:		
			mov ecx, [ebp - 10h]		; ecx = ordinal table
			mov edx, [ebp - 8h]			; edx = export address table

			; tính địa chỉ hàm
			mov ax, [ecx + eax * 2]		; tính ordinal của hàm
			mov eax, [edx + eax * 4]	; lấy RVA của function
			add eax, ebx               	; cộng thêm địa chỉ kernel32.dll để lấy chính xác địa chỉ của hàm 

        add esp, 14h      
        mov esp, ebp
        pop ebp
        ret
    peb_getFunc endp

    getStdHandle proc
        push ebp
		mov ebp, esp
        
        sub esp, 08h
		xor eax, eax
	    mov [ebp - 04h], eax			; lưu chuỗi GetStdHandle
		mov [ebp - 08h], eax			

        ; đẩy chuỗi GetStdHandle vào Stack
        push 0                          ; push null
        push 656c646eh                  ; push e,l,d,n
		push 61486474h				    ; push a,H,d,t
		push 53746547h				    ; push S,t,e,G
		mov [ebp - 04h], esp			; lưu vào biến

        push [ebp - 04h]
        call peb_getFunc				; lấy địa chỉ hàm, kết quả tại eax

        push [ebp + 8h]
        call eax						; gọi hàm

        add esp, 08h
        mov esp, ebp
        pop ebp
        ret
    getStdHandle endp

    readConsole proc
        push ebp
		mov ebp, esp
        
        sub esp, 0ch
		xor eax, eax
		mov [ebp - 04h], eax			; lưu chuỗi ReadConsoleA
        mov [ebp - 08h], eax            ; lưu HandleRead (giá trị trả về của GetStdHandle)
        mov [ebp - 0ch], eax            

        push -10
        call getStdHandle
        mov [ebp - 08h], eax 

        ; đẩy chuỗi ReadConsoleA vào Stack
        push 00h                      	; push null
        push 41656c6fh                  ; push A,e,l,o
		push 736e6f43h				    ; push s,n,o,C
		push 64616552h				    ; push d,a,e,R
		mov [ebp - 04h], esp			; lưu vào biến

        push [ebp - 04h]
        call peb_getFunc				; lấy địa chỉ hàm, kết quả tại eax
        
		push 0
		push offset realIn
		push 300
		push [ebp + 08h]
		push [ebp - 08h]						
		call eax						; gọi hàm

        add esp, 0ch
        mov esp, ebp
        pop ebp
        ret
    readConsole endp

    writeConsole proc
        push ebp
		mov ebp, esp
        
        sub esp, 0ch
		xor eax, eax
		mov [ebp - 04h], eax			; lưu chuỗi WriteConsoleA
        mov [ebp - 08h], eax            ; lưu HandleWrite (giá trị trả về của GetStdHandle)
        mov [ebp - 0ch], eax            

		push -11							
		call getStdHandle
        mov [ebp - 08h], eax

        ; đẩy chuỗi WriteConsoleA vào Stack
        push 0041h                      ; push null,A
        push 656c6f73h                  ; push e,l,o,s
		push 6e6f4365h				    ; push n,o,C,e
		push 74697257h				    ; push t,i,r,W
		mov [ebp - 04h], esp			; lưu vào biến

        push [ebp - 04h]
        call peb_getFunc				; lấy địa chỉ hàm, kết quả tại eax
        
		push 0
		push offset realOut
		push [ebp + 08h]
		push [ebp + 0ch]
		push [ebp - 08h]						
		call eax						; gọi hàm

        add esp, 0ch
        mov esp, ebp
        pop ebp
        ret
    writeConsole endp

    extProc proc
        push ebp
		mov ebp, esp

        sub esp, 08h
		xor eax, eax
	    mov [ebp - 04h], eax			; lưu chuỗi ExitProcess
		mov [ebp - 08h], eax			

        ; đẩy chuỗi ExitProcess vào Stack
        push 00737365h                  ; push null,s,s,e
		push 636f7250h				    ; push c,o,r,P
		push 74697845h				    ; push t,i,x,E
		mov [ebp - 04h], esp			; lưu vào biến

        push [ebp - 04h]
        call peb_getFunc				; lấy địa chỉ hàm, kết quả tại eax

        push 0
        call eax						; gọi hàm

        add esp, 08h
        mov esp, ebp
        pop ebp
        ret
    extProc endp
	end main
	
