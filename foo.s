
./build/test:     file format elf64-x86-64


Disassembly of section .init:

0000000000001000 <_init>:
    1000:	f3 0f 1e fa          	endbr64
    1004:	48 83 ec 08          	sub    $0x8,%rsp
    1008:	48 8b 05 c1 2f 00 00 	mov    0x2fc1(%rip),%rax        # 3fd0 <__gmon_start__@Base>
    100f:	48 85 c0             	test   %rax,%rax
    1012:	74 02                	je     1016 <_init+0x16>
    1014:	ff d0                	call   *%rax
    1016:	48 83 c4 08          	add    $0x8,%rsp
    101a:	c3                   	ret

Disassembly of section .plt:

0000000000001020 <printf@plt-0x10>:
    1020:	ff 35 ca 2f 00 00    	push   0x2fca(%rip)        # 3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:	ff 25 cc 2f 00 00    	jmp    *0x2fcc(%rip)        # 3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:	0f 1f 40 00          	nopl   0x0(%rax)

0000000000001030 <printf@plt>:
    1030:	ff 25 ca 2f 00 00    	jmp    *0x2fca(%rip)        # 4000 <printf@GLIBC_2.2.5>
    1036:	68 00 00 00 00       	push   $0x0
    103b:	e9 e0 ff ff ff       	jmp    1020 <_init+0x20>

0000000000001040 <usleep@plt>:
    1040:	ff 25 c2 2f 00 00    	jmp    *0x2fc2(%rip)        # 4008 <usleep@GLIBC_2.2.5>
    1046:	68 01 00 00 00       	push   $0x1
    104b:	e9 d0 ff ff ff       	jmp    1020 <_init+0x20>

Disassembly of section .text:

0000000000001050 <_start>:
    1050:	f3 0f 1e fa          	endbr64
    1054:	31 ed                	xor    %ebp,%ebp
    1056:	49 89 d1             	mov    %rdx,%r9
    1059:	5e                   	pop    %rsi
    105a:	48 89 e2             	mov    %rsp,%rdx
    105d:	48 83 e4 f0          	and    $0xfffffffffffffff0,%rsp
    1061:	50                   	push   %rax
    1062:	54                   	push   %rsp
    1063:	45 31 c0             	xor    %r8d,%r8d
    1066:	31 c9                	xor    %ecx,%ecx
    1068:	48 8d 3d 2f 01 00 00 	lea    0x12f(%rip),%rdi        # 119e <main>
    106f:	ff 15 4b 2f 00 00    	call   *0x2f4b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
    1075:	f4                   	hlt
    1076:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    107d:	00 00 00 
    1080:	48 8d 3d 99 2f 00 00 	lea    0x2f99(%rip),%rdi        # 4020 <__TMC_END__>
    1087:	48 8d 05 92 2f 00 00 	lea    0x2f92(%rip),%rax        # 4020 <__TMC_END__>
    108e:	48 39 f8             	cmp    %rdi,%rax
    1091:	74 15                	je     10a8 <_start+0x58>
    1093:	48 8b 05 2e 2f 00 00 	mov    0x2f2e(%rip),%rax        # 3fc8 <_ITM_deregisterTMCloneTable@Base>
    109a:	48 85 c0             	test   %rax,%rax
    109d:	74 09                	je     10a8 <_start+0x58>
    109f:	ff e0                	jmp    *%rax
    10a1:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10a8:	c3                   	ret
    10a9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10b0:	48 8d 3d 69 2f 00 00 	lea    0x2f69(%rip),%rdi        # 4020 <__TMC_END__>
    10b7:	48 8d 35 62 2f 00 00 	lea    0x2f62(%rip),%rsi        # 4020 <__TMC_END__>
    10be:	48 29 fe             	sub    %rdi,%rsi
    10c1:	48 89 f0             	mov    %rsi,%rax
    10c4:	48 c1 ee 3f          	shr    $0x3f,%rsi
    10c8:	48 c1 f8 03          	sar    $0x3,%rax
    10cc:	48 01 c6             	add    %rax,%rsi
    10cf:	48 d1 fe             	sar    $1,%rsi
    10d2:	74 14                	je     10e8 <_start+0x98>
    10d4:	48 8b 05 fd 2e 00 00 	mov    0x2efd(%rip),%rax        # 3fd8 <_ITM_registerTMCloneTable@Base>
    10db:	48 85 c0             	test   %rax,%rax
    10de:	74 08                	je     10e8 <_start+0x98>
    10e0:	ff e0                	jmp    *%rax
    10e2:	66 0f 1f 44 00 00    	nopw   0x0(%rax,%rax,1)
    10e8:	c3                   	ret
    10e9:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    10f0:	f3 0f 1e fa          	endbr64
    10f4:	80 3d 25 2f 00 00 00 	cmpb   $0x0,0x2f25(%rip)        # 4020 <__TMC_END__>
    10fb:	75 33                	jne    1130 <_start+0xe0>
    10fd:	55                   	push   %rbp
    10fe:	48 83 3d da 2e 00 00 	cmpq   $0x0,0x2eda(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1105:	00 
    1106:	48 89 e5             	mov    %rsp,%rbp
    1109:	74 0d                	je     1118 <_start+0xc8>
    110b:	48 8b 3d 06 2f 00 00 	mov    0x2f06(%rip),%rdi        # 4018 <__dso_handle>
    1112:	ff 15 c8 2e 00 00    	call   *0x2ec8(%rip)        # 3fe0 <__cxa_finalize@GLIBC_2.2.5>
    1118:	e8 63 ff ff ff       	call   1080 <_start+0x30>
    111d:	c6 05 fc 2e 00 00 01 	movb   $0x1,0x2efc(%rip)        # 4020 <__TMC_END__>
    1124:	5d                   	pop    %rbp
    1125:	c3                   	ret
    1126:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    112d:	00 00 00 
    1130:	c3                   	ret
    1131:	66 66 2e 0f 1f 84 00 	data16 cs nopw 0x0(%rax,%rax,1)
    1138:	00 00 00 00 
    113c:	0f 1f 40 00          	nopl   0x0(%rax)
    1140:	f3 0f 1e fa          	endbr64
    1144:	e9 67 ff ff ff       	jmp    10b0 <_start+0x60>

0000000000001149 <foo>:
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline)) int foo(int x, float b) {
    1149:	55                   	push   %rbp
    114a:	48 89 e5             	mov    %rsp,%rbp
    114d:	48 83 ec 10          	sub    $0x10,%rsp
    1151:	89 7d fc             	mov    %edi,-0x4(%rbp)
    1154:	f3 0f 11 45 f8       	movss  %xmm0,-0x8(%rbp)
    printf("the value of x is %d\n", x);
    1159:	8b 45 fc             	mov    -0x4(%rbp),%eax
    115c:	48 8d 15 a1 0e 00 00 	lea    0xea1(%rip),%rdx        # 2004 <_IO_stdin_used+0x4>
    1163:	89 c6                	mov    %eax,%esi
    1165:	48 89 d7             	mov    %rdx,%rdi
    1168:	b8 00 00 00 00       	mov    $0x0,%eax
    116d:	e8 be fe ff ff       	call   1030 <printf@plt>
    printf("the value of b is %.2f\n", b);
    1172:	66 0f ef c9          	pxor   %xmm1,%xmm1
    1176:	f3 0f 5a 4d f8       	cvtss2sd -0x8(%rbp),%xmm1
    117b:	66 48 0f 7e c8       	movq   %xmm1,%rax
    1180:	48 8d 15 93 0e 00 00 	lea    0xe93(%rip),%rdx        # 201a <_IO_stdin_used+0x1a>
    1187:	66 48 0f 6e c0       	movq   %rax,%xmm0
    118c:	48 89 d7             	mov    %rdx,%rdi
    118f:	b8 01 00 00 00       	mov    $0x1,%eax
    1194:	e8 97 fe ff ff       	call   1030 <printf@plt>
    return x;
    1199:	8b 45 fc             	mov    -0x4(%rbp),%eax
}
    119c:	c9                   	leave
    119d:	c3                   	ret

000000000000119e <main>:

int main(int argc, char* argv[]) {
    119e:	55                   	push   %rbp
    119f:	48 89 e5             	mov    %rsp,%rbp
    11a2:	48 83 ec 20          	sub    $0x20,%rsp
    11a6:	89 7d ec             	mov    %edi,-0x14(%rbp)
    11a9:	48 89 75 e0          	mov    %rsi,-0x20(%rbp)
    printf("this is a test program");
    11ad:	48 8d 05 7e 0e 00 00 	lea    0xe7e(%rip),%rax        # 2032 <_IO_stdin_used+0x32>
    11b4:	48 89 c7             	mov    %rax,%rdi
    11b7:	b8 00 00 00 00       	mov    $0x0,%eax
    11bc:	e8 6f fe ff ff       	call   1030 <printf@plt>
    int x = 0;
    11c1:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
    for (int i = 0; i < 10; i++) {
    11c8:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
    11cf:	eb 43                	jmp    1214 <main+0x76>
        foo(1, 2.7);
    11d1:	8b 05 75 0e 00 00    	mov    0xe75(%rip),%eax        # 204c <_IO_stdin_used+0x4c>
    11d7:	66 0f 6e c0          	movd   %eax,%xmm0
    11db:	bf 01 00 00 00       	mov    $0x1,%edi
    11e0:	e8 64 ff ff ff       	call   1149 <foo>
        usleep(50);
    11e5:	bf 32 00 00 00       	mov    $0x32,%edi
    11ea:	e8 51 fe ff ff       	call   1040 <usleep@plt>
        x = foo(2, 3.14);
    11ef:	8b 05 5b 0e 00 00    	mov    0xe5b(%rip),%eax        # 2050 <_IO_stdin_used+0x50>
    11f5:	66 0f 6e c0          	movd   %eax,%xmm0
    11f9:	bf 02 00 00 00       	mov    $0x2,%edi
    11fe:	e8 46 ff ff ff       	call   1149 <foo>
    1203:	89 45 f8             	mov    %eax,-0x8(%rbp)
        usleep(1000);
    1206:	bf e8 03 00 00       	mov    $0x3e8,%edi
    120b:	e8 30 fe ff ff       	call   1040 <usleep@plt>
    for (int i = 0; i < 10; i++) {
    1210:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
    1214:	83 7d fc 09          	cmpl   $0x9,-0x4(%rbp)
    1218:	7e b7                	jle    11d1 <main+0x33>
    }
    return x;
    121a:	8b 45 f8             	mov    -0x8(%rbp),%eax
}
    121d:	c9                   	leave
    121e:	c3                   	ret

Disassembly of section .fini:

0000000000001220 <_fini>:
    1220:	f3 0f 1e fa          	endbr64
    1224:	48 83 ec 08          	sub    $0x8,%rsp
    1228:	48 83 c4 08          	add    $0x8,%rsp
    122c:	c3                   	ret
