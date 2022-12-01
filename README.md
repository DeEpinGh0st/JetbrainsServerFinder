
![Logo](https://raw.githubusercontent.com/DeEpinGh0st/BlogOSS/main/aticles/2022/11/29/202211292006258.png)


# JetbrainsServerFinder

JetbrainsServerFinder是一个利用Shodan搜索引擎查询Jetbrains系列产品激活服务器的网页端工具


## 安装

clone仓库

```bash
git clone https://github.com/DeEpinGh0st/JetbrainsServerFinder.git
```
修改settings.py的APIKEY  
![](https://raw.githubusercontent.com/DeEpinGh0st/BlogOSS/main/aticles/2022/11/29/202211292015247.png)
APIKEY可从[Shodan账户页面](https://account.shodan.io/)获取  
启动本地测试服务  
```bash
python manage.py runserver
```
访问`http://127.0.0.1:8000`即可  
**注意**  
发布上线前, 请修改settings.py的DEBUG为`FALSE`  

## Docker
```bash
docker run -d --name jetbrainserverfinder -p 8000:8000 --env APIKEY=xxxxxxxxxx s0cke3t/jetbrainserverfinder:latest
```
## API 参考

#### 获取激活服务列表

```http
  GET /getserverlist
```

| 参数 | 类型     | 描述                |
| :-------- | :------- | :------------------------- |
| `无` | `无` | 获取所有存活且可用的激活服务器 |

![](https://raw.githubusercontent.com/DeEpinGh0st/BlogOSS/main/aticles/2022/11/29/202211291943755.png)
## 截图

![](https://raw.githubusercontent.com/DeEpinGh0st/BlogOSS/main/aticles/2022/11/29/202211301537522.png)


## TODO

 - ~~Docker~~(已完成)
 - ~~Mutilthread~~(已完成)


## 致谢

 - [readme.so](https://readme.so)
 - [logoko](https://www.logoko.com.cn)
 

