# front

这是一个简单的http/https/ws/wss均衡负载、故障转移路由/代理，通过定时刷新配置不中断地：

- 监听占用等待
- 动态后端
- 路径继承
- 自定权重
- 故障转移
- 自定义头
- 多种轮询
- 请求路径过滤
- 请求头过滤
- 请求数据过滤

支持嵌入到其他项目中/独立运行

示例
```json
[
    {
        "addr": "127.0.0.1:10000",
        "routes": [
            {
                "path": ["/"],
                "pathAdd": true,
                "filiter": {
                    "reqUri": {
                        "accessRule": "!{stop}",
                        "items": {
                            "stop": "(main\\.json)"
                        }
                    }
                },
                "backs": [
                    {
                        "name": "back1",
                        "to": "./",
                        "weight": "1"
                    }
                ]
            }
        ]
    }
]
```
```
curl http://127.0.0.1:10000/
<!doctype html>
<meta name="viewport" content="width=device-width">
<pre>
<a href="front.run">front.run</a>
<a href="main.json">main.json</a>
<a href="main.log">main.log</a>
</pre>

curl http://127.0.0.1:10000/main.json -I
HTTP/1.1 403 Forbidden
X-Front-Error: ErrPatherCheckFail
Date: Wed, 30 Oct 2024 17:50:22 GMT

curl http://127.0.0.1:10000/main.log -I
HTTP/1.1 200 OK
Accept-Ranges: bytes
Content-Length: 1700014
Content-Type: text/x-log; charset=utf-8
Last-Modified: Wed, 30 Oct 2024 17:51:23 GMT
Date: Wed, 30 Oct 2024 17:51:23 GMT
```

配置为json数组格式[]，下面为数组中的其中一个{}，下述字段*倾斜*的，表示不会根据配置动态加载

config:

- *addr*: string 监听端口 例：`0.0.0.0:8081`
- *matchRule*: string 匹配规则，默认`prefix`。 `prefix`：当未匹配到时，返回最近的/匹配， `all`：当未匹配到时，返回404
- *copyBlocks*: int 转发的块数量，默认`1000`
- *retryBlocks*: {} 重试, 当停用时，分配仅进行一次
    - *sizeB*: int 重试的块大小，默认`1000000`
    - *num*: int 重试的块数量，默认`0`，为`0`时停用重试
- *tls*: {} 启用tls, 默认空
    - *pub*: string 公钥pem路径
    - *key*: string 私钥pem路径
- routes: [] 路由
    - path: []string 路径
    - pathAdd: bool 将客户端访问的路径附加在path上 例：/api/req => /ws => /ws/api/req
    - rollRule: string 可选
        - `order`(按顺序)
        - `loop`(轮流)
        - `disableC_MinFirst`(禁用数较少的优先)
        - `dealingC_MinFirst`(连接数较少的优先)
        - `chosenC_MinFirst`(被选择较少的优先)
        - (使用rand.Shuffle随机，默认)
    - reqBody: 请求后端前，请求数据过滤器
        - action: string 可选`access`、`deny`。
        - reqSize: string 限定请求数据大小，默认为`1M`
        - matchExp: string `access`时如不匹配将结束请求。`deny`时如匹配将结束请求。
    - setting... 将会给backs默认值
    - backs: [] 后端
        - name: string 后端名称，将在日志中显示
        - to: string 后端地址，说明如下：
            - 含有`://`时，例`s://www.baidu.com`，会根据客户端自动添加http or ws在地址前
            - 不含`://`时，将会尝试解析成本地文件
        - weight: string uint 权重，按routes中的全部back的权重比分配，当权重为0时，将停止新请求的进入
        - alwaysUp: bool 总是在线， 当只有一个后端时，默认为true
        - setting...

setting: json配置不需要setting

- splicing: int 当客户端支持cookie时，将会固定使用后端多少秒，默认不启用
- errToSec: float64 当后端响应超过(ws则指初次返回时间)指定秒，将会触发errBanSec
- errBanSec: int 当后端错误时（指连接失败，不指后端错误响应），将会禁用若干秒
- insecureSkipVerify: bool 忽略不安全的tls证书
- verifyPeerCer: string 路径，校验服务器证书，使用intermediate_ca

- filiter:
    - reqUri: 请求后端前，请求路径过滤器
        - accessRule: 布尔表达式，为true时才通过,例`{id}|(!{id2}&{id3})`
        - items: map[string]string
            - id: matchExp
    - reqHeader: 请求后端前，请求头处理器
        - accessRule: 布尔表达式，为true时才通过
        - items: map[string]{}
            - id:
                - key: string header头
                - matchExp: string
    - resHeader: 返回后端的响应前，请求头处理器
        - accessRule: 布尔表达式，为true时才通过
        - items: map[string]{}
            - id:
                - key: string header头
                - matchExp: string
- dealer:
    - reqUri:[] 请求后端前，路径处理器
        - action: string 可选`replace`。
        - matchExp: string `replace`时结合value进行替换
        - value: string `replace`时结合matchExp进行替换。
    - reqHeader:[] 请求后端前，请求头处理器
        - action: string 可选`replace`、`add`、`del`、`set`。
        - key: string 具体处理哪个头
        - matchExp: string `replace`时结合value进行替换
        - value: string `replace`时结合matchExp进行替换。add时将附加值。`set`时将覆盖值。
    - resHeader:[] 返回后端的响应前，请求头处理器
        - action: string 可选`add`、`del`、`set`。
        - key: string 具体处理哪个头
        - matchExp: string `replace`时结合value进行替换
        - value: string `replace`时结合matchExp进行替换。`add`时将附加值。`set`时将覆盖值。
