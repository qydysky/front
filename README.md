# front

这是一个简单的http/https/ws/wss均衡负载、故障转移路由/代理，通过定时刷新配置不中断地：

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

配置为json数组格式[]，下面为数组中的其中一个{}，下述字段*倾斜*的，表示不会根据配置动态加载

config:

- *addr*: string 监听端口 例：`0.0.0.0:8081`
- *matchRule*: string 匹配规则 `prefix`：当未匹配到时，返回最近的/匹配， `all`：当未匹配到时，返回404
- *copyBlocks*: int 转发的块数量，默认`1000`
- *tls*: {} 启用tls
    - *pub*: string 公钥pem路径
    - *key*: string 私钥pem路径
- routes: [] 路由
    - path: []string 路径
    - pathAdd: bool 将客户端访问的路径附加在path上 例：/api/req => /ws => /ws/api/req
    - rollRule: string 可选
        - `order`(按顺序)
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
        - to: string 后端地址，例`s://www.baidu.com`，会根据客户端自动添加http or ws在地址前
        - weight: int 权重，按routes中的全部back的权重比分配，当权重为0时，将停止新请求的进入
        - alwaysUp: bool 总是在线， 当只有一个后端时，默认为true
        - setting...

setting:

- splicing: int 当客户端支持cookie时，将会固定使用后端多少秒，默认不启用
- errToSec: float64 当后端响应超过(ws则指初次返回时间)指定秒，将会触发errBanSec
- errBanSec: int 当后端错误时（指连接失败，不指后端错误响应），将会禁用若干秒
- insecureSkipVerify: bool 忽略不安全的tls证书
- verifyPeerCer: string 路径，校验服务器证书，使用intermediate_ca

- filiter:
    - reqUri: 请求后端前，请求路径过滤器
        - accessRule: 布尔表达式，为true时才通过
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
