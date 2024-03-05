# front

这是一个简单的http/https/ws/wss均衡负载、故障转移路由/代理，通过定时刷新配置不中断地：

- 动态后端
- 路径继承
- 自定权重
- 故障转移
- 自定义头
- 请求头过滤
- 请求数据过滤

支持嵌入到其他项目中/独立运行

配置为json数组格式[]，下面为数组中的其中一个{}，注意此级不会动态增加/移除

config:

- addr: string 监听端口 例：0.0.0.0:8081
- matchRule: string 匹配规则 prefix：当未匹配到时，返回最近的/匹配， all：当未匹配到时，返回404
- copyBlocks: int 转发的块数量，默认1000
- tls: {} 启用tls
    - pub: string 公钥pem路径
    - key: string 私钥pem路径
- routes: [] 路由, 可以动态增加/删除
    - path: string 路径
    - splicing: int 当客户端支持cookie时，将会固定使用后端多少秒
    - pathAdd: bool 将客户端访问的路径附加在path上 例：/api/req => /ws => /ws/api/req
    - matcher 将会附加到每个backs前
    - backs: [] 后端, 可以动态增加/删除
        - name: string 后端名称，将在日志中显示
        - to: string 后端地址，例"s://www.baidu.com"，会根据客户端自动添加http or ws在地址前
        - weight: int 权重，按routes中的全部back的权重比分配，当权重变为0时，将停止新请求的进入
        - errBanSec: int 当后端错误时（指连接失败，不指后端错误响应），将会禁用若干秒
        - matcher

matcher:

- matchHeader: [] 匹配客户端请求头，只有都匹配才使用此后端, 可以动态增加/删除
    - key: string 要匹配的header名
    - matchExp: string 要匹配的正则式
    - value: string 要匹配的值
- reqHeader: [] 请求后端前，请求头处理器, 可以动态增加/删除
    - action: string 可选check、replace、add、del、set。
    - key: string 具体处理哪个头
    - matchExp: string check时，如不匹配将结束请求。replace时结合value进行替换
    - value: string check时，如不匹配将结束请求。replace时结合matchExp进行替换。add时将附加值。set时将覆盖值。
- resHeader: [] 返回后端的响应前，请求头处理器, 可以动态增加/删除
    - action: string 可选check、add、del、set。
    - key: string 具体处理哪个头
    - matchExp: string check时，如不匹配将结束请求。replace时结合value进行替换
    - value: string check时，如不匹配将结束请求。replace时结合matchExp进行替换。add时将附加值。set时将覆盖值。
- reqBody: [] 请求后端前，请求数据过滤器, 可以动态增加/删除
    - action: string 可选access,deny。
    - reqSize：string 限定请求数据大小，默认为"1M"
    - matchExp: string access时如不匹配将结束请求。deny时如匹配将结束请求。
