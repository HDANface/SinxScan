



## 使用方法

要定义 ffuf 的测试用例，请在 URL（`-u`）、请求头（`-H`）或 POST 数据（`-d`）中任何位置使用关键字 `FUZZ`。

```
Fuzz Faster U Fool - v2.1.0

HTTP 选项：
  -H                  请求头 `"Name: Value"`，以冒号分隔。可接受多个 -H 标志。
  -X                  使用的 HTTP 方法
  -b                  Cookie 数据 `"NAME1=VALUE1; NAME2=VALUE2"`，用于模拟 curl 功能。
  -cc                 用于认证的客户端证书。还需要定义客户端密钥才能使其工作
  -ck                 用于认证的客户端密钥。还需要定义客户端证书才能使其工作
  -d                  POST 数据
  -http2              使用 HTTP2 协议（默认：false）
  -ignore-body        不获取响应内容。（默认：false）
  -r                  跟随重定向（默认：false）
  -raw                不对 URI 进行编码（默认：false）
  -recursion          递归扫描。仅支持 FUZZ 关键字，且 URL（-u）必须以其结尾。（默认：false）
  -recursion-depth    最大递归深度。（默认：0）
  -recursion-strategy 递归策略："default" 基于重定向，"greedy" 对所有匹配进行递归（默认：default）
  -replay-proxy       使用此代理重放匹配的请求。
  -sni                目标 TLS SNI，不支持 FUZZ 关键字
  -timeout            HTTP 请求超时时间（秒）。（默认：10）
  -u                  目标 URL
  -x                  代理 URL（SOCKS5 或 HTTP）。例如：http://127.0.0.1:8080 或 socks5://127.0.0.1:8080

通用选项：
  -V                  显示版本信息。（默认：false）
  -ac                 自动校准过滤选项（默认：false）
  -acc                自定义自动校准字符串。可多次使用。隐含 -ac
  -ach                按主机自动校准（默认：false）
  -ack                自动校准关键字（默认：FUZZ）
  -acs                自定义自动校准策略。可多次使用。隐含 -ac
  -c                  彩色输出。（默认：false）
  -config             从文件加载配置
  -json               JSON 输出，打印换行符分隔的 JSON 记录（默认：false）
  -maxtime            整个进程的最大运行时间（秒）。（默认：0）
  -maxtime-job        每个作业的最大运行时间（秒）。（默认：0）
  -noninteractive     禁用交互式控制台功能（默认：false）
  -p                  请求之间的 `延迟` 秒数，或随机延迟范围。例如 "0.1" 或 "0.1-2.0"
  -rate               每秒请求数（默认：0）
  -s                  不打印其他信息（静默模式）（默认：false）
  -sa                 在所有错误情况下停止。隐含 -sf 和 -se。（默认：false）
  -scraperfile        自定义爬虫文件路径
  -scrapers           活跃的爬虫组（默认：all）
  -se                 在虚假错误时停止（默认：false）
  -search             从 ffuf 历史记录中搜索 FFUFHASH 载荷
  -sf                 当 > 95% 的响应返回 403 Forbidden 时停止（默认：false）
  -t                  并发线程数。（默认：40）
  -v                  详细输出，打印完整 URL 和重定向位置（如果有）以及结果。（默认：false）

匹配器选项：
  -mc                 匹配 HTTP 状态码，或 "all" 匹配所有。（默认：200-299,301,302,307,401,403,405,500）
  -ml                 匹配响应中的行数
  -mmode              匹配器集运算符。可选值：and, or（默认：or）
  -mr                 匹配正则表达式
  -ms                 匹配 HTTP 响应大小
  -mt                 匹配到第一个响应字节的毫秒数，大于或小于。例如：>100 或 <100
  -mw                 匹配响应中的词数

过滤器选项：
  -fc                 从响应中过滤 HTTP 状态码。逗号分隔的代码和范围列表
  -fl                 按响应中的行数过滤。逗号分隔的行数和范围列表
  -fmode              过滤器集运算符。可选值：and, or（默认：or）
  -fr                 过滤正则表达式
  -fs                 过滤 HTTP 响应大小。逗号分隔的大小和范围列表
  -ft                 按到第一个响应字节的毫秒数过滤，大于或小于。例如：>100 或 <100
  -fw                 按响应中的词数过滤。逗号分隔的词数和范围列表

输入选项：
  -D                  DirSearch 词表兼容模式。与 -e 标志一起使用。（默认：false）
  -e                  逗号分隔的扩展名列表。扩展 FUZZ 关键字。
  -enc                关键字的编码器，例如 'FUZZ:urlencode b64encode'
  -ic                 忽略词表注释（默认：false）
  -input-cmd          生成输入的命令。使用此输入方法时需要 --input-num。覆盖 -w。
  -input-num          要测试的输入数量。与 --input-cmd 结合使用。（默认：100）
  -input-shell        用于运行命令的 shell
  -mode               多词表操作模式。可用模式：clusterbomb, pitchfork, sniper（默认：clusterbomb）
  -request            包含原始 http 请求的文件
  -request-proto      与原始请求一起使用的协议（默认：https）
  -w                  词表文件路径和（可选）以冒号分隔的关键字。例如 '/path/to/wordlist:KEYWORD'

输出选项：
  -debug-log          将所有内部日志写入指定文件。
  -o                  将输出写入文件
  -od                 存储匹配结果的目录路径。
  -of                 输出文件格式。可用格式：json, ejson, html, md, csv, ecsv（或 'all' 表示所有格式）（默认：json）
  -or                 如果没有结果则不创建输出文件（默认：false）

使用示例：
  从 wordlist.txt 模糊测试文件路径，匹配所有响应但过滤掉内容大小为 42 的响应。
  彩色、详细输出。
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

  模糊测试 Host 头，匹配 HTTP 200 响应。
    ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

  模糊测试 POST JSON 数据。匹配所有不包含 "error" 文本的响应。
    ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
      -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"

  模糊测试多个位置。仅匹配反映 "VAL" 关键字值的响应。彩色输出。
    ffuf -w params.txt:PARAM -w values.txt:VAL -u https://example.org/?PARAM=VAL -mr "VAL" -c

  更多信息和示例：https://github.com/ffuf/ffuf
```

### 交互模式

在 ffuf 执行期间按 `ENTER`，进程会暂停，用户进入类似 shell 的交互模式：

```
entering interactive mode
type "help" for a list of commands, or ENTER to resume.
> help

可用命令：
 afc  [value]             - 追加到状态码过滤器
 fc   [value]             - (重新)配置状态码过滤器
 afl  [value]             - 追加到行数过滤器
 fl   [value]             - (重新)配置行数过滤器
 afw  [value]             - 追加到词数过滤器
 fw   [value]             - (重新)配置词数过滤器
 afs  [value]             - 追加到大小过滤器
 fs   [value]             - (重新)配置大小过滤器
 aft  [value]             - 追加到时间过滤器
 ft   [value]             - (重新)配置时间过滤器
 rate [value]             - 调整每秒请求数（当前：0）
 queueshow                - 显示作业队列
 queuedel [number]        - 删除队列中的作业
 queueskip                - 跳到下一个排队的作业
 restart                  - 重启并恢复当前 ffuf 作业
 resume                   - 恢复当前 ffuf 作业（或：ENTER）
 show                     - 显示当前作业的结果
 savejson [filename]      - 将当前匹配项保存到文件
 help                     - 你正在查看它
>
```

