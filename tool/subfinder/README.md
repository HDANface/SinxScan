# **Subfinder - 快速被动子域名枚举工具**

快速被动子域名枚举工具。

[![img](https://goreportcard.com/badge/github.com/projectdiscovery/subfinder)](https://goreportcard.com/report/github.com/projectdiscovery/subfinder/v2)[![img](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/subfinder/issues)[![img](https://img.shields.io/github/release/projectdiscovery/subfinder)](https://github.com/projectdiscovery/subfinder/releases)[![img](https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter)](https://twitter.com/pdiscoveryio)

------

`subfinder` 是一个子域名发现工具，使用被动在线源返回网站的有效子域名。它具有简单、模块化的架构，并针对速度进行了优化。`subfinder` 专为做一件事而构建——被动子域名枚举，并且做得非常好。

## **功能特性**

- 快速强大的解析和通配符消除模块
- **精选**的被动源以最大化结果
- 支持多种输出格式（JSON、文件、标准输出）
- 针对速度进行了优化，资源占用**轻量**
- **STDIN/OUT**支持便于轻松集成到工作流中

## **使用方法**

```
subfinder -h

```

这将显示工具的帮助信息。以下是它支持的所有开关选项。

```
用法:
  ./subfinder [flags]

标志:
输入:
  -d, -domain string[]  要查找子域名的域名
  -dL, -list string     包含用于子域名发现的域名列表的文件

源:
  -s, -sources string[]           用于发现的特定源 (-s crtsh,github)。使用 -ls 显示所有可用源。
  -recursive                      仅使用能够递归处理子域名的源（例如 subdomain.domain.tld 与 domain.tld）
  -all                            使用所有源进行枚举（较慢）
  -es, -exclude-sources string[]  从枚举中排除的源 (-es alienvault,zoomeyeapi)

过滤器:
  -m, -match string[]   要匹配的子域名或子域名列表（文件或逗号分隔）
  -f, -filter string[]   要过滤的子域名或子域名列表（文件或逗号分隔）

速率限制:
  -rl, -rate-limit int  每秒发送的最大HTTP请求数
  -rls value            以key=value格式为提供者设置每秒最大HTTP请求数 (-rls "hackertarget=10/s,shodan=15/s")
  -t int                用于解析的并发goroutine数量（仅-active）（默认10）

更新:
  -up, -update                 将subfinder更新到最新版本
  -duc, -disable-update-check  禁用自动subfinder更新检查

输出:
  -o, -output string       写入输出的文件
  -oJ, -json               以JSONL(ines)格式写入输出
  -oD, -output-dir string  写入输出的目录（仅-dL）
  -cs, -collect-sources    在输出中包含所有源（仅-json）
  -oI, -ip                 在输出中包含主机IP（仅-active）

配置:
  -config string                标志配置文件（默认"$CONFIG/subfinder/config.yaml"）
  -pc, -provider-config string  提供者配置文件（默认"$CONFIG/subfinder/provider-config.yaml"）
  -r string[]                   要使用的解析器逗号分隔列表
  -rL, -rlist string            包含要使用的解析器列表的文件
  -nW, -active                  仅显示活跃子域名
  -proxy string                 与subfinder一起使用的HTTP代理
  -ei, -exclude-ip              从域名列表中排除IP

调试:
  -silent             输出中仅显示子域名
  -version            显示subfinder版本
  -v                  显示详细输出
  -nc, -no-color      禁用输出中的颜色
  -ls, -list-sources  列出所有可用源

优化:
  -timeout int   超时前等待的秒数（默认30）
  -max-time int  等待枚举结果的分钟数（默认10）
```

### **环境变量**

Subfinder支持环境变量来指定配置文件的自定义路径：

- `SUBFINDER_CONFIG` - config.yaml文件的路径（覆盖默认的`$CONFIG/subfinder/config.yaml`）
- `SUBFINDER_PROVIDER_CONFIG` - provider-config.yaml文件的路径（覆盖默认的`$CONFIG/subfinder/provider-config.yaml`）

## **安装**

`subfinder` 需要 **go1.24** 才能成功安装。运行以下命令安装最新版本：

```
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

了解更多安装subfinder的方法：https://docs.projectdiscovery.io/tools/subfinder/install

### **安装后说明**

`subfinder` 安装后即可使用，但许多源需要API密钥才能工作。了解更多：https://docs.projectdiscovery.io/tools/subfinder/install#post-install-configuration

### **运行Subfinder**

了解如何运行Subfinder：https://docs.projectdiscovery.io/tools/subfinder/running

### **Subfinder Go库**

Subfinder也可以作为库使用，使用subfinder SDK的最小示例可在[此处](https://www.qianwen.com/chat/examples/main.go)找到。

