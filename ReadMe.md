# Nmap AutoScan

AutoScan是基于python-nmap和Nmap开发的自动化扫描脚本（可以算得上三次开发了（笑））

其主要目的是通过多进程进行更快速的多目标多端口（强调端口数目较多，比如全端口）扫描，其中实现了异步数据写入、中断恢复等功能。

关于多进程使用Nmap的必要性，见 https://www.cnblogs.com/yc0806/p/15106994.html

需要说明的是，脚本中的中断恢复功能的实际意义和可用性未经可靠的理论论证和实践验证，使用前请做好相应准备，同时欢迎指导和反馈。

注意，在内网中使用时，需要将connection_check函数中的“8.8.8.8”修改为网关地址来确认本机和目标网络的连通性。

# 使用说明

由于是简单的实验版本，扫描所需的所有参数都需要在脚本内修改，暂不提供外部参数输入。

## 目标输入

### 目标地址

```
f = open("target.txt","r")
```

脚本从target.txt中读入目标的地址，用换行符（\n）分隔。建议以单个地址的形式书写目标，而非以网段的形式。

### 目标端口

```
port_chunks = ["0-10000","10001-20000","20001-30000","30001-40000","40001-50000","50001-60000","60001-65535"]
```

脚本主要用于多目标多端口扫描。为了减少中断和重试的成本，在扫描时采用分段扫描的形式（如上是全端口扫描按10000端口为一段分隔）进行，也用单个端口段形式定义不进行分段扫描，如下：

```
port_chunks = ["0-65535"]
```

需要说明的是，为了避免多个进程对同一目标进行扫描，端口段之间串行的。

## 结果输出

```
output_file= "scandata_"+time.strftime("%Y%m%d%H%M%S")+".csv"
```

扫描结果以csv的形式输出，格式如下：

| host     | hoststate | protocol | port | portstate | name |
| -------- | --------- | -------- | ---- | --------- | ---- |
| 10.0.2.2 | up        | tcp      | 25   | open      | smtp |
| 10.0.2.2 | up        | tcp      | 110  | open      | pop3 |
| 10.0.2.3 | down      |          |      |           |      |
| 10.0.2.4 | slow      |          |      |           |      |

其中，hoststate为**down**表示该主机关闭（不回应Ping包），hoststate为**slow**表示对该主机的扫描超时（超时设置见下文）

## 扫描设置

```
nm = nmap.PortScanner()
nm.scan(hosts=target,ports=port_chunk,arguments="-sT -T3",timeout=600)
```

扫描的执行主要使用的python-nmap库，参数调整见作者博客 http://xael.org/pages/python-nmap-en.html

对timeout的设置可以避免在慢速主机上消耗过多的时间，注意timeout是对于单个主机单个地址段定义的，请根据自身的任务量和网络情况设置。


