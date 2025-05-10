# r0idamcp

大模型驱动IDAPro智能自动化逆向体验单文件MCP服务器

> 交流学习：加vx：r0ysue（备注：进MCP学习群）

本项目的优点是：

- 功能集大成：集成市面已有项目的大部分功能，还会继续维护根据issue添加功能
- 依赖极少：只需要一个最新的FastMCP2.0，不需要复杂的uv及特定版本的python
- 兼容性强：支持所有MCP功能的大模型助手，无需科学上网配置复杂的依赖和环境，成功率极高
- 代码极简：市面项目大量采用嵌套代码生成工具，可读性极差。本项目浓缩到单文件，mcp.tool声明与实现一一对应，可读性极强，伸缩性和扩展性极佳


## 安装要求：

- uv：不需要
- python：不需要（使用IDA的python即可
- IDA Pro：推荐8.3以上，最好9
- 支持的MCP客户端：所有

## 安装方式：

1. IDA pro 正常安装使用，运行idapyswitch指定python路径。

2. 使用同路径的python安装好pip，使用pip安装fastmcp。

`pip install fastmcp`

3. 将r0idamcp.py文件拷贝到IDA插件目录下，插件目录如下：

|Windows|%appdata%\Hex-Rays\IDA Pro\plugins|
|:-:|:-:|
|Linux|~/.idapro/plugins/|
|macOS|~/Library/Application Support/IDA Pro/plugins/|

安装完毕！

## 使用流程：
    
1. 打开IDA主界面，下方python窗口有日志输出：

```
>>>r0mcp plugin loaded, use Edit->Plugins->r0mcp to start SSE server
```

2. 点击：编辑->插件->r0idamcp，开启MCPserver，日志如下：

```
>>> r0mcp.run() is invoked ,Server start
INFO:     Started server process [6804]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:26868 (Press CTRL+C to quit)
```

>如有提示访问局域网设备、请求局域网连接等等，一并允许；防火墙允许26868通过或关闭。如果IDA与大模型助手运行在同一台电脑，也可以将源码中的0.0.0.0改成127.0.0.1纯本地连接。

3. 大部分有MCP功能的大模型助手都会支持json配置文件配置：

```json
{
  "mcpServers": {
    "r0idamcp": {
      "url": "http://192.168.1.2:26868/sse",
      "type": "sse"
    }
  }
}
```

>192.168.1.2为IDA pro所在的电脑IP

假如使用的GUI界面配置，应选择添加SSE服务器，URL同上。配置成功检查连接状态时，IDA下方python窗口出现如下日志则为连接成功：

```
INFO:     192.168.1.3:62966 - "GET /sse HTTP/1.1" 200 OK
```

可以开始大模型驱动自动化逆向啦！

## 已有功能：

- `check_connection`: 确认正在运行
- `get_metadata()`: 获取IDB的元数据
- `get_function_by_name(name)`: 根据函数名获取函数
- `get_function_by_address(address)`: 根据函数地址获取函数
- `get_current_address()`: 获取当前选中的地址
- `get_current_function()`: 获取当前选中地址函数
- `convert_number(text, size)`: 十进制、十六进制互转
- `list_functions(offset, count)`: 分页列出IDB中的所有函数
- `list_strings(offset, count)`: 分页列出IDB中的所有字符串
- `search_strings(pattern, offset, count)`: 搜索字符串
- `decompile_function(address)`: 反编译指定地址函数至伪代码
- `disassemble_function(start_address)`: 反编译指定地址函数至机器码
- `get_xrefs_to(address)`: 列出指定地址的引用位置
- `get_entry_points()`: 列出数据库中所有的入口点
- `set_comment(address, comment)`: 指定地址添加注释
- `rename_local_variable(function_address, old_name, new_name)`: 函数内局部变量重命名
- `set_local_variable_type(function_address, variable_name, new_type)`: 指定局部变量类型
- `rename_global_variable(old_name, new_name)`: 全局变量重命名
- `set_global_variable_type(variable_name, new_type)`: 指定全局变量类型
- `rename_function(function_address, new_name)`: 函数重命名
- `set_function_prototype(function_address, prototype)`: 指定函数原型
- `declare_c_type(c_declaration)`: 根据C的声明创建或更新局部变量类型

为了达到最为准确的执行效果，提示词尽可能采用我的中文翻译（或函数名），提高命中率。

抓紧玩起来吧宝子们！有问题欢迎群里反馈！根据反馈修复或更新功能～

## Thanks：

- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)
- [taida957789/ida-mcp-server-plugin](https://github.com/taida957789/ida-mcp-server-plugin)
- [fdrechsler/mcp-server-idapro](https://github.com/fdrechsler/mcp-server-idapro )
- [MxIris-Reverse-Engineering/ida-mcp-server](https://github.com/MxIris-Reverse-Engineering/ida-mcp-server)