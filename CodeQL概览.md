## CodeQL概览

[TOC]

### 一、开源部分

开源部分为QL语言查询库，可以进行QL规则编写，进行漏洞挖掘等

github源码地址：https://github.com/github/codeql

官方使用教程：https://codeql.github.com/docs/

相关目录结构：

- 根目录：

  - 配置目录

  - 文档：感兴趣可以都看看

  - 各种语言的查询库：进入特定语言的目录查看，例如Python目录

    - 文档目录

    - 配置目录

    - tools：部分语言存在，辅助工具等

    - ql库目录：每种语言的主要查询库，集成大量内置规则

      - lib库：标准查询库，提供了编写ql语言的大量库，比如数据流、source点、sink点、API图等

        例如内置的Source和sink：

        ![image-20230106111021954](D:\git\CodeQL-LowLevel-Analyze\img\image-20230106111021954.png)

      - src：内置ql规则库，包含有限的安全类和非安全类规则

        例如CWE关联规则(ql/src/Security)：

        ![image-20230106110911016](D:\git\CodeQL-LowLevel-Analyze\img\image-20230106110911016.png)

        

    - tools：一些辅助工具

    - 其他目录：略



### 二、未开源部分

codeql-cli-binaries：CodeQL命令行执行工具，数据库创建、数据库查询等

github下载地址：https://github.com/github/codeql-cli-binaries

官方使用教程：https://codeql.github.com/docs/

相关目录结构：

-  执行入口：codeql（Linux）\codeql.exe（Windows)
  - 详细执行流程分析参考：https://paper.seebug.org/1921/
  - codeql整个调度流程是JAVA语言编写
- 具体语言目录：以Python举例
  - tools：提取器
    - 自动构建脚本
    - xxx.zip：提取器源码，可以解压调试分析，可以发现是生成trap文件的
  - 其他配置：略
