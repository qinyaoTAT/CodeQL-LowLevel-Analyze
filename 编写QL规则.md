## 编写QL规则

[TOC]

### 一、如何查询

1、创建数据库

```
 codeql database create example_database --language=python --source-root=example
```

2、执行查询

命令行执行：

```
codeql database analyze .\example_database --format=csv --output=1.csv codeql/python-queries
```

VSCODE插件：

- 导入数据库
- 执行查询
- 结果查看

### 二、基本语法

查询文件扩展名`.ql`

查询套件 `.qls`

查询库文件 `.qll`

预编译查询文件 `.qlx`

```codeql
/**
 *
 * Query metadata
 *
 */

import /* ... CodeQL libraries or modules ... */

/* ... Optional, define CodeQL classes and predicates ... */

from /* ... variable declarations ... */
where /* ... logical formula ... */
select /* ... expressions ... */
```



### 三、过程内分析

单个函数内代码数据流

1、本地数据流

```python
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

from DataFlow::CallCfgNode call, DataFlow::ParameterNode p
where
  call = API::moduleImport("os").getMember("open").getACall() and
  DataFlow::localFlow(p, call.getArg(0))
select call, p
```



2、本地污点分析

与数据流分析的主要区别：污点分析能够识别值传递节点

```python
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

from DataFlow::CallCfgNode call, DataFlow::ParameterNode p
where
  call = API::moduleImport("os").getMember("open").getACall() and
  TaintTracking::localTaint(p, call.getArg(0))
select call, p
```





### 四、过程间分析

跨函数、跨类、跨文件的数据流


1、全局数据流

```
/**
 * @name cmd query built from env sources
 * @description Building a SQL query from env sources is vulnerable to insertion of
 *              malicious exec code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/cmd-injection
 * @tags security
 *       external/cwe/cwe-111
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs


class MyDataFlowConfiguation  extends DataFlow::Configuration {
    MyDataFlowConfiguation () { this = "MyDataFlowConfiguation " }
  
    override predicate isSource(DataFlow::Node source) {
        source = API::moduleImport("os").getMember("getenv").getACall()
    }
  
    override predicate isSink(DataFlow::Node sink) {
        exists(DataFlow::CallCfgNode call |
            call = API::moduleImport("subprocess").getMember("call").getACall() and
            sink = call.getArg(0)
        ) or
        exists(DataFlow::CallCfgNode call |
              call = API::moduleImport("os").getMember("system").getACall() and
              sink = call.getArg(0)
            ) 
      }
    }

from MyDataFlowConfiguation dataflow, DataFlow::Node source, DataFlow::Node sink
where dataflow.hasFlow(source, sink)
select source, "Data flow to $@.", sink, sink.getLocation()
```



2、全局污点分析

```
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

class EnvironmentToCallConfiguration extends TaintTracking::Configuration {
    EnvironmentToCallConfiguration() { this = "EnvironmentToCallConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source = API::moduleImport("os").getMember("getenv").getACall()
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("subprocess").getMember("call").getACall() and
      sink = call.getArg(0)
    ) or
    exists(DataFlow::CallCfgNode call |
        call = API::moduleImport("os").getMember("system").getACall() and
        sink = call.getArg(0)
      ) 
  }
}


from DataFlow::Node source, DataFlow::Node sink, EnvironmentToCallConfiguration config
where config.hasFlow(source, sink)
select sink, "This call to 'call' uses data from $@.",
source, "call to 'os.getenv'"
```

