## CVE查询案例

### 一、CVE-2021-31856

#### 1、漏洞类型

SQL注入漏洞

go语言框架 meshery（云原生管理系统）

#### 2、执行查询

构建数据库：

```
codeql database create --language=go mehsery_database
```

命令行查询：

```
codeql database analyze mehsery_database --format=csv --output=1.csv codeql/go-queries
```

#### 3、查询结果

结果分析SQL注入结果：

| Database query built from user-controlled sources | Building a database query from user-controlled sources is vulnerable to insertion of malicious code by the user. | error | This query depends on a [["user-provided value"\|"relative:///handlers/meshery_pattern_handler.go:147:7:147:11"]]. | /models/meshery_pattern_persister.go | 35   | 24   | 35   | 28   |
| ------------------------------------------------- | ------------------------------------------------------------ | ----- | ------------------------------------------------------------ | ------------------------------------ | ---- | ---- | ---- | ---- |
|                                                   |                                                              |       |                                                              |                                      |      |      |      |      |

#### 4、编写QL规则查询

SQL内置规则QL单脚本查询：

codeql\go-queries\0.3.4\Security\CWE-089\SqlInjection.ql

```
/**
 * @name Database query built from user-controlled sources
 * @description Building a database query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

 import go
 import semmle.go.security.SqlInjection
 import DataFlow::PathGraph
 
 from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink.getNode(), source, sink, "This query depends on a $@.", source.getNode(),
   "user-provided value"
 
```

查看可能的攻击面：

```
/**
 * @name Database query built from user-controlled sources
 * @description Building a database query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

 import go
 import semmle.go.security.SqlInjectionCustomizations::SqlInjection

 from  DataFlow::Node source
 where 
    source instanceof Source
 select 
    source, source.getFile(), source.getStartLine()
 
```



自写一条SQL查询规则：

```
/**
 * @name Database query built from user-controlled sources
 * @description Building a database query from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id go/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import go
import DataFlow::PathGraph

class UserControlledRequestField extends UntrustedFlowSource::Range, DataFlow::FieldReadNode {
    UserControlledRequestField() {
      exists(string fieldName | this.getField().hasQualifiedName("net/http", "Request", fieldName) |
        fieldName =
          ["Body", "GetBody", "Form", "PostForm", "MultipartForm", "Header", "Trailer", "URL"]
      )
    }
  }
 
class GormSink extends SQL::QueryString::Range {
    GormSink() {
      exists(Method meth, string package, string name |
        meth.hasQualifiedName(package, "DB", name) and
        this = meth.getACall().getArgument(0) and
        package = Gorm::packagePath() and
        name in [
            "Where", "Raw", "Order", "Not", "Or", "Select", "Table", "Group", "Having", "Joins",
            "Exec", "Distinct", "Pluck"
          ]
      )
    }
  }

class MyConfiguration extends TaintTracking::Configuration {
    MyConfiguration() { this = "MyConfiguration" }

    override predicate isSource(DataFlow::Node source) { 
        source instanceof UserControlledRequestField
     }

    override predicate isSink(DataFlow::Node sink) { 
        sink instanceof GormSink
     }

}

from MyConfiguration mc, DataFlow::PathNode source, DataFlow::PathNode sink
where mc.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This query depends on a $@.", source.getNode(),
  "user-provided value"

```





