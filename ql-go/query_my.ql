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
