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