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