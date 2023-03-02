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
 