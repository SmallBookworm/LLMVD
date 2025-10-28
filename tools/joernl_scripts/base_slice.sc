import io.joern.dataflowengineoss.language._
import io.shiftleft.codepropertygraph.generated.nodes
import io.shiftleft.semanticcpg.language._

// 使用正则直接匹配危险函数名（避免手动函数判断）
val DANGEROUS_SINKS_REGEX = ".*(system|execv|execvp|popen|strcpy|strcat|memcpy|sprintf|vsprintf|printf|fprintf|snprintf|vprintf|eval|assert).*"

@main
def mainAnalysis(): Unit = {
  // Source: 所有函数的输入参数
  val sources = cpg.method.head.parameter

  // Sink: 匹配危险函数调用
  val sinks = cpg.call.name(DANGEROUS_SINKS_REGEX)

  // 执行污点流分析
  val flows = sinks.reachableByFlows(sources).l

  // 构建 JSON 结果
  val results = flows.map { flow =>
    val source = flow.elements.head
    val sink = flow.elements.last.asInstanceOf[nodes.Call]

    // 获取 source 所属函数名
    val sourceFuncName = source match {
      case p: nodes.MethodParameterIn => p.method.name
      case _ => "<unknown>"
    }

    val sinkLoc = sink.location

    ujson.Obj(
      "sourceFunction" -> sourceFuncName,
      "sourceParameter" -> source.code,
      "sinkFunction" -> sink.name,
      "sinkFile" -> sinkLoc.filename,
      "sinkLine" -> sinkLoc.lineNumber.getOrElse(-1),
      "path" -> ujson.Arr(
        flow.elements.map { node =>
          val loc = node.location
          ujson.Obj(
            "code" -> node.code,
            "file" -> loc.filename,
            "line" -> loc.lineNumber.getOrElse(-1)
          )
        }
      )
    )
  }
  println("Json:")
  println(ujson.Arr(results: _*).render(indent = 2))
}