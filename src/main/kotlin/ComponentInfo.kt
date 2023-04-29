package com.darblee.project

import java.io.PrintWriter

class ComponentInfo(val componentName: String) {
    var cveList: Array<CVEinfo> = arrayOf()
    var criticalCount: Int = 0
    var highCount: Int = 0
    var mediumCount: Int = 0
    var lowCount: Int = 0

    fun printTextComponentInfo(out: PrintWriter, printDetail: Boolean, longestComponentNameLength: Int) {
        if (!printDetail) {
            out.print(componentName)
            repeat((longestComponentNameLength - componentName.length)) { out.print(" ") }
            val myStr =
                String.format(" %4s %4s %4s %4s\n", this.criticalCount, this.highCount, this.mediumCount, this.lowCount)
            out.print(myStr)
        } else {
            out.println("=============================")
            out.println("Container Image: $componentName")
            out.println("  Critical: ${this.criticalCount}")
            out.println("  High:     ${this.highCount}")
            out.println("  Medium:   ${this.mediumCount} ")
            out.println("  Low:      ${this.lowCount}")
            out.println()
            out.println("Package                                       CVE ID              Severity")
            out.println("--------------------------------------------- ------------------  -------")
            cveList.forEach { it.printCVEInfo(out) }
            out.println()
        }
    }
}
