package com.darblee.project

import java.io.PrintWriter

/*
 * Class to process CVE fixed data
 */
class CVEinfo(val pkg: String, val cveid: String, val severity: String) {
    fun printCVEInfo(out: PrintWriter) {
        val myStr = String.format("%-45s %-20s %-8s\n", pkg, cveid, severity)
        out.print(myStr)
    }
}