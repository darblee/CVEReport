package com.darblee.project

import java.io.File
import java.io.PrintWriter

class CVErange(private val cveDirectory: File) {
    var validRange = false
    var referenceRelease: String = ""
    var targetRelease: String = ""

    private var componentList: Array<ComponentInfo> = arrayOf()

    var totalCriticalCountInCVERange: Int = 0
    var totalHighCountInCVERange: Int = 0
    var totalMediumCountInCVERange: Int = 0
    var totalLowCountInCVERange: Int = 0

    // This variable is used for nice proper spacing format output for ASCII report
    private var longestComponentNameLength: Int = 0

    init {
        val dirName = cveDirectory.name
        val regex = Regex(pattern = "\\d_\\d_\\d-to-\\d_\\d_\\d", options = setOf(RegexOption.IGNORE_CASE))

        if (dirName.contains(regex)) {
            referenceRelease = dirName.substring(0, 5).replace('_', '.')
            targetRelease = dirName.substring(9, 14).replace('_', '.')

            validRange = true
            processAllComponentFiles()
        } else {
            validRange = false
        }
    }

    /*
     * Process all the *.csv files in this directory
     */
    private fun processAllComponentFiles() {
        println("Parsing directory \"$cveDirectory\"....")

        cveDirectory.listFiles()?.forEach {
            val fileObject: File = it.canonicalFile

            if (fileObject.isFile) {
                // Only process file with the filename format *.csv
                if (fileObject.toString().substringAfter(".").contains("csv")) {
                    if (fileObject.toString().substringBefore(".").contains(("Images with serious defects"))) {
                        println("   Ignoring file: \"$fileObject\"")
                    } else {
                        processComponentFile(fileObject)
                    }

                } else {
                    println("   Ignoring file: \"$fileObject\"")
                }
            }
        }
        return
    }

    /*
     * Process the <component>.csv file.
     */
    private fun processComponentFile(csvFile: File) {
        val componentName: String = (csvFile.toString().substringAfterLast("\\")).substringBefore(".csv")

        if (componentName.length > longestComponentNameLength) longestComponentNameLength = componentName.length

        var currentLineIndex = 0
        val componentEntry = ComponentInfo(componentName = componentName)

        componentList += componentEntry

        csvFile.readLines().forEach { currentRawLine ->
            var line: String = currentRawLine

            currentLineIndex++

            // Skip the first line
            if (currentLineIndex == 1) {
                // Need to do a string comparison of the header line
                if (!(line.contains("Package,CVE String,Severity"))) {
                    error("Got unexpected first line header. Expect to see ===  Package,CVE String,Severity")
                }
                return@forEach
            }

            // Need to tokenize each line
            // If we have a "," at the end of the string, then we do not want to make a null item
            if (line.endsWith(",")) {
                line = line.substring(0, line.length - 1)
            }

            // Use trim() to delete spaces around the strings (if exist)
            val lstValues: List<String> = line.split(",").map { it.trim() }

            if (lstValues.size != 3) error("Got unexpected number of tokens. Expecting 3, but it has ${lstValues.size}")

            val pkg: String = lstValues[0]
            val cveid: String = lstValues[1]
            val severity: String = lstValues[2]

            val entry = CVEinfo(pkg = pkg, cveid = cveid, severity = severity)
            componentEntry.cveList = componentEntry.cveList + entry

            if (severity.contains("Critical")) componentEntry.criticalCount++
            if (severity.contains("High")) componentEntry.highCount++
            if (severity.contains("Medium")) componentEntry.mediumCount++
            if (severity.contains("Low")) componentEntry.lowCount++
        }

        totalCriticalCountInCVERange += componentEntry.criticalCount
        totalHighCountInCVERange += componentEntry.highCount
        totalMediumCountInCVERange += componentEntry.mediumCount
        totalLowCountInCVERange += componentEntry.lowCount
    }


    // Build ASCII text based CVE fixed report
    fun buildTextReport() {
        val fixedReportFileName =
            "CVE-fixed-${referenceRelease.replace('.', '_')}-to-${targetRelease.replace('.', '_')}.txt"
        val file = File(fixedReportFileName)
        file.delete() // Delete the previous file if it exists

        File(fixedReportFileName).printWriter().use { out ->
            out.println("========================================")
            out.println("HPE Ezmeral Runtime Enterprise")
            out.println("CVE Fixed Report for $targetRelease")
            out.println("Total # of components: " + componentList.size)
            out.println(" Total # of Critical: $totalCriticalCountInCVERange")
            out.println(" Total # of High: $totalHighCountInCVERange")
            out.println(" Total # of Medium: $totalMediumCountInCVERange")
            out.println(" Total # of Low: $totalLowCountInCVERange")
            repeat(longestComponentNameLength) { out.print("=") }

            out.println("========================================")
            out.print("Component")
            repeat((longestComponentNameLength - "Component".length)) { out.print(" ") }
            out.println(" Crit High Med  Low")
            repeat(longestComponentNameLength) { out.print("-") }
            out.println(" ---- ---- ---- ----")
            componentList.forEach { it.printTextComponentInfo(out, false, longestComponentNameLength) }
            out.println("")

            out.println("\n\n============ DETAILS =========================\n")
            componentList.forEach { it.printTextComponentInfo(out, true, longestComponentNameLength) }

            println("File \"$fixedReportFileName\" generated")
        }
    }

    // Build HTML-based CVE fixed report
    fun buildHTMLReport() {
        val htmlFixedReportFileName =
            "CVE-fixed-${referenceRelease.replace('.', '_')}-to-${targetRelease.replace('.', '_')}.html"

        val file = File(htmlFixedReportFileName)
        file.delete() // Delete the previous file if it exists

        File(htmlFixedReportFileName).printWriter().use { out ->
            printHTMLHeader(out, referenceRelease, targetRelease)
            printHTMLComponentSummary(out)
            printHTMLComponentDetails(out)
            printHTMLend(out)
            println("File \"$htmlFixedReportFileName\" generated")
        }
    }

    // Print HTML header content
    private fun printHTMLHeader(out: PrintWriter, referenceRelease: String, currentRelease: String) {
        // Print the html beginning
        out.println(
            """
        <!DOCTYPE html>
        <html>
        <head>
        <style>
        body {
          background-color: white;
        }
        
        h1 {
          color: black;
          text-align: left;
        }
        
        h2 {
          color: black;
          text-align: left;
          margin-bottom:1px;
        }
        
        h3 {
          color: black;
          text-align: left;
          margin-bottom:1px;
        }
        
        p {
          font-family: verdana;
          font-size: 20px;
          margin-top:1px;
        }
        
        ul {
                margin-top:1px;
           }
        </style>
        </head>
        <body>
        <img src="hpe.jpg" alt="HPE" width="200" height="100">
        <h1>HPE Ezmeral Runtime Enterprise </h1>
        <h1>CVE Fixed Report for $currentRelease</h1>
        <p>CVE fixes between $referenceRelease and $currentRelease</p>
        <p>
        <hr>
        """.trimIndent()
        )
    }

    // Print Component Summary in html format
    private fun printHTMLComponentSummary(out: PrintWriter) {
        // Print the body
        out.println("<h2>Component Summary</h2>")
        out.println(
            """
        <table border = "2" cellpadding = "5">
          <tr bgcolor="#DCDCDC">
            <th rowspan="2" style="font-size: 23px"><img src="component-new.jpg" alt="component"/>Component</th>
            <th colspan="4"><img src="severity-new.jpg" alt="severity"/> Severity</th>
          </tr>
          <tr bgcolor="#DCDCDC">
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
          </tr>
         """.trimIndent()
        )

        componentList.forEach {curComponentInfo ->
            out.println("<tr>")
            out.println("    <td><a href=\"#${curComponentInfo.componentName}\">${curComponentInfo.componentName}</a></td>")
            out.println("    <td>${curComponentInfo.criticalCount}</td>")
            out.println("    <td>${curComponentInfo.highCount}</td>")
            out.println("    <td>${curComponentInfo.mediumCount}</td>")
            out.println("    <td>${curComponentInfo.lowCount}</td>")
            out.println("</tr>")
        }
        out.println("<tr>")
        out.println("     <td><b>TOTAL</b></td>")
        out.println("     <td><b>$totalCriticalCountInCVERange</b></td>")
        out.println("     <td><b>$totalHighCountInCVERange</b></td>")
        out.println("     <td><b>$totalMediumCountInCVERange</b></td>")
        out.println("     <td><b>$totalLowCountInCVERange</b></td>")
        out.println("</tr>")

        out.println("</table>")
        out.println("<p>")
        out.println("<hr>")
    }

    // Print Component Detail table in html format
    private fun printHTMLComponentDetails(out: PrintWriter) {
        out.println("<h2>Component Details</h2>")
        componentList.forEach { componentEntry ->
            out.println("<h3 id=\"${componentEntry.componentName}\">Component : ${componentEntry.componentName}</h3>")
            out.println("<ul>")
            out.println("<li>Critical : ${componentEntry.criticalCount} </li>")
            out.println("<li>High : ${componentEntry.highCount} </li>")
            out.println("<li>Medium : ${componentEntry.mediumCount} </li>")
            out.println("<li>Low : ${componentEntry.lowCount} </li>")
            out.println("</ul>")

            out.println(
                """
            <table border = "2" cellpadding = "5">
              <tr bgcolor="#DCDCDC">
                <th align="left"><img src="container-new.jpg" alt"pkg"/> Package</th>
                <th align="left"><img src="cve-bug-new.jpg" alt="cve"/> CVE ID</th>
                <th align="left"><img src="severity-new.jpg" alt="severity"/> Severity</th>
              </tr>
            """.trimIndent()
            )
            var footNoteNeeded = false

            componentEntry.cveList.forEach { cveinfo ->
                if (cveinfo.severity.contains("Critical")) {
                    out.println("<tr bgcolor=#CD6155>")
                } else if (cveinfo.severity.contains("High")) {
                    out.println("<tr bgcolor=#F5B7B1>")
                } else if (cveinfo.severity.contains("Medium")) {
                    out.println("<tr bgcolor=#F9E79F>")
                } else {
                    out.println("<tr>")
                }
                out.println("    <td>${cveinfo.pkg}</td>")

                if (cveinfo.cveid.startsWith("CVE-")) {
                    val hrefString: String = "https://nvd.nist.gov/vuln/detail/" + cveinfo.cveid
                    out.println("    <td><a href = \"$hrefString\" target = \"_blank\"> ${cveinfo.cveid}</a></td>")
                } else if (cveinfo.cveid.startsWith("PRISMA-")) {
                    // TODO: CHeck to see if Palo Alto provide clarity on PRISMA-<ID>. We need to update info in html table report
                    // val hrefString: String = "https://nvd.nist.gov/vuln/detail/CVE" + it.cveid.substring("PRISMA".length)
                    // out.println("    <td><a href = \"$hrefString\" target = \"_blank\"> ${it.cveid}</a></td>")
                    out.println("    <td>${cveinfo.cveid}<sup>&dagger;1</sup></td>")
                    footNoteNeeded = true
                } else if (cveinfo.cveid.startsWith("GHSA-")) {
                    val hrefString: String = "https://github.com/advisories/" + cveinfo.cveid
                    out.println("    <td><a href = \"$hrefString\" target = \"_blank\"> ${cveinfo.cveid}</a></td>")
                } else {
                    out.println("    <td>${cveinfo.cveid}</td>")
                }

                out.println("    <td>${cveinfo.severity}</td>")
                out.println("</tr>")
            }
            out.println("</table>")

            if (footNoteNeeded) {
                out.println(
                    """
                <p margin-top:1px>
                <font size="-2">
                <em>&dagger;1</em>
                - PRISMA-*ID is not the same vulnerability as CVE-*ID. See
                <a href="https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin-compute/vulnerability_management/prisma_cloud_vulnerability_feed"
                target="_blank" rel="noopener noreferrer">
                PRISMA vulnerability
                </a>
                for more info.
                </font>
                </p>                         
                """.trimIndent()
                )
            }
        }
    }

    // Print HTML ending section
    private fun printHTMLend(out: PrintWriter) {
        // Print the html ending
        out.println(
            """
                    
        </body>
        </html>
        """.trimIndent()
        )
    }
}