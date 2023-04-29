package com.darblee.project
import java.io.File
import java.io.PrintWriter

var AllAvailableCVERanges: Array<CVErange> = arrayOf()
var TotalCriticalCount: Int = 0
var TotalHighCount: Int = 0
var TotalMediumCount: Int = 0
var TotalLowCount: Int = 0

/*
 * Main program
 */
fun main() {
    scanCVEDirectory()

    AllAvailableCVERanges.forEach { curCVERange ->
        curCVERange.buildTextReport()
        curCVERange.buildHTMLReport()
    }

    processAllContinuousCVERangeReports()
}

/*
 * Scan the "input" directory and look for all the "CVE range" directories.
 *  A CVE range directory is defined by the format "<reference-release>-to-<target-release>"
 * where the release has the format "<major>_<minor>_<patch>". Each release major/minor/patch entry
 * is only 1 digit (0 - 9).
 */
private fun scanCVEDirectory() {
    File("input" + File.separator).list()?.forEach { currentDirName ->

        val currentDirEntry = File("input" + File.separator + currentDirName)

        // Do not continue if this is not a directory
        if (!(currentDirEntry.isDirectory))
            return@forEach

        val range = CVErange(currentDirEntry)

        if (range.validRange) {
            AllAvailableCVERanges += range

            TotalCriticalCount += range.totalCriticalCountInCVERange
            TotalHighCount += range.totalHighCountInCVERange
            TotalMediumCount += range.totalMediumCountInCVERange
            TotalLowCount += range.totalLowCountInCVERange
        }
    }

    var index = 0
    AllAvailableCVERanges.forEach { currentCVERange ->
        println("[$index]   Source: ${currentCVERange.referenceRelease} Target: ${currentCVERange.targetRelease}")
        index++
    }
}

/*
 * Look for all possible continuous CVE ranges and generate a html-based summary table report.
 *
 * For example, if there ia CVE range 5.0-5.1 and 5.1-5.2, then this routine will generate
 * a total summary report of 5.0-5.2 combined.
 */
fun processAllContinuousCVERangeReports() {
    for(curStartingIndex in AllAvailableCVERanges.indices) {
        var nextIndex = curStartingIndex
        var lastIndex = curStartingIndex + 1

        while (nextIndex < (AllAvailableCVERanges.size - 1)) {
            val nextTargetRelease = AllAvailableCVERanges[nextIndex].targetRelease
            val lastRefRelease = AllAvailableCVERanges[lastIndex].referenceRelease

            if (nextTargetRelease != lastRefRelease)  break

            // We have a chained link
            generateContinuousCVERangeReport(curStartingIndex, lastIndex)

            nextIndex++
            lastIndex++
        }
    }
}

/*
 * Generate one continuous CVE ranges report. Just add total of one cve range to the current total.
 * Generate a html-based summary table report with the combined total.
 */
fun generateContinuousCVERangeReport(startIndex: Int, lastIndex: Int)
{
    println("Generate chain report for from $startIndex to $lastIndex")

    var totalCritical = AllAvailableCVERanges[startIndex].totalCriticalCountInCVERange
    var totalHigh = AllAvailableCVERanges[startIndex].totalHighCountInCVERange
    var totalMedium = AllAvailableCVERanges[startIndex].totalMediumCountInCVERange
    var totalLow = AllAvailableCVERanges[startIndex].totalLowCountInCVERange

    var curIndex = startIndex + 1
    while (curIndex <= lastIndex) {
        totalCritical += AllAvailableCVERanges[curIndex].totalCriticalCountInCVERange
        totalHigh += AllAvailableCVERanges[curIndex].totalHighCountInCVERange
        totalMedium += AllAvailableCVERanges[curIndex].totalMediumCountInCVERange
        totalLow += AllAvailableCVERanges[curIndex].totalLowCountInCVERange

        curIndex++
    }

    // Generate html report
    val startingRelease = AllAvailableCVERanges[startIndex].referenceRelease
    val lastRelease = AllAvailableCVERanges[lastIndex].targetRelease
    val htmlFileName = "Summary-from-${startingRelease.replace('.', '_')}-to-${lastRelease.replace('.', '_')}.html"

    File(htmlFileName).printWriter().use { out ->
        printHTMLHeaderSpanningCVERanges(out, startingRelease, lastRelease)
        printHTMLBodySpanningCVERanges(out, startIndex, lastIndex)
        printHTMLendSpanningCVERanges(out)
        println("File \"$htmlFileName\" generated")
    }
}

fun printHTMLHeaderSpanningCVERanges(out: PrintWriter, startingRelease: String, targetRelease: String) {
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
        <h1>Overall CVE Fixed Report</h1>
        <p>CVE fixes between $startingRelease and $targetRelease</p>
        <p>
        <hr>
        """.trimIndent()
    )
}

fun printHTMLBodySpanningCVERanges(out: PrintWriter, startIndex: Int, lastIndex: Int ) {
    // Print the body
    out.println(
        """
        <table border = "2" cellpadding = "5">
          <tr bgcolor="#DCDCDC">
            <th rowspan="2" style="font-size: 23px">Release Range</th>
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

    var totalCritical = 0
    var totalHigh = 0
    var totalMedium = 0
    var totalLow = 0

    var curIndex = startIndex

    while (curIndex <= lastIndex) {

        val curCVERangeStartRelease = AllAvailableCVERanges[curIndex].referenceRelease
        val curCVERangeTargetRelease = AllAvailableCVERanges[curIndex].targetRelease

        val curTotalCritical = AllAvailableCVERanges[curIndex].totalCriticalCountInCVERange
        val curTotalHigh = AllAvailableCVERanges[curIndex].totalHighCountInCVERange
        val curTotalMedium = AllAvailableCVERanges[curIndex].totalMediumCountInCVERange
        val curTotalLow = AllAvailableCVERanges[curIndex].totalLowCountInCVERange

        out.println("<tr>")
        out.println("    <td>Between ERE $curCVERangeStartRelease and ERE $curCVERangeTargetRelease</td>")
        out.println("    <td>${curTotalCritical}</td>")
        out.println("    <td>${curTotalHigh}</td>")
        out.println("    <td>${curTotalMedium}</td>")
        out.println("    <td>${curTotalLow}</td>")
        out.println("</tr>")

        totalCritical += AllAvailableCVERanges[curIndex].totalCriticalCountInCVERange
        totalHigh += AllAvailableCVERanges[curIndex].totalHighCountInCVERange
        totalMedium += AllAvailableCVERanges[curIndex].totalMediumCountInCVERange
        totalLow += AllAvailableCVERanges[curIndex].totalLowCountInCVERange

        curIndex++
    }

    out.println("<tr>")
    out.println("     <td><b>TOTAL</b></td>")
    out.println("     <td><b>$totalCritical</b></td>")
    out.println("     <td><b>$totalHigh</b></td>")
    out.println("     <td><b>$totalMedium</b></td>")
    out.println("     <td><b>$totalLow</b></td>")
    out.println("</tr>")

    out.println("</table>")
    out.println("<p>")
    out.println("<hr>")
}

fun printHTMLendSpanningCVERanges(out: PrintWriter) {
    // Print the html ending
    out.println(
        """
                    
        </body>
        </html>
        """.trimIndent()
    )
}