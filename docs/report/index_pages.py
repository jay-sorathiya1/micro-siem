"""Find the printed page number of every INDEX entry in the rendered PDF."""
import json, re, subprocess, sys
pdf, out = sys.argv[1], sys.argv[2]
n = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", pdf], capture_output=True, text=True).stdout).group(1))
heads = {"1.1": "1.1 PROJECT PROFILE", "1.2": "1.2 PROJECT DEFINITION", "2.1": "2.1 HARDWARE AND SOFTWARE SPECIFICATION",
         "2.2": "2.2 DEVELOPMENT DESCRIPTION", "3.1": "3.1 INTRODUCTION", "3.2": "3.2 SCOPE OF THE SYSTEM",
         "3.3": "3.3 OBJECTIVE OF THE SYSTEM", "3.4": "3.4 FUNCTIONALITY OF SYSTEM", "3.5": "3.5 EXPECTED OUTCOME",
         "4.1": "4.1 FEASIBILITY STUDY", "4.2": "4.2 SOFTWARE ENGINEERING MODEL", "4.3": "4.3 REQUIREMENT ANALYSIS AND DATA GATHERING",
         "4.4": "4.4 TIME LINE CHART", "5.1": "5.1 USE CASE DIAGRAM", "5.2": "5.2 CLASS DIAGRAM", "5.3": "5.3 ACTIVITY DIAGRAM",
         "5.4": "5.4 DEPLOYMENT DIAGRAM", "5.5": "5.5 DATABASE DESIGN", "6.1": "6.1 SOURCE CODE / SCREEN SHOTS",
         "7": "7. SYSTEM TESTING", "8": "8. CONCLUSION AND FUTURE SCOPE", "9": "9. BIBLIOGRAPHY", "1": "1. PROJECT DESCRIPTION"}
pages, first_body = {}, None
for i in range(1, n + 1):
    t = subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), "-layout", pdf, "-"], capture_output=True, text=True).stdout
    flat = re.sub(r"\s+", " ", t)
    for k, h in heads.items():
        if k not in pages and h in flat:
            pages[k] = i
pdf_first = pages.pop("1")
printed = {k: v - pdf_first + 1 for k, v in pages.items()}
missing = [k for k in heads if k != "1" and k not in printed]
print("chapter 1 on pdf page", pdf_first, "| missing:", missing)
print(printed)
json.dump(printed, open(out, "w"))
