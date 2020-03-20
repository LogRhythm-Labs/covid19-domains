param(
    [Parameter()][string]$OutputFilePath,
    [Parameter()][string]$OutputFileName
)

# ================= COVID-19 Malicious Domain List Importer PowerShell Script =================
#
# A PowerShell script that automatically pulls the latest copy of a list of recent malicious COVID-19-related domains and builds a list file for import within the LogRhythm SIEM
#
# Copyright March 2020 - LogRhythm Labs/LogRhythm Office of the CISO - LogRhythm, Inc. 

# ======= Example usage:

# If no custom output file path and file name are specified, the script will write the output file to the default LR list auto import directory

# PS> covid19_domains.ps1 -OutputFileName "covid_custom_list_name.txt"
# PS> covid19_domains.ps1 -OutputFilePath "C:\Users\zack.rowland\Documents\lists" -OutputFileName "covid_test_list.txt"

# ======= Globals/Parameters/Etc.

# Default path and filename for the LR list file that we'll create (used if no args specified)
$outListFile = "C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import"
$outListFileName = "covid_domains.txt"

if ($OutputFilePath -ne "")
{
    $outListFile = $OutputFilePath
}

if ($OutputFileName -ne "")
{
    $outListFileName = $OutputFileName
}

$outputFullPath = [System.IO.Path]::Combine($outListFile,$outListFileName)

# ======= Pull XML File, find latest CoVid list

$uri = 'https://covid-public-domains.s3-us-west-1.amazonaws.com/'
$xmld = Invoke-RestMethod -Method Get -Uri $uri -SessionVariable sv -ErrorAction Ignore
$xmlroot = $xmld.DocumentElement
$dateNow = [System.DateTime]::Now
$dateLatest = [System.DateTime]::MinValue
$covidLatest = "none"
foreach ($c in $xmlroot.Contents)
{
    if ($c.Key -match "covid.*")
    {
        $tmpCoName = $c.Key
        $tmpDateStr = $c.LastModified
        $tmpDate = [System.DateTime]::Parse($tmpDateStr)
        if ($tmpDate -gt $dateLatest)
        {
            $dateLatest = $tmpDate
            $covidLatest = $tmpCoName
        }
    }
}

Write-Host -ForegroundColor Green "Found latest covid domain file: ${dateLatest}: ${covidLatest}"

if ($covidLatest -eq "none")
{
    Write-Error "Unable to find any file listings in XML file!"
    return 1
}

$latestUri = $($uri + $covidLatest)

$respCovidFile = Invoke-WebRequest -Uri $latestUri -Method Get -OutFile "./${covidLatest}" -ErrorAction Ignore

# To do: Need to add error handling here in case web req fails

$csv = Import-Csv -Path "./${covidLatest}"

# Test filter that also only outputs domains with "flu" in the name; generates a much shorter list, helpful for testing purposes
#$covidEntries = $($csv | Where { $_.Query -ne "virus" -and $_.Match -match "flu" } | Select -Unique Match)

$covidEntries = $($csv | Where { $_.Query -ne "virus" } | Select -Unique Match)

$covidList = New-Object System.Collections.Generic.List[string]

foreach ($entry in $covidEntries)
{
    $entryMain = $entry.Match
    $entryMod1 = $("http://" + $entryMain)
    $entryMod2 = $("https://" + $entryMain)
    $covidList.Add($entryMain)
    $covidList.Add($entryMod1)
    $covidList.Add($entryMod2)
}

Write-Host -ForegroundColor Green "Completed building domain list"

# Delete old list
[System.IO.File]::Delete($outputFullPath)

foreach ($cl in $covidList)
{
    echo $cl >> $outputFullPath
}

Write-Host -ForegroundColor Green "Wrote LR list text file to: ${outputFullPath}"
Write-Host -ForegroundColor Green "Done!"