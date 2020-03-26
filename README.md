## COVID-19 Malicious Domain List Importer

#### LogRhythm Labs | LogRhythm Office of the CISO | March 2020

A PowerShell script that automatically pulls the most recent list of malicious COVID-19-related domains and builds a list file for import within the LogRhythm SIEM.

**Available script options (PowerShell command line arguments/flags):**

`-OutputFilePath` (string): Set the final output path/folder for the generated domain list file. If not specified, this path defaults to: `C:\Program Files\LogRhythm\LogRhythm Job Manager\config\list_import`

`-TempDir` (string): Set the temporary/working directory path. The script will use this directory for storing temporary files prior to copying the final domain list file to the final output path/folder. If not specified, this path defaults to: `C:\Program Files\LogRhythm\LogRhythm Job Manager\config\covid_temp`

`-OutputFileName` (string): Set the file name for the generated domain list file. If not specified, this file name defaults to: `covid_domains.txt`

`-DoPrepend` (switch): If this switch/flag is enabled, each original covid domain entry will be prepended with each prefix specified in the `$prefixList` array in the script file, with each prepended variant then being added to the final output list. The default prefix list in the script includes `http://` and `https://`. If this switch/flag is not specified, no prepending will occur.