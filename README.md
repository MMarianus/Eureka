# Eureka

<b>Introduction</b>

Eureka! is search tool that identifies mail artifacts, urls, email addresses and human language in files (mostly, in memory dumps). NOTE: To save the results into a file, please redirect the output..

<b>Usage</b> </br>
python eureka.py -f fileName.ext --ma --mails --urls --lang eng

<b>Help</b> </br>
-h, --help            show this help message and exit</br>
-f File_Name          File to analyze.</br>
--ma                  Will search Mails. (Raw output)</br>
--mails               Will search mail addresses.</br>
--urls                Will search URLs.</br>
--lang 'eng' [or] 'esp'
                      Identify human language in a given file. 'esp' for
                      spanish, 'eng' for english language identification.
                      Example: python eureka.py --lan eng pagefile.sys

