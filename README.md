# Eureka

<b>Introduction</b>

Eureka! is search tool that identifies Facebook Chats, Emails, URLs, Email Addresses and Human Language in very, very large files (mostly, in memory dumps). NOTE: To save the results into a file, please redirect the output..

<b>Usage</b> </br>
python eureka.py -f fileName.ext --fb --je --mails --urls --lang eng

<b>Help</b> </br>
-h, --help            show this help message and exit</br>
-f File_Name          File to analyze.</br>
--je                  JSON Emails Search. (Raw output)</br>
--mails               Mail Addresses search.</br>
--urls                URLs search.</br>
--fb                Facebook chats search.</br>
--lang 'eng' [or] 'esp'
                      Identify human language in a given file. 'esp' for
                      spanish, 'eng' for english language identification.
                      Example: python eureka.py -f pagefile.sys --lan eng

