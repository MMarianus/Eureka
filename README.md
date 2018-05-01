# Eureka - The Forensics OpenSource Tool

<b>Introduction</b>

Eureka is a digital forensics open source search tool that identifies Facebook Chats, Emails, URLs, Email Addresses and Human Language in very, very large files (mostly, in memory dumps). NOTE: To save the results into a file, please remember to redirect the output to a file..

<b>Usage</b> </br>
For full detection, just run: python eureka.py -f fileName.ext --fb --je --mails --urls --lang eng

<b>Help:</b> 
<table style="width: 75%; float: left;">
<tbody>
<tr>
<td style="width: 32.7107%;"><strong>Parameter</strong></td>
<td style="width: 62.2893%;"><strong>Explanation</strong></td>
</tr>
<tr>
<td style="width: 32.7107%;">-h, --help</td>
<td style="width: 62.2893%;"><em>Shows this help message and exit</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">-f File_Name</td>
<td style="width: 62.2893%;"><em>File to analyze.</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">--je</td>
<td style="width: 62.2893%;"><em>JSON Emails Search. (Raw output)</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">--mails</td>
<td style="width: 62.2893%;"><em>Mail Addresses search.</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">--urls</td>
<td style="width: 62.2893%;"><em>URLs search.</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">--fb</td>
<td style="width: 62.2893%;"><em>Facebook chats search.</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">--lang eng &lt;or esp&gt;</td>
<td style="width: 62.2893%;"><em>Identify human language in a given file. 'esp' for spanish or 'eng' for english language identification.</em></td>
</tr>
<tr>
<td style="width: 32.7107%;">&nbsp;</td>
<td style="width: 62.2893%;"><em>Example: python eureka.py -f pagefile.sys --lan eng</em></td>
</tr>
</tbody>
</table>

</br>If any <b>bug</> is found, please let me know! =)
