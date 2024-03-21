#!/usr/bin/env python
# -*- coding: utf-8 -*-
# eureka.py - The forensics search tool..
# eureka.py - The forensics search tool..
# Please use Python 3 to run this tool

from __future__ import division
from collections import OrderedDict
from operator import itemgetter
import re
import subprocess
import argparse
import os

def GetBanner():
    return "\nEureka! :)\n"

def GetUsage():
    return "python eureka.py -f fileName.ext --fb --je --mails --urls --lang eng"

def GetDescription():
    return """
    Eureka! is search tool that identifies Facebook Chats, Emails, URLs, Email Addresses and Human Language in very, very large files (mostly, in memory dumps). NOTE: To save the results into a file, please redirect the output..
    """

def NotFound():
    return "\t[i] - No results found, but keep trying!."

def GetLangLetters(lang):
    if "esp" in lang:
        return "abcdefghijklmnopqrstuvwxqyzñáóé \t\n"
    return "abcdefghijklmnopqrstuvwxqyz \t\n"

def LangDelTable(lang):
    return "".join(l.lower() for l in [chr(x) for x in range(256)] if l.lower() not in GetLangLetters(lang))

def GetOutFileName():
    return "stringsOut.txt"

def StringSearch(filename):
    cmd = "strings"
    if os.name == "nt":
        cmd = "strings2"
    cmdStringSearch = cmd + " " + filename + " > " + GetOutFileName() 
    subprocess.call(cmdStringSearch, shell=True)
    
def WarmingUp():
    parser = argparse.ArgumentParser(description=GetDescription(), usage=GetUsage())
    parser.add_argument("-f", metavar='File_Name', nargs=1, required=True, help="File to analyze.")
    parser.add_argument("--je",action='store_true', help="JSON Emails Search. (Raw output)")
    parser.add_argument("--mails", action='store_true', help="Mail Addresses search.")
    parser.add_argument("--urls", action='store_true', help="URLs search. For each detected URL, web vulnerabilities presence will be audited.")
    parser.add_argument("--fb", action='store_true', help="Facebook chats search.")
    parser.add_argument("--lang", metavar='\'eng\' [or] \'esp\'', nargs=1, help="Identify human language in a given file. 'esp' for spanish, 'eng' for english language identification. Example: python eureka.py -f pagefile.sys --lan eng ")
    return parser.parse_args()

#ToDo: deprecate this functionality
def SearchJSONMails(fileName):
    print("\n[i]- Now, JSON Emails are being searched..")
    with open(fileName,'r') as memDumpFile:
      found = 0
      for line in memDumpFile:
         if "email\\u" in line:
            found += 1
            print(line)
      if found == 0:
         print(NotFound())
            
def FilterFBChat(chat):
    filReg = "\"(?:thread_id|message_id|author|timestamp|body)\":\"{0,1}[^\"]+[\"|\,]"
    re.compile(filReg)
    matches2 = re.finditer(filReg, chat)
    for match2 in matches2:
        print(match2.group())

def SearchFBChat(fileName):
   print("\n[i]- Now, Facebook chats are being searched..")
   print("\t[i]- To get the identity of the Author, use: https://www.facebook.com/profile.php?id={AUTHOR FBID NUMBER}")
   with open(fileName,'r') as memDumpFile:
      found = 0
      for line in memDumpFile:
         if "source:chat:" in line:
            found += 1
            FilterFBChat(line)
      if found == 0:
         print(NotFound())

def SearchData(fileName, regex):
    allData = {}
    with open(fileName,'r') as memDumpFile:
        for line in memDumpFile:
            if isURLValidation(regex) == True:
               if "www." not in line and "http" not in line and "ftp" not in line:
                  continue
            else:
               if "@" not in line:
                  continue
            data = ValidateLine(line,regex)
            if data:
                allData[data] = ''
        if not allData:
            return NotFound()
        else:
            return allData
          
def ValidateLine(line, regex):
    compiledRe = re.compile(regex, re.IGNORECASE)
    matches = compiledRe.finditer(line)
    for match in matches:
        #return line.replace('u003c','').replace('u003e','').replace('u003d','').replace('\n','')
        return match.group().replace('u003c','').replace('u003e','').replace('u003d','')
                  
def LoadDictionary(lang):
    if 'eng' in lang:
        dictionaryFile = open('engDict.txt','r')
    else:
        dictionaryFile = open('espDict.txt','r')
    wordList = {}
    for word in dictionaryFile.read().split('\n'):
        wordList[word] = 'found'
    dictionaryFile.close()
    return wordList

def GetWordCount(message, lang, dictionary):
    possibleWords = message.split()
    
    if possibleWords == [] or len(possibleWords)==1:
        return 0.0 
    
    if DepShorts(possibleWords):
        matches = 0
        for word in possibleWords:
            if word in dictionary:
                matches += 1
    else:
        return 0.0
    return matches / len(possibleWords)

def DepShorts(possibleWords):
    cantSingle = 0
    for word in possibleWords:
        if len(word) < 2:
            cantSingle += 1
    return cantSingle <= len(possibleWords)/2            

def RemoveNonLetters(message, lang):
    delTable = LangDelTable(lang)
    translator = message.maketrans("","",delTable)
    return message.translate(translator)

def IsValidLanguage(lang, message, dictionary, wordPercentage=.2, letterPercentage=.8):
    message = message.lower()
    originalMessageLength = len(message)
    message = RemoveNonLetters(message, lang)
    wordsMatch = GetWordCount(message, lang, dictionary) >= wordPercentage
    messageLettersPercentage = len(message) / originalMessageLength
    lettersMatch = messageLettersPercentage >= letterPercentage
    return wordsMatch and lettersMatch
    
def SearchUrls(fileName):
    print("\n[i]- Now, URLs are being searched..")
    urlReg = r"(?=https?:\/\/|www\.|ftp:\/\/)([^\n\r]+)"
    urlList = SearchData(GetOutFileName(), urlReg)
    if urlList != NotFound():
        print("[i]- URLs were found:")
        urlList = OrderedDict(sorted(SearchWebVulns(urlList).items(), key=itemgetter(1)))
        for url,flag in urlList.items():
            print(flag + "- " + url)
    else:
        print(NotFound())

def SearchXSS(url):
    rdo = ValidateLine(url, r"((\%3C)|(\<))((\%2F)|\/)*([a-z0-9\%]|\s)+(\/|((\%3E)|(\>))+|((\%22)((\%2f))))")
    if rdo:
        return "XSS"
    return ""
    
def SearchWebVulns(urlList):
    for url in urlList:
        vulnName = SearchXSS(url)
        if vulnName:
            urlList[url] = WebVulnPrefix(vulnName)
            continue
        vulnName = SearchSQLi(url)
        if vulnName:
            urlList[url] = WebVulnPrefix(vulnName)
            continue
    return urlList
    
def SearchSQLi(url):
    rdo = ValidateLine(url, r"(((\%27)|(\')|(\%027))((\+)|(\s)))")
    if rdo:
        return "SQLi"
    return ""

def WebVulnPrefix(vulnName):
    return "[Web Vuln Found: %s]" % (vulnName)

def SearchLanguage(fileName, lang):
    print("\n[i]- Now, Human Language is being searched..")
    if not "esp" in lang and not "eng" in lang:
        print("\t[!]- No valid language was provided.")
    else:
        print("\t[i]- Using %s language for detection." % ('English' if 'eng' in args.lang else 'Spanish'))
        dictionary = LoadDictionary(lang)
        with open(fileName,'r') as file:
            for line in file:
                if IsValidLanguage(lang, line, dictionary):
                    print(line.replace('\n',''))

def isURLValidation(regex):
   if "http" in regex:
      return True
   return False

def SearchEmails(fileName):
    print("\n[i]- Now, Email Addresses are being searched..")
    mailReg = r"(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
    mailList = SearchData(fileName, mailReg)
    if mailList != NotFound():
        print("[i]- Emails were found:")
        for mail in mailList:
            print(mail)
    else:
        print(NotFound())
            
if __name__ == "__main__":
    print(GetBanner())
    args = WarmingUp()
    
    if not args.je and not args.mails and not args.lang and not args.urls and not args.fb:
        print("\n[!]- Maybe you need help, as no parameter was provided. You can try with \'eureka.py -h\'..\n")
        quit()
        
    print("\n[i]- Searching strings in the file, please be patient..")
    StringSearch(args.f[0])
    
    if args.je:
        SearchJSONMails(GetOutFileName())
        
    if args.mails:
        SearchEmails(GetOutFileName())
        
    if args.urls:
        SearchUrls(GetOutFileName())
        
    if args.fb:
        SearchFBChat(GetOutFileName())    

    if args.lang:
        SearchLanguage(GetOutFileName(), args.lang[0])
    
    print("\n")
    os.remove(GetOutFileName())
