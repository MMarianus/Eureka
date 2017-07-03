#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @MMerianus 2017 - eureka.py - The forensic search tool..

import re
import subprocess
import argparse
import os

def GetBanner():
	return '\nEureka! :)\n'

def GetUsage():
	return 'python eureka.py -f fileName.ext --fb --je --mails --urls --lang eng'

def GetDescription():
	return """
	Eureka! is search tool that identifies Facebook Chats, Emails, URLs, Email Addresses and Human Language in very, very large files (mostly, in memory dumps). NOTE: To save the results into a file, please redirect the output..
	"""

def notFound():
	return '\t[i] - No results found, but keep trying!.'

def GetLangLetters(lang):
	if 'esp' in lang:
		return 'abcdefghijklmnopqrstuvwxqyzñáóé \t\n'
	return 'abcdefghijklmnopqrstuvwxqyz \t\n'

def GetOutFileName():
	return "stringsOut.txt"

def StringSearch(filename):
	cmd = 'strings'
	if os.name == 'nt':
		cmd = 'strings2'
	cmdStringSearch = cmd + ' ' + filename + ' > ' + GetOutFileName() 
	subprocess.call(cmdStringSearch, shell=True)
	
def WarmingUp():
	parser = argparse.ArgumentParser(description=GetDescription(), usage=GetUsage())
	parser.add_argument("-f", metavar='File_Name', nargs=1, required=True, help="File to analyze.")
	parser.add_argument("--je",action='store_true', help="JSON Emails Search. (Raw output)")
	parser.add_argument("--mails", action='store_true', help="Mail Addresses search.")
	parser.add_argument("--urls", action='store_true', help="URLs search.")
	parser.add_argument("--fb", action='store_true', help="Facebook chats search.")
	parser.add_argument("--lang", metavar='\'eng\' [or] \'esp\'', nargs=1, help="Identify human language in a given file. 'esp' for spanish, 'eng' for english language identification. Example: python eureka.py --lan eng pagefile.sys")
	
	return parser.parse_args()

def SearchMails(fileName):
	with open(fileName,'r') as memDumpFile:
		regex = r".*email\\.*"
		re.compile(regex)
		found = 0
		for line in memDumpFile:
			matches = re.finditer(regex, line)
			for match in matches:
				found += 1
				print match.group() 
		if found == 0:
			print(notFound())

def FilterFBChat(chat):
	filReg = "\"(?:thread_id|message_id|author|timestamp|body)\":\"{0,1}[^\"\,]+[\"|\,]"
	re.compile(filReg)
	matches2 = re.finditer(filReg, chat)
	for match2 in matches2:
		print match2.group()

def SearchFBChat(fileName):
	print("\n[i]- Now, Facebook chats are being searched..")
	print("\t[i]- To get the identity of the Author, use: https://www.facebook.com/profile.php?id={AUTHOR FBID NUMBER}")
	with open(fileName,'r') as memDumpFile:
		regChat = r".*\[\"source:chat\"\].*"
		re.compile(regChat)
		found = 0
		for line in memDumpFile:
			matches = re.finditer(regChat, line)
			for match in matches:
				found += 1
				FilterFBChat(match.group())			
		if found == 0:
			print(notFound())

def SearchData(fileName, regex):
	allData = {}
	re.compile(regex)
	with open(fileName,'r') as memDumpFile:
		found = 0
		for line in memDumpFile:
			matches = re.finditer(regex, line)
			for match in matches:
				found += 1
				allData[match.group().replace('u003c','').replace('u003e','').replace('u003d','')] = 'data'
	if found == 0:
		print(notFound())
	else:
		for data in allData:
			print data
			
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
	message = message.lower()
	message = RemoveNonLetters(message, lang)
	possibleWords = message.split()
	
	if possibleWords == [] or len(possibleWords)==1:
		return 0.0 
	
	if depShorts(possibleWords):
		matches = 0
		for word in possibleWords:
			if word in dictionary:
				matches += 1
	else:
		return 0.0
	return float(matches) / len(possibleWords)

def depShorts(possibleWords):
	cantSingle = 0
	for word in possibleWords:
		if len(word) < 2:
			cantSingle += 1
	return cantSingle <= len(possibleWords)/2			

def RemoveNonLetters(message, lang):
	lettersOnly = []
	for symbol in message:
		if symbol in GetLangLetters(lang):
			lettersOnly.append(symbol)
	return ''.join(lettersOnly)

def IsValidLanguage(lang, message, dictionary, wordPercentage=20, letterPercentage=80):
	message = message.lower()
	wordsMatch = GetWordCount(message, lang, dictionary) * 100 >= wordPercentage
	numLetters = len(RemoveNonLetters(message, lang))
	messageLettersPercentage = float(numLetters) / len(message) * 100
	lettersMatch = messageLettersPercentage >= letterPercentage
	return wordsMatch and lettersMatch

def SearchLanguage(fileName, lang):
	print("\n[i]- Now, Human Language is being searched..")
	if not 'esp' in lang and not 'eng' in lang:
		print("\t[!]- No valid language was provided.")
	else:
		print("\t[i]- Using %s language for detection." % ('English' if 'eng' in args.lang else 'Spanish'))
		dictionary = LoadDictionary(lang)		
		with open(fileName,'r') as file:
			for line in file:
				if IsValidLanguage(lang, line, dictionary):
					print line.replace('\n','')
				
if __name__ == "__main__":
	print(GetBanner())
	args = WarmingUp()

	if not args.je and not args.mails and not args.lang and not args.urls and not args.fb:
		print("\n[!]- Maybe you need help, as no parameter were provided. You can try with \'eureka.py -h\'..\n")
	else:
		print("\n[i]- Searching strings in the file, please be patient..")
		StringSearch(args.f[0])

	if args.je:
		print("\n[i]- Now, JSON Emails are being searched..")
		SearchMails(GetOutFileName())
		
	if args.mails:
		print("\n[i]- Now, Email Addresses are being searched..")
		mailReg = r"(?:[a-z0-9_-]+(?:\.[a-z0-9_-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
		SearchData(GetOutFileName(), mailReg)
		
	if args.urls:
		print("\n[i]- Now, URLs are being searched..")
		urlReg = r"(?=https?://|www\.|ftp://)([^\s\"\'\)\>]+)"
		SearchData(GetOutFileName(), urlReg)
		
	if args.fb:
		SearchFBChat(GetOutFileName())	

	if args.lang:
		SearchLanguage(GetOutFileName(), args.lang)
	
	print("\n")
	os.remove(GetOutFileName())
