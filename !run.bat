@echo off
:: must run etw as admin
powershell -Command "Start-Process python 'main.py' -Verb runAs"
