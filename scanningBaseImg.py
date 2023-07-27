import subprocess as sb
import requests
import os
import json
from datetime import datetime


bot_token = "2037580205:AAGVcKMCPDwK1aDJCUXS_h3wy0C2Ih2e12E"
# chat_id = "-1001614051926" # real group
chat_id = "-1001757730802" # test group
trivyBin = "trivyBin/trivy"
trivySrv = "http://10.70.70.39:1115"
token = "H5nF5ywy262wt881ZWpq"
imageURL = "hub.nexdev.net/rebuild-baseimage/dotnetcore/aspnet"
listImgTag = ["3.1.32-alpine", "5.0-alpine", "5.0-nap-mail-core", "6.0-alpine", "7.0-alpine", "7.0-nap-mail-core", "7.0-slim"]
numberCriticalIssue = "0"
numberHighIssue = "0"
numberMediumIssue = "0"
dbVerPath = "db/metadata.json"

# Detec Medium Issues
# def sendMessageDetectIssue(critical,high,medium,imgName,dbVer):
#     detailMessage = """
# ⚠️<b>Vulnerabilities Detected</b>⚠️
# <b>Image Name:</b> <code>{0}</code>,
# <b>Critical:</b> {1}, <b>High:</b> {2}, <b>Medium</b>: {3}
# <b>DatabaseVer:</b> <code>{4}</code>
# <i>For details, please follow the following file</i>
#     """.format(imgName,critical, high, medium, dbVer)
#     params = {
#         'chat_id': chat_id,
#         'text': detailMessage,
#         'parse_mode': 'HTML'
#     }
#     url_send = "https://api.telegram.org/bot" + \
#         bot_token + "/sendMessage"
#     requests.post(url_send, params=params)


def sendMessageDetectIssue(critical,high,imgName,dbVer):
    detailMessage = """
⚠️<b>Vulnerabilities Detected</b>⚠️
<b>Image Name:</b> <code>{0}</code>,
<b>Critical:</b> {1}, <b>High:</b> {2},
<b>DatabaseVer:</b> <code>{3}</code>
<i>For details, please follow the following file</i>
    """.format(imgName,critical, high, dbVer)
    params = {
        'chat_id': chat_id,
        'text': detailMessage,
        'parse_mode': 'HTML'
    }
    url_send = "https://api.telegram.org/bot" + \
        bot_token + "/sendMessage"
    requests.post(url_send, params=params)





def sendMessageCleanImg(critical,high,imgName,dbVer):
    detailMessage = """
✅<b><code>NO</code> Vulnerabilities Detected</b>✅
<b>Image Name:</b> <code>{0}</code>,
<b>Critical:</b> {1}, <b>High:</b> {2}
<b>DatabaseVer:</b> <code>{3}</code>
    """.format(imgName,critical, high, dbVer)
    params = {
        'chat_id': chat_id,
        'text': detailMessage,
        'parse_mode': 'HTML'
    }
    url_send = "https://api.telegram.org/bot" + \
        bot_token + "/sendMessage"
    requests.post(url_send, params=params)


def sendResultFileScan(detailFileScan):
    files = {'document':  open(detailFileScan, 'rb')}
    url_send = "https://api.telegram.org/bot" + \
        bot_token + "/sendDocument?chat_id=" + chat_id
    requests.post(url_send, files=files)



def showVersionTrivyDB(versionFile):
    fileName = open(versionFile)
    data = json.loads(fileName.read())
    content = data["UpdatedAt"]
    return content

def shortResult(imageName):
    command = f"""{trivyBin} client --remote {trivySrv} --format template --template '{{{{- $critical := 0 }}}}{{{{- $high := 0 }}}}{{{{- range . }}}}{{{{- range .Vulnerabilities }}}}{{{{- if  eq .Severity "CRITICAL" }}}}{{{{- $critical = add $critical 1 }}}}{{{{- end }}}}{{{{- if  eq .Severity "HIGH" }}}}{{{{- $high = add $high 1 }}}}{{{{- end }}}}{{{{- end }}}}{{{{- end }}}}{{{{ $critical }}}},{{{{ $high }}}}' --ignore-unfixed --token {token} {imageName} | tail -1"""
    result = sb.getoutput(command)
    return result.split(',')[0], result.split(',')[1]


# show Result with Medium Issues
# def shortResult(imageName):
#     command = f"""{trivyBin} client --remote {trivySrv} --format template --template '{{{{- $critical := 0 }}}}{{{{- $high := 0 }}}}{{{{- $medium := 0 }}}}{{{{- range . }}}}{{{{- range .Vulnerabilities }}}}{{{{- if eq .Severity "CRITICAL" }}}}{{{{- $critical = add $critical 1 }}}}{{{{- end }}}}{{{{- if eq .Severity "HIGH" }}}}{{{{- $high = add $high 1 }}}}{{{{- end }}}}{{{{- if eq .Severity "MEDIUM" }}}}{{{{- $medium = add $medium 1 }}}}{{{{- end }}}}{{{{- end }}}}{{{{- end }}}}{{{{ $critical }}}},{{{{ $high }}}},{{{{ $medium }}}}' --ignore-unfixed --token {token} {imageName} | tail -1"""
#     result = sb.getoutput(command)
#     return result.split(',')[0], result.split(',')[1], result.split(',')[2]


# critical,high,medium = shortResult("hub.nexdev.net/base/dotnet/core/aspnet:5.0-nap-mail-core")
# print(medium)




def detailResult(imageName):
    now = datetime.now()
    current_time = now.strftime("%H%M%S")
    current_date = now.strftime("%d-%m-%Y")
    namingImg = imageName.split('/')[-1]
    command = f"""{trivyBin} client --remote {trivySrv} --format template --template "@trivyBin/html.tpl" -o reports/{namingImg}-{current_date}--{current_time}.html --ignore-unfixed  --token  H5nF5ywy262wt881ZWpq {imageName}"""
    sb.run(command, shell=True)
    fileScan = f"reports/{namingImg}-{current_date}--{current_time}.html"
    return fileScan



def main():
    
    dbVer = showVersionTrivyDB(dbVerPath)
    for imageTag in listImgTag:
        imageName = f"{imageURL}:{imageTag}"
        critical,high = shortResult(imageName)
        if critical == numberCriticalIssue and high == numberHighIssue:
            # sendMessageCleanImg(critical,high,imageName,dbVer)
            print(f"ImageName: {imageName} - Critical: {critical} - High: {high}")
        else:
            resultFile = detailResult(imageName)
            sendMessageDetectIssue(critical,high,imageName,dbVer)
            sendResultFileScan(resultFile)
            os.remove(resultFile)
            print(f"ImageName: {imageName} - Critical: {critical} - High: {high}")
            


main()
