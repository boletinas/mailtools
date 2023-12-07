#!/usr/local/bin/python3

import os, sys, threading, time, queue, random, re, signal, smtplib, ssl, socket, configparser, base64, string, datetime

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

try:
	import psutil, requests, dns.resolver
except ImportError:
	print('\033[1;33minstalling missing packages...\033[0m')
	os.system('apt -y install python3-pip; pip3 install psutil dnspython requests pyopenssl')
	import psutil, requests, dns.resolver

if not sys.version_info[0] > 2 and not sys.version_info[1] > 8:
	exit('\033[0;31mpython 3.9 is required. try to run this script with \033[1mpython3\033[0;31m instead of \033[1mpython\033[0m')

# dangerous mx domains, skipping them all
dangerous_domains = r'acronis|acros|adlice|alinto|appriver|aspav|atomdata|avanan|avast|barracuda|baseq|bitdefender|broadcom|btitalia|censornet|checkpoint|cisco|cistymail|clean-mailbox|clearswift|closedport|cloudflare|comforte|corvid|crsp|cyren|darktrace|data-mail-group|dmarcly|drweb|duocircle|e-purifier|earthlink-vadesecure|ecsc|eicar|elivescanned|eset|essentials|exchangedefender|fireeye|forcepoint|fortinet|gartner|gatefy|gonkar|guard|helpsystems|heluna|hosted-247|iberlayer|indevis|infowatch|intermedia|intra2net|invalid|ioactive|ironscales|isync|itserver|jellyfish|kcsfa.co|keycaptcha|krvtz|libraesva|link11|localhost|logix|mailborder.co|mailchannels|mailcleaner|mailcontrol|mailinator|mailroute|mailsift|mailstrainer|mcafee|mdaemon|mimecast|mx-relay|mx1.ik2|mx37\.m..p\.com|mxcomet|mxgate|mxstorm|n-able|n2net|nano-av|netintelligence|network-box|networkboxusa|newnettechnologies|newtonit.co|odysseycs|openwall|opswat|perfectmail|perimeterwatch|plesk|prodaft|proofpoint|proxmox|redcondor|reflexion|retarus|safedns|safeweb|sec-provider|secureage|securence|security|sendio|shield|sicontact|sonicwall|sophos|spamtitan|spfbl|spiceworks|stopsign|supercleanmail|techtarget|titanhq|trellix|trendmicro|trustifi|trustwave|tryton|uni-muenster|usergate|vadesecure|wessexnetworks|zillya|zyxel|fucking-shit|abus|bad|black|bot|brukalai|excello|filter|honey|junk|lab|list|metunet|rbl|research|security|spam|trap|ubl|virtual|virus|vm\d'
mailing_services = r'amazon|elastic|sendinblue|twilio|sendgrid|mailgun|netcore|pepipost|mailjet|mailchimp|mandrill|salesforce|constant|postmark|sharpspring|zepto|litmus|sparkpost|smtp2go|socketlabs|aritic|kingmailer|netcore|flowmailer|jangosmtp'
no_read_receipt_for = r'@(web\.de|gmx\.[a-z]{2,3}|gazeta\.pl|wp\.pl|op\.pl|interia\.pl|onet\.pl|spamtest\.glockdb\.com)$'
glock_json_response_url = 'https://app.prod.glockapps.com/api/v1/GetSingleTestResults?ExternalUserId=st-3-'
glock_report_url = 'https://glockapps.com/inbox-email-tester-report/?uid=st-3-'
dummy_config_path = 'https://raw.githubusercontent.com/aels/mailtools/main/mass-mailer/dummy.config'
text_extensions = 'txt|html|htm|mhtml|mht|xhtml|svg'.split('|')

requests.packages.urllib3.disable_warnings()
sys.stdout.reconfigure(encoding='utf-8')

b   = '\033[1m'
z   = '\033[0m'
wl  = '\033[2K'
up  = '\033[F'
err = b+'[\033[31mx\033[37m] '+z
okk = b+'[\033[32m+\033[37m] '+z
wrn = b+'[\033[33m!\033[37m] '+z
inf = b+'[\033[34mi\033[37m] '+z
npt = b+'[\033[37m?\033[37m] '+z

def show_banner():
	banner = f"""

              ,▄   .╓███?                ,, .╓███)                              
            ╓███| ╓█████╟               ╓█/,███╙                  ▄▌            
           ▄█^[██╓█* ██F   ,,,        ,╓██ ███`     ,▌          ╓█▀             
          ╓█` |███7 ▐██!  █▀╙██b   ▄██╟██ ▐██      ▄█   ▄███) ,╟█▀▀`            
          █╟  `██/  ██]  ██ ,██   ██▀╓██  ╙██.   ,██` ,██.╓█▌ ╟█▌               
         |█|    `   ██/  ███▌╟█, (█████▌   ╙██▄▄███   @██▀`█  ██ ▄▌             
         ╟█          `    ▀▀  ╙█▀ `╙`╟█      `▀▀^`    ▀█╙  ╙   ▀█▀`             
         ╙█                           ╙                                         
          ╙     {b}MadCat Mailer v23.05.24{z}
                Made by {b}Aels{z} for community: {b}https://xss.is{z} - forum of security professionals
                https://github.com/aels/mailtools
                https://t.me/freebug
	"""
	for line in banner.splitlines():
		print(line)
		time.sleep(0.05)

def red(s,type=0):
	return f'\033[{str(type)};31m'+str(s)+z

def green(s,type=0):
	return f'\033[{str(type)};32m'+str(s)+z

def orange(s,type=0):
	return f'\033[{str(type)};33m'+str(s)+z

def blue(s,type=0):
	return f'\033[{str(type)};34m'+str(s)+z

def violet(s,type=0):
	return f'\033[{str(type)};35m'+str(s)+z

def cyan(s,type=0):
	return f'\033[{str(type)};36m'+str(s)+z

def white(s,type=0):
	return f'\033[{str(type)};37m'+str(s)+z

def bold(s):
	return b+str(s)+z

def num(s):
	return f'{int(s):,}'

def tune_network():
	if os.name != 'nt':
		try:
			import resource
			resource.setrlimit(8, (2**20, 2**20))
			print(okk+'tuning rlimit_nofile:          '+', '.join([bold(num(i)) for i in resource.getrlimit(8)]))
			# if os.geteuid() == 0:
			# 	print('tuning network settings...')
			# 	os.system("echo 'net.core.rmem_default=65536\nnet.core.wmem_default=65536\nnet.core.rmem_max=8388608\nnet.core.wmem_max=8388608\nnet.ipv4.tcp_max_orphans=4096\nnet.ipv4.tcp_slow_start_after_idle=0\nnet.ipv4.tcp_synack_retries=3\nnet.ipv4.tcp_syn_retries =3\nnet.ipv4.tcp_window_scaling=1\nnet.ipv4.tcp_timestamp=1\nnet.ipv4.tcp_sack=0\nnet.ipv4.tcp_reordering=3\nnet.ipv4.tcp_fastopen=1\ntcp_max_syn_backlog=1500\ntcp_keepalive_probes=5\ntcp_keepalive_time=500\nnet.ipv4.tcp_tw_reuse=1\nnet.ipv4.tcp_tw_recycle=1\nnet.ipv4.ip_local_port_range=32768 65535\ntcp_fin_timeout=60' >> /etc/sysctl.conf")
			# else:
			# 	print('Better to run this script as root to allow better network performance')
		except Exception as e:
			print(wrn+'failed to set rlimit_nofile:   '+str(e))

def quit(signum, frame):
	print('\r\n'+wl+okk+'exiting... see ya later. bye.')
	time.sleep(1)
	sys.exit(0)

def now():
	return datetime.datetime.now().strftime('[ %Y-%m-%d %H:%M:%S ]')

def check_ipv4():
	print(inf+'checking ipv4 address in blacklists...'+up)
	try:
		socket.has_ipv4 = read('https://api.ipify.org')
		socket.ipv4_blacklist = re.findall(r'"name":"([^"]+)","listed":true', read('https://addon.dnslytics.net/ipv4info/v1/'+socket.has_ipv4))
		socket.ipv4_blacklist = red(', '.join(socket.ipv4_blacklist)) if socket.ipv4_blacklist else False
	except:
		socket.has_ipv4 = False
		socket.ipv4_blacklist = False

def check_ipv6():
	try:
		socket.has_ipv6 = read('https://api6.ipify.org')
	except:
		socket.has_ipv6 = False

def first(a):
	return (a or [''])[0]

def bytes_to_mbit(b):
	return round(b/1024./1024.*8, 2)

def sec_to_min(i):
	return '%02d:%02d'%(int(i/60), i%60)

def normalize_delimiters(s):
	return re.sub(r'[:,\t|]+', ';', re.sub(r'"+', '', s))

def read(path):
	return os.path.isfile(path) and open(path, 'r', encoding='utf-8-sig', errors='ignore').read() or re.search(r'^https?://', path) and requests.get(path, timeout=5).text or ''

def read_lines(path):
	return read(path).splitlines()

def read_bytes(path):
	return os.path.isfile(path) and open(path, 'rb').read() or ''

def rand_file_from_dir(path):
	path = re.sub(r'//', '/', path+'/')
	filenames = [file for file in os.listdir(path) if is_file_or_url(path+file)]
	return path+random.choice(filenames) if len(filenames) else ''

def is_file_or_url(path):
	return os.path.isfile(path) or re.search(r'^https?://', path)

def base64_encode(string):
	return base64.b64encode(str(string).encode('ascii')).decode('ascii')

def get_rand_ip_of_host(host):
	global resolver_obj
	try:
		ip_array = resolver_obj.resolve(host, socket.has_ipv6 and 'aaaa' or 'a')
	except:
		try:
			ip_array = resolver_obj.resolve(host, 'a')
		except:
			raise Exception('no a record found for '+host)
	return str(random.choice(ip_array))

def is_valid_email(email):
	return re.match(r'^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$', email)

def is_dangerous_email(email):
	global resolver_obj, dangerous_domains
	try:
		mx_domain = str(resolver_obj.resolve(email.split('@')[-1], 'mx')[0].exchange)[0:-1]
		return mx_domain if re.findall(dangerous_domains, mx_domain) and not re.findall(r'\.outlook\.com$', mx_domain) else False
	except:
		return 'no mx records found'

def extract_email(line):
	return first(re.findall(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', line))

def expand_macros(text, subs):
	mail_str, smtp_user, mail_redirect_url, rand_Fname, rand_Lname = subs
	mail_to = extract_email(mail_str)
	placeholders = 'email|email_b64|email_user|email_host|email_l2_domain|smtp_user|smtp_host|url|random_Fname|random_Lname|random_fname|random_lname'.split('|')
	replacements = [
		mail_to,
		base64_encode(mail_to),
		mail_to.split('@')[0].capitalize(),
		mail_to.split('@')[-1],
		mail_to.split('@')[-1].split('.')[0],
		smtp_user,
		smtp_user.split('@')[-1],
		mail_redirect_url,
		rand_Fname,
		rand_Lname,
		rand_Fname.lower(),
		rand_Lname.lower()
	]
	if not '\x00' in text:
		for i, column in enumerate(mail_str.split(';')):
			text = text.replace('{{'+str(i+1)+'}}', column)
		for i, placeholder in enumerate(placeholders):
			text = text.replace('{{'+placeholder+'}}', replacements[i])
		macros = re.findall(r'(\{\{.*?\}\})', text)
		for macro in macros:
			text = text.replace(macro, random.choice(macro[2:-2].split('|')))
	return text

def get_read_receipt_headers(mail_from):
	receipt_headers = f'Disposition-Notification-To: {mail_from}\n'
	receipt_headers+= f'Generate-Delivery-Report: {mail_from}\n'
	receipt_headers+= f'Read-Receipt-To: {mail_from}\n'
	receipt_headers+= f'Return-Receipt-Requested: {mail_from}\n'
	receipt_headers+= f'Return-Receipt-To: {mail_from}\n'
	receipt_headers+= f'X-Confirm-reading-to: {mail_from}\n'
	return receipt_headers

def create_attachment(file_path, subs):
	global text_extensions
	if os.path.isdir(file_path):
		file_path = rand_file_from_dir(file_path)
	if is_file_or_url(file_path):
		attachment_filename = expand_macros(re.sub(r'=', '/', file_path).split('/')[-1], subs)
		attachment_ext = file_path.split('.')[-1]
		attachment_body = expand_macros(read(file_path), subs) if attachment_ext in text_extensions else read_bytes(file_path)
		attachment = MIMEApplication(attachment_body)
		attachment.add_header('content-disposition', 'attachment', filename=attachment_filename)
		return attachment
	else:
		return ''

def str_ljust(string, length):
	is_inside_tag = False
	shift = 0
	for i, s in enumerate(string):
		if i<length+shift:
			is_inside_tag |= s == '\033'
			shift += int(is_inside_tag)
			is_inside_tag &= s != 'm'
	if len(string)>length+shift:
		return re.sub(r'\033[^m]*$', '', string[0:length+shift-3])+'...'+z
	else:
		return string+' '*(length-len(re.sub(r'\033[^m]+m', '', string)))

def smtp_connect(smtp_server, port, user, password):
	global connection_timeout
	smtp_class = smtplib.SMTP_SSL if str(port) == '465' else smtplib.SMTP
	smtp_server_ip = get_rand_ip_of_host(smtp_server)
	ctx = ssl._create_unverified_context()
	server_obj = smtp_class(smtp_server_ip, port, local_hostname=smtp_server, timeout=connection_timeout)
	server_obj.ehlo()
	if server_obj.has_extn('starttls') and port != '465':
		server_obj.starttls(context=ctx)
		server_obj.ehlo()
	server_obj.login(user, password)
	return server_obj

def smtp_sendmail(server_obj, smtp_server, smtp_user, mail_str):
	global config, no_read_receipt_for, total_sent
	mail_redirect_url = random.choice(config['redirects_list'])
	subs = [mail_str, smtp_user, mail_redirect_url] + get_random_name()
	mail_to = extract_email(mail_str)
	mail_from = expand_macros(config['mail_from'], subs)
	mail_reply_to = expand_macros(config['mail_reply_to'], subs)
	mail_subject = expand_macros(config['mail_subject'], subs)
	mail_body = expand_macros(read(config['mail_body']) if is_file_or_url(config['mail_body']) else config['mail_body'], subs)
	smtp_from = extract_email(smtp_user) or extract_email(mail_from) or 'no-reply@localhost'
	message = MIMEMultipart()
	message['To'] = mail_to
	message['From'] = smtp_from if is_valid_email(mail_from) else mail_from.split(' <')[0]+f' <{smtp_from}>'
	message['Subject'] = mail_subject
	message.attach(MIMEText(mail_body, 'html', 'utf-8'))
	for attachment_file_path in config['attachment_files']:
		attachment = create_attachment(attachment_file_path, subs)
		message.attach(attachment)
	headers = 'Return-Path: '+smtp_from+'\n'
	headers+= 'Reply-To: '+mail_reply_to+'\n'
	if config['add_high_priority']:
		headers+= 'X-Priority: 1\n'
		headers+= 'X-MSmail-Priority: High\n'
	headers+= 'X-Source-IP: 127.0.0.1\n'
	headers+= 'X-Sender-IP: 127.0.0.1\n'
	headers+= 'X-Mailer: Microsoft Office Outlook, Build 10.0.5610\n'
	headers+= 'X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2800.1441\n'
	headers+= 'Received: '+' '.join(get_random_name())+'\n'
	if config['add_read_receipts'] and not re.findall(no_read_receipt_for, mail_to.lower()):
		headers += get_read_receipt_headers(smtp_from)
	message_raw = headers + message.as_string()
	server_obj.sendmail(smtp_from, mail_to, message_raw)

def get_testmail_str(smtp_str):
	global smtp_pool_tested, test_mail_str, config
	mails_to_verify = config['mails_to_verify'].split(',')
	mail_str = False
	if smtp_pool_tested[smtp_str]<len(mails_to_verify):
		mail_str = test_mail_str.replace(extract_email(test_mail_str), mails_to_verify[smtp_pool_tested[smtp_str]])
		smtp_pool_tested[smtp_str] += 1
	return mail_str

def smtp_testmail():
	global smtp_pool_array, test_mail_str, smtp_errors_que
	test_mail_sent = False
	while not test_mail_sent:
		try:
			smtp_str = random.choice(smtp_pool_array)
		except:
			exit(wl+err+'sorry, no valid smtp servers left. bye.')
		smtp_server, port, smtp_user, password = smtp_str.split('|')
		try:
			server_obj = smtp_connect(smtp_server, port, smtp_user, password)
			smtp_sendmail(server_obj, smtp_server, smtp_user, test_mail_str)
			test_mail_sent = True
		except Exception as e:
			msg = '~\b[X] '+str(e).split('b\'')[-1].strip()
			smtp_errors_que.put((smtp_str, msg, 0))
			smtp_str in smtp_pool_array and smtp_pool_array.remove(smtp_str)
			print(wl+err+smtp_server+' ('+smtp_user+'): '+red(msg))
	return True

def test_inbox():
	global inbox_test_id, glock_json_response_url, glock_report_url
	results_mask = r'"Finished":true,"DKIM".+?"ISP":"Gmail".+?"iType":"([^"]+)".+?"ISP":"Outlook".+?"iType":"([^"]+)".+?"ISP":"Yahoo \(Global\)".+?"iType":"([^"]+)".+?"SpamAssassin".+?"Score":([\d.]+),'
	results_array = []
	print(wl+inf+f'sending test mail to '+bold(f'st-3-{inbox_test_id}@spamtest.glockdb.com')+'...')
	smtp_testmail()
	for i in range(1,17):
		time.sleep(1)
		print(wl+inf+'waiting ~15 seconds for the results to come'+(i%4*'.')+up)
		result_json = i%5==0 and read(glock_json_response_url+inbox_test_id)
		if result_json and re.findall(r'"Finished":true,"DKIM"', result_json):
			inbox_test_result = first(re.findall(results_mask, result_json)) or ['-']*4
			break
		if i==16:
			inbox_test_result = ['Lost']*4
	for service in ['Gmail','Outlook','Yahoo','SpamAssassin']:
		status = inbox_test_result.pop(0)
		status = re.search(r'^(Primary|Inbox|[0-4]\.\d)$', status) and green(status) or red(status)
		results_array += [service+': '+status]
	print(wl+okk+', '.join(results_array).lower())
	print(wl+okk+'report url: '+glock_report_url+inbox_test_id)

def worker_item(mail_que, results_que):
	global threads_counter, smtp_pool_array, loop_times, smtp_errors_que, mails_dangerous_que
	self = threading.current_thread()
	mail_str = False
	mails_sent = 0
	while True:
		if not len(smtp_pool_array) or mail_que.empty() and not mail_str:
			results_que.put((self.name, f'~\bdone with {green(mails_sent,0)} mails', mails_sent))
			break
		else:
			smtp_str = random.choice(smtp_pool_array)
			smtp_server, port, smtp_user, password = smtp_str.split('|')
			smtp_sent = 0
			current_server = f'{smtp_server} ({smtp_user}): '
			results_que.put((self.name, current_server+blue('~\b->- ',0)+smtp_str, mails_sent))
			try:
				server_obj = smtp_connect(smtp_server, port, smtp_user, password)
				while True:
					if mail_que.empty() and not mail_str:
						break
					try:
						time_start = time.perf_counter()
						mail_str = get_testmail_str(smtp_str) or mail_str or mail_que.get()
						mail_to = extract_email(mail_str)
						if is_dangerous := is_dangerous_email(mail_to):
							msg = red('-\b'+'>'*(mails_sent%3)+b+'>',2)+red('>> '[mails_sent%3:],2)+'skipping email - '+mail_to+' ('+red(is_dangerous)+')'
							results_que.put((self.name, current_server+msg, mails_sent))
							mails_dangerous_que.put((mail_str, is_dangerous))
							mail_str = False
							time.sleep(0.5)
							continue
						smtp_sendmail(server_obj, smtp_server, smtp_user, mail_str)
						msg = green('+\b'+'>'*(mails_sent%3)+b+'>',0)+green('>> '[mails_sent%3:],0)+mail_str
						results_que.put((self.name, current_server+msg, mails_sent))
						smtp_sent += 1
						mails_sent += 1
						mail_str = False
						loop_times += [time.perf_counter() - time_start]
						len(loop_times)>100 and loop_times.pop(0)
					except Exception as e:
						if re.search(r'suspicio|suspended|too many|limit|spam|blocked|unexpectedly closed|mailbox unavailable', str(e).lower()):
							raise Exception(e)
						msg = '~\b{!} '+str(e).split(' b\'')[-1].strip()
						results_que.put((self.name, current_server+orange(msg), mails_sent))
						smtp_errors_que.put((smtp_str, msg, smtp_sent))
						time.sleep(1)
						break
			except Exception as e:
				msg = '~\b[X] '+str(e).split(' b\'')[-1].strip()
				results_que.put((self.name, current_server+red(msg), mails_sent))
				smtp_errors_que.put((smtp_str, msg, smtp_sent))
				smtp_str in smtp_pool_array and smtp_pool_array.remove(smtp_str)
				time.sleep(1)
			time.sleep(0.04)
	threads_counter -= 1

def get_random_name():
	fnames = 'Dan|Visakan|Molly|Nicole|Nick|Michael|Joanna|Ed|Maxim|Nancy|Mika|Margaret|Melody|Jerry|Lindsey|Jared|Lindsay|Veronica|Marianne|Mohammed|Alex|Lisa|Laurie|Thomas|Mike|Lydia|Melissa|Ccsa|Monique|Morgan|Drew|Milan|Nemashanker|Benjamin|Mel|Norine|Deirdre|Millie|Tom|Maria|Mighty|Terri|Marsha|Mark|Stephen|Holly|Megan|Fonda|Melanie|Nada|Barry|Marilyn|Letitia|Mary|Larry|Mindi|Alexander|Mirela|Lhieren|Wilson|Nandan|Matthew|Nicolas|Michelle|Lauri|John|Amy|Danielle|Laly|Lance|Nance|Debangshu|Emily|Graham|Aditya|Edward|Jimmy|Anne|William|Michele|Laura|George|Marcus|Martin|Bhanu|Miles|Marla|Luis|Christa|Lina|Lynn|Alban|Tim|Chris|Fakrul|Angad|Nolan|Christine|Anil|Marigem|Matan|Louisa|Timothy|Mirza|Donna|Steve|Chandan|Bethany|Oscar|Marcie|Joanne|Jitendra|Lorri|Manish|Brad|Swati|Alan|Larissa|Lori|Lana|Amanda|Anthony|Luana|Javaun|Max|Luke|Malvika|Lee|Nic|Lynne|Nathalie|Natalie|Brooke|Masafumi|Marty|Meredith|Miranda|Liza|Tanner|Jeff|Ghazzalle|Anna|Odetta|Toni|Marc|Meghan|Matt|Fai|Martha|Marjorie|Christina|Martina|Askhat|Leo|Leslie|As|Mandy|Jenene|Marian|Tia|Murali|Heidi|Jody|Mamatha|Sudhir|Yan|Frank|Lauren|Steven|Jessica|Monica|Aneta|Leanne|David|Mallory|Ianne|Melaine|Leeann|Arvid|Marge|Greg|Melinda|Alison|Deborah|Nikhol|Charles|Doug|Nicholas|Alexandre|Nels|James|Yvette|Muruganathan|Mangesh|Cfre|Claudia|Austin|Mara|Linda|Dana|Stewart|Oleg|Nikhil|Emilio|Lenn|Emiliano|Lennart|Cortney|Cullen|Lena|Garima|Levent|Nelson|Xun|Jenn|Noah|Marshall|Nozlee|Lois|Lars|Alissa|Casimir|Fiona|Mehul|Brian|Marvin|Hiedi|Ashley|Luise|Vinay|Mithun|Denise|Orlando|Madison|Colin|Mina|Nichole|Norman|M|Jason|Nereida|Damon|Mohamed|Tomas|Len|Liliana|Marybeth|Dave|Cole|Jennifer|Lucas|Milton|Makhija|Marlon|Miki|Joan|Barbara|Nevins|Marta|Angelique|Muriel|Cornelia|Monty|Mouthu|Jayson|Louis|Janet|Moore|Nathan|Luanne|Dheeraj|Chelley|Vishal|Laree|Ado|Mona|Lorena|Marco|Jeremy|Joe|Andrew|Lloyd|Mahalaxmi|Niamh|Daniel|Mitzi|Les|Laurence|Levonte|Nuno|Mj|Derek|Susan|Deandre|Nizar|Tanya|Maritza|Gabe|Imtiaz|Nira|Ervin|Maureen|Lalit|Lynwood|Li|Christopher|Min|Liz|Diane|Michaeline|Craig|Marianna|Becky|Leonard|Aj|Jeffrey|Edison|Csm|Clay|Marie|Jae|Bruce|Marcello|Lucille|Megha|Todd|Elizabeth|Angelica|Minette|Lynda|Liton|Carrie|Dennis|Amit|May|B|Laurel|Istiaq|Valerio|Sujesh|Vincent|Charley|Benj|Jeanine|Marcin|Ali|Arnaud|Mirna|Dianne|Namita|Melvin|Geroge|Omar|Wesley|Dominic|Adrian|Tina|Eric|Graciano|Leon|Mario|Brandon|Isabel|Antonio|Liang|Lara|Nadezhda|Navjot|Vicki|Danette|Nikia|Sunil|Leighann|Dustin|Adekunle|Natalia|Taylor|Darryl|Danny|Lorenza|Manny|Dorothy|Maryanne|Tarun|Lou|Oliver|Jay|Carla|Atle|Geoff|Mathew|Brit|Casey|Martijn|Laquita|Aaron|Mahesh|Althea|Lorra|Nina|Tammy|Ellie|Calvin|Marcia|Tamir|Meital|Cheryl|Gordon|Mujie|Marylou|Nicki|Manoj|Mitch|Tania|Hector|Dallan|Carol|Adenton|Nadira|Chengxiang|Naomi|Nirav|Frances|Lorelei|Methila|Ilias|Madhusudan|Jim|Noel|Harsha|Mayra|Masano|Nellie|Mengli|Lalita|Margo|Olga|Chase|Vineet|Mae|Akash|Vandhana|Naren|Ian|Niall|Alicia|Nate|Ben|Bill|Meagan|Madelene|Neha|Louise|Marti|Maarten|Asim|Earlyn|Nobumasa|Maaike|Sylvain|Mack|Maggie|Lester|April|Trent|Leland|Maged|Loren|Lycia|Leandrew|Learcell|Terra|Clara|Lasse|Nadine|Lew|Marquita|Marina|Leah|Miche|Brett|Hao|Lex|Maurice|Natasha|Moni|Melodie|Libby|Elliott|Aprajit|Ning|Lanette|Ivy|Liautaud|Merla|Mihaela|Heather|Nicola|Adger|Alyssa|Marusca|Donald|Mashay|Ashlee|Destine|Victor|Narin|Mathias|Branden|Geoffrey|Manjunath|Alexis|Dahlia|Mayer|Taras|Monte|Igor|Harry|Yonas|Obed|Albert|Darrell|Maxime|Zoe|Leigh|Tal|Thoai|Curtis|Cindy|Evan|Gomathy|Tessa|Elaheh|Marinca|Abby|Veronika|Onetta|Nikki|Mohsen|Edwin|Margie|Mick|Bonnie|Trina|Marilia|Nora|Leonor|Eddie|Gail|Arjan|Lorna|Mengwei|Aray|Ann|Wolfgang|Barb|Mahir|Swapna|Lijuan|Dinesh|Mayur|Marit|Beat|Maricela|Erika|Muhammad|Avi|Nestor|Anchal|Avni|Amber|Jessy|Luz|Midhat|Anita|Nandini|Lola|Nathaniel|Cleo|Jean|Lynette|Mitchell|Lawrence|Liviu|Madelyn|Nabil|Mila|Carson|Marcy|Mohammad|Bobby|Theresa|Lei|Nazim|Laurens|Chetan|Magdalena|Charlotte|Ana|Nissanka|Neil|Glenn|Mari|Miguel|Devin|Courtney|Mora|Jocelyn'.split('|')
	lnames = 'Scearcy|Sachchi|Ohalloran|Smith|Karahalios|Puglisi|Cordero|Pinero|Turcan|Poor|Tanaka|Henderson|Baltzer|Ivy|Jones|Mertens|Oyer|Polin|Lee|Greene|Sanchez|St|Kazi|Glowik|Mccann|Hogberg|Hutchinson|Morse|Hardy|Luke|Kincaid|Ceh|Guerrero|Roe|Vanderwert|Area|Singh|Ho|Koehler|Ask|Oakes|Vega|Sternfeldt|Huddleston|Massa|Interactive|Ruzsbatzky|Miller|Neeley|Posnock|Marando|Bright|Moyers|Walsh|Cataldi|Herbst|Lange|Shepherd|Nelson|Doherty|Willms|Lane|Romashkov|Trudeau|Bancu|Fraga|Wei|Kulkarni|Linkewich|Rouquette|Messer|Naypaue|Giafaglione|Bunting|Ahlersmeyer|Deschene|Viggers|Vadassery|Alves|Wilson|Trueworthy|Mukherjee|Sharp|Thomas|Prabhakar|Moore|Horikawa|Horne|Brostek|Richardson|Lewis|Alberti|Kelso|Mashita|Forsling|Dong|Diaz|Gibbs|Chitturi|Trackwell|Jeanne|Napoleon|Mclau|Craigie|Dacosta|Johnson|Farr|Martinez|Rauscher|Barclay|Webber|Delortlaval|Lin|Rinenbach|Weyand|Syed|Brady|Pathak|Fairchild|Ta|Higgins|Zhang|Kensey|Puthin|Malundas|Marom|Labed|Smagala|Zelenak|Capecelatro|Hambley|Causevic|Simmet|Schneider|Poovaiah|Enge|Maddatu|Wheeler|Henken|Fett|Goldston|Solanki|Arnce|Tamayo|Visa|Labruyere|French|Bennett|Shah|Osborne|Curley|Vaidya|Valachovic|Witters|Terrill|Thompson|Fryer|Price|Fulgieri|Queen|Moradi|Bell|Kort|Gillfoyle|Wosje|Aswal|Chelap|Wie|M.;4831600947|Niziolek|Whitley|Huntington|Drew|Santana|Basch|Simond|Bakke|Massi|Usuda|Mcquade|Rodgers|Kerpovich|Williams|Marciano|Ludeman|Strange|Spano|Hahn|Elgin|Mirkooshesh|Angottiportell|Deet|Pumphrey|Sandler|Vogel|Flynn|De|Wagner|Cheung|Dalberth|Skoog|Benavides|Ginsberg|Woodworth|Roachell|Monfeli|Sadow|Mejean|Song|Smurzynski|Mckee|Hunter|Gabdulov|Arnaboldi|Saxton|Worthy|Asd|Kee|Thigpen|Ormand|Schwartz|Sandberg|Pitner|Achutharaman|Seyot|Mientka|Hougom|Speer|Pearce|Hernandez|Long|Earley|Fulton|Chiavetta|Mcbrayer|Chamarthi|Barag|Kumar|Yang|Casari|Slicer|Lang|Bourgeois|Perry|Spivack|Taylor|Hughes|Seric|Barth|Hayter|Westerdale|Cook|Rico|Fasthoff|Trainor|Kleinman|Harverstick|Greenwell|Grady|Kirkpatrick|Saxon|Ujvari|Glander|Robinson|Goddard|Chen|Kramer|Caracache|Ramer|Baudet|Casner|Jenson|Butz|Hooper|Ramanathan|Marks|Dhawale|Ferguson|Huapaya|Mcdowell|Haehn|Piccolo|Carns|Jeffrey|Gibitz|Hsu|Jindra|Isaev|Gaikwad|Manganaro|Gerbelli|Sisson|Santiago|Izzo|Mills|Wiseen|Cooney|Libby|Miles|Mcgough|Fox|Koch|Rochelle|Mehta|Riffee|Erkok|Gibby|Freitas|Remund|Arones|Penn|Liu|Farkas|Kelkenberg|Samadzadeh|Castillo|Garrett|Cooper|Djuvik|Fishbane|Niedzielski|Kan|Hammond|Kruse|Rees|Leone|Vanbemmel|Ramani|Macdonald|Hall|Kiragu|Folkert|Tremaine|Zachry|Sherpard|Gearo|Richard|Voy|Weinem|Bhatia|Marder|Whittam|Garcia|Brannen|Mcindoe|Nandi|Mcgowen|Orr|Tamsitt|Kingsford|Lillie|Sheehan|Mylexsup|Davis|Yanez|Neal|Spinks|Massimo|Taulbee|Yunus|Maxian|Giuliano|Jorgenson|Sullivan|Obrien|Garcis|Allen|Kowalske|Wirtzberger|Kaiser|Millen|Mclaughlin|Sinclair|Messina|Lins|Robertson|Kindle|Velez|Vin|Argueta|Seltzer|Hayes|Clark|Slocum|Laski|Jim|Fey|Weston|Licata|Hanson|Mohlenkamp|Kos|Bilotti|Popke|Sloss|Campbell|Pham|Eby|Tipps|Walker|Hertzman|Harrell|Jansen|Kumarasamy|Lopez|Lindsley|Silver|Seremeth|Gorelick|Snider|Cauley|Ann|Garmatz|Ashcraft|Pawar|Kain|Coronel|Wilkes|Hinkle|Lloyd|Hassan|Ghangale|Kurtz|Trakic|Gibson|Shaheen|Calkins|Kuhlmann|Nishihara|Skrbin|Vanora|Fitzgerald|Trifler|Arriola|Krishnamurthy|Leleux|Weum|Dunne|Bairstow|Choi|Boyce|Joe|Ploshay|Tibbits|Minkley|Coshurt|Santos|Odonnell|Rios|Burkart|Turner|Parker|Racki|Paliferro|Wcislo|Donchatz|Ford|Ladak|Emmick|Mobed|Quiles|Gagne|Medrano|Hussain|Tejada|Alterson|Anastasia|Eddie|Adams|Motto|Brooks|Sharma|Byrum|Cheng|Kagan|Helman|Kim|Roller|Bordelon|Dozal|Mitchell|Barnes|Hummel|Fenton|Anderson|Reinbold|Dillard|Mattingly|Shcherbina|Mintz|Tullos|Siuda|Maggi|Lucas|Bouchard|Cortes|Dunning|Howard|Gower|Cotter|Kisner|Kennedy|Palacios|Levy|Uppal|Oholendt|Jew|Schultz|Dabrock|Peel|Cls|Deady|Park|Corradini|Sisneros|Hartnett|Nazaredth|Gentile|Hester|Richcreek|Giermak|Kay|Shadle|Pott|Kubey|Chacana|Rangel|York|Cooke|Squire|Roush|Tillman|Kandel|Roy|Sun|Herrmann|Chong|Knudsen|Coomer|Sarkar|Woodward|Banks|Allan|Schiller|Nicholls|Mahmud|Fiala|Horvath|Dangelo|Vickery|Somanathan|Sellier|Alejos|Ellis|Roska|Thibeault|Fuller|Brown|Roach|Bulgajewski|Oztekin|Sabol|Nomellini|Magnier|Berglund|Schau|Gramling|Francisco|Korman|Shubhy|Gossmeyer|Murray|Foster|Blevins|Arias|Soda|Litwin|Solak|Casey|Schmidt|Hartshorn|Deck|Leodoro|Swenson|Luc|Zamudio|Lacoe|Simko|Metz|Pace|Benjamin|Tolwinska|Little|Mcdonough|Lynch|Worley|Funk|Bachtle|Estes|Hennessey|Wurtzel|Jimenez|Pilogallo|Donaldson|Eng|Weiss|Coy|Bockstahler|Nekrasova|Rand|Gagen|Masters|Root|Eldert|Bleiler|Huang|Ryan|Janca|Cozart|Bhatara|Todd|Haylett|Mckinney|Adeniran|Oneill|Zamparini|Lafauce|Hetzel|Boers|Elder|Glaser|Kienzler|Reverendo|Cruse|Salafia|Bossard|Muir|Khanna|Orsatti|Mantheiy|Moorehead|Trevino|Delorme|Gregory|Gratwick|Mooney|Reitan|L|Flachaire|Simpson|Edwards|Humes|Probst|Wood|La|Hardesty|Rogers|Batten|Peifer|Devolt|Tesnovets|Hitchcock|Scarlata|Khot|Bush|Navale|Volper|Schnell|Emmons|Newton|Adkins|Roberts|Romaine|Barker|Louie|Richmond|Stear|Derr|Hallinger|See|Heller|Raveenthran|Bridges|Robison|Caney|Thaves|Darab|Corridore|Haas|Medved|Hain|Chiu|Chalmer|Sirotnak|Lavecchia|Buoniconti|Karpe|Poell|Massicot|Bauer|Augusty|Cfp|Guzman|Zuleta|Dijohnson|Whatley|Zickur|Denton|Mety|Dhani|Ren|Rivas|Chartier|Botuck|Mistry|Rigney|Hough|Rahman|Panagiotou|Bookbinder|Mcnabb|Reddy|Desma|Giampicclo|Granata|Shekleton|Shivaram|Marzan|Abramson|Mack|Hribar|Wolman|Machado|Weispfenning|Adcock|Sugiyama|Manning|Mcclure|Salinas|Yuan|Langer|Metcalf|Cherian|Baamonde|Lolam|Bealhen|Trout|Titkova|Gariti|Lamb|Myhrvold|Peltekian|Londergan|Zdroik|Filkins|Nichols|Dieter|Chaturvedi|Kotsikopoulos|Saqcena|Naranjo|Atkinson|Woodley|Kushner|Thorson|Ropple|Phoenix|Jaganathan|Gomar|Denham|Drelich|Livermore|Burns|Cartwright|Wickum|Kluger|Hockenhull|Heindl|Zak|Shipman|Saple|Besmond|Malone|Caldwell|King|Balfe|Tilton|Van|Iqbal|Shuffler|Berry|Panetta|Mori|Meijer|Mckeever|Grande|Stinson|Swanson|Wong|Gavilondo|Jaffe|Innes|Junker|Strickler|Fouad|Phillips|Stevens|Lemmon|Reinholz|Rogan|Krongold|Gremillon|Phipps|Loyd|Atkins|Downing|Parsons|Stanovich|Folger|Savio|Holmes|Osgood|Harris|Soloski|Galvin|Low|Jamt|Baldwin|Doohen|Dustman|Clopton|Zamora|Austin|Delery|Hansen|Samson|Buddin|Hollander|Xiong|Maultsby|Madore|Fortuna|Heckman|Cooey|Heise|Matsuda|Bent|Kar|Gahan|Wang|Yip|Butts|Lincoln|Dorminy|Golojuch|Florestal|Escarment|Aye|Sheldon|Petrova|Haines|Beaudoin|Watkins|Knuth|Balena|Shay|Bogush|Thomann|Blackwell|Carr|Pochiraju|Rauch|Waldeisen|Harding|Lacroix|Kolber|Horenstein|Hoegerman|Ilfeld|Wnorowski|Jacobs|Burnette|Gatto|Wandell|Anerella|Melara|Deisner|Merchant|Mount|Borchardt|Tschupp|Ciotola|Leung|Frailey|Lemons|Clement|Wattanavirun|Schmidheiny|Harness|Schechter|Gebert|Peralta|Stanley|Sandoval|Rangaswamy|Ranallo|Chrostowski|Wallach|Graham|Goltermann|Crosby|Boschman|Pelta|Szmagala|Fry|Konforti|Garduno|Dolan|Rockwell|Mcgah|Damm|Gebrewold|Benito|Chang|Yeboah|Coleman|Steib|London|Ashby|Schulman|Ferrara|Griffith|Sadrieh|Anetakis|Serrano|Konidaris|Kastenson|Barel|Le|Molina|Peterson|Leddy|Espinal|Cohn|Swamy|Chermiset|Link|Hobson|Pentzke|Shirneshan|Veno|Peters|Warren|Stanfield|Magnus|Grantham|Szabo|Hou|Juncherbenzon|Lara|Marlatt|Millbrooke|Sofastaii|Downer|Matheis|Galati|Olson|Wiederrecht|Quintana|Drozd|Weaver|Russell|Fisher|Dorrian|Morris|Ortiz|Newnam|Piper|Modic|Pfister|Butler|Tschetter|Tibbetts|Mattox|Frank|Curry|Zayas|Alvarez|Arrington|Hanlon|Freedman|Lineberry|Robyn|Morakinyo|Stokkel|Rinear|Zheng|Cutting|Driggers|Adil|Nikumbhe|Farver|George|Gyurko|Riley|Greve|Dreyer|Petschl|Hodzic|Rawe|Vijayakumar|Kang|Drees|Calderone|Alvarado|Watson|Belcher|Chaudhari|Panchal|Carnevale|Ayers|Studinger|D|Latib|Haksar|Oles|Dowland|Borreli|Serravalle|Vincent|Sachdeva|Wallace|Jain|Segal|Aguirre|Salihovic|Antonio|Viau|Marek|Murphy|Barratt|Fischer|Lennon|Mike|Ramaswamy|Defruscio|Hamby|Pallant|Clifton|Chenevert|Stuebe|Bloss|Rowe|Speak|Cupido|Debartolomeis|Katz|Brophy|Myster|Frazier|Olaru|Rojas|Straub|Keenan|Phan|Agresta|Mansour|Fiore|Pucci|Levin|Abrams|Cox|Lockwood|Vangilder|Olshan|Tyus|Murry|Crites|Leonard|Flores|Gonzalez|Young|Jones|Clark|Hill|Perez|Scott|Carter|Allen|King|Nguyen|Rodriguez|Allen|Thompson|Taylor|Sanchez|Walker|Wright|Mitchell|White|Baker|Lopez|Clark|Nelson|Baker|Garcia|Wright|Moore|Mitchell|Nguyen|Ramirez|Martin|Thompson|Lewis|Martinez|Baker|Wilson|Hall|Allen|Brown|Young|Roberts|Allen|Williams|Walker|Adams|White|Campbell|Nelson|Sanchez|Gonzalez|Williams|Anderson|Martin|Davis|Garcia|Thomas|White|Green|Lewis|Gonzalez|Carter|Roberts|Allen|Wilson|Walker|Roberts|Martin|Jackson|Flores|Campbell|Young|Davis|Hill|Adams|Davis|Torres|Perez|Wilson|Baker|Young|Thompson|Nguyen|Wright|Rivera|Anderson|Adams|Hill|Smith|Young|Walker|Baker|Campbell|Flores|Jackson|Davis|Harris|Sanchez|Torres|Wright|Thompson|Nguyen|Green|Thompson|Flores|Hernandez|Martin|Green|Mitchell|White|Nelson|Taylor|Torres|Lopez|Hernandez|Lewis|Martinez|Thompson|Thomas|Sanchez|Green|Martin|Campbell|Carter|Johnson|Thomas|Rivera|Rivera|Thompson|Wilson|Young|Mitchell|Mitchell|Roberts|Jackson|Adams|Ramirez|Perez|Harris|Williams|Williams|Sanchez|Lee|Martinez|Smith|Rivera|Jackson|Gonzalez|Robinson|Rivera|White|Garcia|Wright|Hill|Carter|King|Sanchez|Nelson|Rivera|Johnson|Ramirez|Miller|Rodriguez|Jackson|Flores|Jones|Walker|Rivera|Sanchez|Allen|Young|Campbell|Lewis|Jackson|Taylor|Rivera|Lewis|Davis|Thompson|Nguyen|Carter|Hernandez|Carter|Jackson|Anderson|Martinez|Robinson|Hall|Thompson|Walker|Adams|Jackson|Rodriguez|Martinez|Hill|Miller|Scott|Johnson|Johnson|Young|Nelson|Gonzalez|Miller|Perez|Baker|Allen|Williams|Rivera|Mitchell|Adams|Green|Torres|Lewis|Young|Flores|Wilson|Hill|Thomas|King|King|Davis|Smith|Thompson|Rodriguez|Brown|Scott|Ramirez|Nelson|Thomas|Harris|Ramirez|Lopez|Adams|Hill|Nelson|King|Sanchez|Hall|Davis|Adams|Baker|Nelson|Nelson|Gonzalez|Nelson|Davis|Brown|Hall|Lewis|Clark|Johnson|Johnson|Harris|Rivera|Walker|Garcia|Hill|Rodriguez|Harris|Flores|Brown|Wright|Nguyen|Hill|Perez|Nelson|Hernandez|Lee|Lee|Smith|Davis|Mitchell|Wright|Lewis|Davis|Rivera|Hill|Carter|Rodriguez|Mitchell|White|Wright|Walker|Lee|Miller|Sanchez|Williams|Mitchell|Martin|Thompson|Hernandez|Young|Walker|Rodriguez|Garcia|Jones|Nelson|Hall|Hall|Rodriguez|Green|Hernandez|Jackson|Rivera|Torres|Rivera|Martinez|Walker|Flores|Carter|Hill|Rodriguez|Wright|Moore|Moore|Thomas|Hill|Sanchez|King|Scott|Gonzalez|Davis|Green|Harris|Hernandez|Johnson|Young|Wright|Martinez|Smith|Davis|King|Robinson|Rodriguez|Rodriguez|Nguyen|Nguyen|Rivera|Garcia|Baker|Rodriguez|Ramirez|Lopez|Taylor|Jones|Johnson|Nguyen|Lewis|Martinez|Martinez|Hernandez|Smith|Anderson|King|Walker|Jackson|Miller|Flores|Brown|Garcia|Roberts|Thomas|Adams|Anderson|Baker|Williams|Wilson|Smith|Mitchell|Johnson|Lopez|Nguyen|Roberts|Hill|Lopez|Roberts|Thompson|Roberts|Hill|Green|Walker|Gonzalez|Sanchez|Moore|Torres|Torres|Brown|Campbell|White|Flores|Roberts|Martin|Nelson|Campbell|Thomas|Martinez|Rodriguez|Flores|King|Brown|Wilson|Gonzalez|Wright|Walker|Rivera|Garcia|Smith|Martinez|Young|Williams|Adams|Roberts|Clark|Flores|Wright|Thomas|Torres|Jackson|Nguyen|Brown|Smith|Walker|Roberts|Hernandez|Roberts|Hill|Nelson|Scott|Allen|Miller|Green|Ramirez|Brown|Hill|Walker|Lewis|Thompson|Scott|Davis|Thomas|Harris|Brown|Adams|Nelson|Garcia|Wright|Garcia|Jackson|Jackson|Lewis|Walker|Allen|Scott|Adams|Adams|Green|Lewis|Garcia|Ramirez|Torres|Wright|Roberts|Adams|Smith|Carter|Moore|Moore|Harris|Brown|Carter|Rodriguez|Wright|Young|Perez|Williams|Young|Taylor|Lee|Hernandez|Torres|Baker|Scott|King|Jackson|Young|Robinson|Perez|Moore|Hill|Harris|Nguyen|Thompson|Williams|Lewis|Anderson|Wilson|King|Clark|Wilson|Harris|Hall|White|Taylor|Young|Jones|Moore|Miller|Hernandez|Ramirez|Hernandez|Torres|Smith|Brown|Martinez|Williams|Moore|Baker|Anderson|Thompson|Harris|Rodriguez|Campbell|Young|Johnson|Miller|Hall|Adams|Wilson|Garcia|Flores|Thomas|Adams|Ramirez|Williams|Garcia|White|Scott|Davis|Campbell|Carter|Campbell|Roberts|Brown|Nguyen|Thompson|Martin|King|Martinez|Jackson|Flores|Green|Hall|Hernandez|Walker|Martin|Martinez|Carter|King|Roberts|Hernandez|Campbell|Clark|White|Nelson|Davis|Young|Harris|Hernandez|Nguyen|Rivera|Carter|Lewis|Harris|Lopez|Perez|Nguyen|Rodriguez|Wright|Lopez|Walker|Wright|Rodriguez|Harris|Garcia|Carter|Hill|Harris|Ramirez|Lee|Lopez|Nguyen|Flores|King|Walker|Green|Wright|Jackson|Robinson|Wright|White|Baker|Wilson|Perez|Ramirez|Campbell|Martin|Martin|Lewis|Garcia|Lewis|Roberts|Thomas|Thomas|Ramirez|Flores|Carter|Hall|Lewis|Williams|Hernandez|Lee|Mitchell|Nguyen|Mitchell|Miller|Clark|Hill|King|Torres|Nelson|Adams|Torres|Lewis|Allen|Moore|Baker|Thompson|Ramirez|Nguyen|Young|King|Roberts|Allen|Miller|Garcia|Campbell|Roberts|Rivera|Robinson|Harris|Sanchez|Gonzalez|Thomas|Flores|Mitchell|Davis|Nelson|Mitchell|Lee|Scott|Nelson|Perez|Brown|King|Jackson|Baker|Wilson|Hernandez|Lee|Nelson|Thomas|Thomas|Lopez|Carter|Campbell|Carter|King|Martinez|Brown|Scott|Lee|Allen|Flores|Mitchell|Adams|Green|King|Martin|Garcia|Taylor|Davis|Wright|Hall|Green|Anderson|Lee|Moore|Perez|Baker|Sanchez|King|Hill|Green|King|Jackson|Thomas|Nguyen|Hall|Johnson|White|Perez|Lopez|Martin|Perez|Wright|Taylor|Carter|Green|Flores|Williams|Brown|Nelson|Hall|Campbell|Torres|Martin|Martin|Torres|Martin|Wilson|Allen|Campbell|Thompson|Nguyen|Young|Thompson|Adams|Hall|Rodriguez|Carter|Harris|Torres|King|Nelson|Nelson|Torres|Hall|Lopez|Torres|Roberts|King|Hernandez|Flores|Lewis|Baker|White|Thomas|Nguyen|Hall|Harris|Lopez|Garcia|Taylor|Rodriguez|Jones|Walker|Scott|Torres|Wilson|Hernandez|Mitchell|Allen|Taylor|Young|Johnson|Thompson|Walker|Campbell|Baker|Wilson|Torres|Davis|Hernandez|Adams|Nguyen|Anderson|Smith|Ramirez|Martin|Hernandez|Garcia|Anderson|Rodriguez|White|Allen|Wilson|Lee|Davis|Taylor|King|Wilson|Torres|Campbell|Hall|Jones|Nguyen|Taylor|White|Hernandez|Flores|Green|Robinson|Clark|Brown|Walker|Williams|Moore|Lewis|Martin|Jackson|Johnson|Johnson|Anderson|Young|Brown|Ramirez|Roberts|Anderson|Rivera|Ramirez|Thomas|Miller|Sanchez|Anderson|Thomas|Wright|Williams|Torres|Lopez|Hernandez|Rivera|Campbell|King|Jackson|Rivera|Hernandez|Lopez|Garcia|Davis|Wright|Young|Taylor|Thompson|Harris|Martinez|Anderson|Davis|Gonzalez|Robinson|Wright|Rodriguez|Davis|Harris|Campbell|Hall|Ramirez|Nguyen|Hill|Wright|Miller|Nguyen|Rodriguez|Moore|Thompson|Walker|Sanchez|White|Mitchell|Rivera|Young|Mitchell|Lee|Williams|Robinson|Garcia|Brown|Baker|Thomas|Campbell|Green|Harris|Wright|Martin|Roberts|Nguyen|Brown|Williams|Hill|Nelson|Anderson|King|Gonzalez|Ramirez|Anderson|Johnson|Flores|Ramirez|Adams|Scott|Allen|King|Lewis|Jackson|Martinez|King|Carter|Mitchell|Johnson|Nguyen|Mitchell|Gonzalez|Ramirez|Garcia|Flores|Jackson|Martin|Davis|Allen|Ramirez|Johnson|Robinson|Campbell|Hall|Torres|Smith|Lewis|Martin|Rodriguez|Davis|Rivera|Hill|Young|Jackson|Campbell|Campbell|Hill|White|King|Taylor|Torres|Baker|Martin|Gonzalez|Nguyen|Gonzalez|Martin|Hall|King|Green|Campbell|Brown|Jackson|Hill|Davis|Lewis|Martin|Jackson|White|Miller|Martin|Ramirez|Hall|Nguyen|King|Clark|Miller|Hernandez|Smith|Hall|Harris|Roberts|Allen|Miller|Brown|Smith|Martinez|Roberts|Moore|Hernandez|Roberts|Moore|White|Davis|Taylor|Roberts|Lee|Davis|Lee|Thompson|Allen|Smith|Ramirez|Martinez|Martin|Robinson|Davis|Taylor|Rivera|Young|Gonzalez|Scott|Campbell|Johnson|Brown|Nguyen|Baker|Smith|Garcia|Davis|Jackson|Davis|Lewis|Lewis|Baker|Miller|Lewis|Campbell|Martinez|Robinson|Flores|Perez|Williams|Martin|Gonzalez|Martin|Moore|Ramirez|Rivera|Allen|Martinez|Perez|Jackson|Hall|Jackson|Smith|Taylor|Walker|Roberts|Harris|Lewis|Mitchell|Gonzalez|Wright|Adams|Gonzalez|Sanchez|Nelson|Green|Walker|Sanchez|Garcia|Rivera|Williams|Wright|Sanchez|Williams|Wright|Jackson|Lewis|Hill|Jackson|Baker|Rivera|Garcia|Harris|Thomas|Martin|Lewis|Carter|Walker|Martinez|Flores|Jones|Green|Martinez|Ramirez|Young|Clark|Rodriguez|King|Davis|Brown|Jones|Anderson|Mitchell|White|Allen|Garcia|Jones|Rodriguez|Harris|Lewis|Smith|Walker|Hill|Jackson|Moore|Baker|Scott|Lopez|Williams|Smith|Nguyen|Carter|Lewis|Hill|Hill|Hernandez|Brown|Lewis|Allen|Johnson|Young|Lewis|Rodriguez|Davis|Hill|Williams|Miller|Wilson|Nguyen|Hall|Moore|Smith|Garcia|Campbell|Baker|Thompson|Thompson|Anderson|Davis|Campbell|Hill|Thomas|Carter|Wright|Mitchell|Miller|Hernandez|Lee|Nelson|Walker|Hall|Ramirez|Adams|Rodriguez|Thompson|Harris|Johnson|Carter|Thomas|Anderson|Anderson|Nelson|Campbell|Hall|Rodriguez|Brown|Clark|Davis|Jackson|Wilson|Miller|Garcia|Allen|Martinez|Young|Ramirez|Hall|Davis|Wright|Roberts|Hernandez|Flores|Lopez|Williams|Jackson|Jones|Jackson|Hernandez|Johnson|Wright|Taylor|Mitchell|Harris|Allen|Brown|Harris|King|Scott|Thompson|Hall|Mitchell|Adams|Thompson|Green|Flores|Roberts|Thomas|Lee|Anderson|Lewis|Baker|Mitchell|Rivera|Carter|Baker|Jones|Thomas|Baker|Carter|Smith|Wilson|Moore|Wilson|Young|Ramirez|Davis|Rivera|Ramirez|Harris|Flores|Jones|Moore|Rodriguez|Wright|Harris|Martinez|Young|Scott|Martin|Gonzalez|Baker|Hernandez|Taylor|Smith|Hernandez|White|Thomas|Brown|White|Wilson|Carter|King|White|Perez|Allen|Hill|Hill|Rivera|Jones|Clark|Thomas|Thompson|Robinson|Rodriguez|Roberts|Rivera|Perez|Taylor|Perez|Martin|Nelson|White|White|Roberts|Robinson|Roberts|Lewis|Brown|Lee|Adams|Lee|Nguyen|Williams|Hernandez|Lewis|Martinez|Taylor|Jackson|Sanchez|Jackson|Ramirez|Wilson|Mitchell|Roberts|Thompson|Wilson|Davis|Torres|Harris|Flores|Clark|Nelson|Mitchell|Jones|Baker|Rodriguez|Hall|Adams|Scott|Lee|Williams|Nguyen|Taylor|Gonzalez|Perez|Carter|Lewis|Garcia|Wilson|Rivera|Allen|Rivera|Harris|Robinson|Robinson|Jackson|Green|Gonzalez|Baker|Nelson|Scott|Jones|Lewis|Miller|Sanchez|Moore|Williams|Allen|Carter|Rodriguez|White|Lewis|Garcia|Jackson|Ramirez|Clark|Jones|Rodriguez|Martinez|Brown|Lee|Sanchez|Hernandez|Rodriguez|Flores|Lewis|Harris|Lewis|Harris|Green|Jones|Davis|Hill|Garcia|Smith|Moore|Allen|Carter|Clark|Harris|Nelson|Nelson|Williams|Williams|Rodriguez|Wright|Torres|Taylor|Taylor|Baker|Mitchell|Lopez|Taylor|Walker|Nguyen|Lee|Thompson|Hall|Rodriguez|Baker|Baker|White|Lopez|Baker|Young|King|Campbell|Robinson|Lopez|Martin|Hernandez|Williams|Wright|Sanchez|Moore|Hernandez|Rivera|Miller|Roberts|Thompson|Nguyen|Nguyen|Jones|Carter|Robinson|Hernandez|Smith|Williams|Martinez|Jones|Anderson|Roberts|Taylor|Taylor|Young|Wilson|Torres|Green|Perez|Ramirez|Mitchell|Green|Smith|Hernandez|King|Martinez|Nguyen|Wright|Thompson|Campbell|Young|Hill|Brown|Walker|Thomas|Lopez|Gonzalez|Wright|Roberts|Nelson|Nguyen|Smith|Campbell|Moore|King|Garcia|Allen|Green|Perez|Robinson|Wright|Campbell|Williams|Martin|Nelson|Garcia|Allen|Rivera|Anderson|King|Rodriguez|Ramirez|Nguyen|Thomas|Walker|Walker|Martinez|Adams|Martinez|Wright|King|Davis|Jackson|Johnson|Taylor|Thompson|Williams|Hill|Wilson|Young|Williams|Ramirez|Johnson|Jones|Rivera|Jackson|Sanchez|Thomas|Anderson|Adams|Ramirez|Thomas|Martinez|Gonzalez|Young|Young|White|Harris|Hill|Rodriguez|Wilson|Brown|Thompson|Brown|Perez|Lee|Allen|Scott|Lewis|Johnson|Jackson|Moore|Johnson|Allen|Thompson|Baker|Hall|Robinson|Roberts|Perez|Lee|Johnson|Young|Adams|Smith|Anderson|Hill|Mitchell|Clark|Flores|Clark|Campbell|Brown|Hall|Rodriguez|King|Allen|Moore|Lopez|Roberts|Thomas|Nguyen|Carter|Allen|Green|Robinson|Clark|Johnson|Hall|Martinez|Wilson|Sanchez|King|Lopez|Torres|White|Harris|Gonzalez|Walker|Nelson|Baker|Torres|Scott|Martinez|Ramirez|Jones|Davis|Jackson|Smith|Rodriguez|Nguyen|Martinez|Perez|Martinez|Johnson|Baker|Clark|Johnson|Gonzalez|Walker|Allen|Anderson|Allen|Wright|Moore|Thomas|Martin|Lee|Adams|Wright|Hill|Hill|Nelson|Carter|Baker|Smith|Harris|Sanchez|Martinez|Lopez|Campbell|Sanchez|Rodriguez|Ramirez|Rodriguez|Johnson|Adams|Wilson|Smith|Robinson|Scott|Lee|Rodriguez|Walker|White|Davis|Anderson|Jones|Campbell|Brown|Lewis|Wright|Lee|Lee|Carter|Green|Robinson|Smith|Harris|Perez|Campbell|Jones|Wilson|Thomas|Davis|Harris|Lee|Mitchell|Hernandez|Nelson|Lee|Thomas|Nguyen|Davis|Clark|Perez|Lee|Martin|Campbell|Torres|Thomas|Moore|White|Lewis|Adams|Moore|Ramirez|Wilson|King|Gonzalez|Williams|Adams|Miller|Miller|Lopez|Smith|Scott|Williams|Campbell|Flores|Lewis|Scott|Garcia|Taylor|Smith|Thomas|Martinez|Lee|Scott|Jones|Lee|Scott|Clark|Moore|Allen|Carter|Baker|Clark|Jones|Gonzalez|Hernandez|Miller|Williams|Martin|Jackson|Adams|Williams|Campbell|Young|Johnson|Campbell|Rodriguez|Green|Jones|Young|Harris|Robinson|Perez|Young|King|Perez|Rodriguez|Baker|Taylor|Davis|Mitchell|Nelson|Davis|Ramirez|Adams|Campbell|Scott|King|Walker|Rodriguez|Hill|Thompson|Torres|Ramirez|Martin|Clark|Garcia|King|Lee|Thomas|Jackson|Brown|Mitchell|Nguyen|Wright|Smith|Hill|King|Perez|Brown|Wilson|Perez|Moore|Williams|Rodriguez|Young|Brown|White|Green|Lewis|Wilson|Roberts|Hernandez|Thomas|Nelson|Roberts|Brown|Harris|King|Carter|Lewis|Thomas|Nguyen|King|Rivera|Brown|Lee|Wright|Nelson|Miller|Jones|Clark|Taylor|Nguyen|Garcia|Lopez|Davis|Davis|Brown|Garcia|Johnson|White|King|Hall|Hernandez|Jackson|Rodriguez|Robinson|Jones|Nguyen|Sanchez|Smith|Taylor|Hernandez|Scott|Adams|White|Clark|Robinson|Gonzalez|Thompson|Clark|Hall|Hall|Jackson|Mitchell|Gonzalez|Torres|Robinson|Smith|Clark|Thompson|Harris|Green|Roberts|Nelson|Lee|Green|Sanchez|Hernandez|Young|Allen|Perez|Lopez|Garcia|Mitchell|King|White|Jones|Robinson|Torres|Rivera|Torres|Clark|Baker|Smith|Lewis|Torres|Nguyen|Sanchez|Adams|Campbell|Perez|Williams|Nelson|Nelson|Harris|Rivera|Roberts|Sanchez|Lopez|King|Lewis|Taylor|Lewis|Taylor|Walker|Brown|Lopez|Mitchell|Baker|Martinez|Davis|Taylor|Davis|Martinez|Anderson|Johnson|Clark|Campbell|Miller|Young|Miller|Wilson|Hill|Hall|Martin|Robinson|Scott|Torres|Perez|Martinez|Torres|Johnson|Martin|Scott|Johnson|Lopez|Rivera|Wright|Miller|Lee|Williams|Nguyen|Moore|Brown|Ramirez|Robinson|King|Lee|Martin|Johnson|Baker|Garcia|Baker|Rodriguez|Carter|Lee|Flores|Campbell|King|Jones|Carter|Martinez|Wilson|Perez|Thomas|Hall|Martinez|Wilson|Hall|Miller|Moore|Baker|Gonzalez|Brown|Roberts|Lewis|Campbell|Martinez|Allen|Rodriguez|Williams|Hall|Miller|Lewis|Young|Thomas|Jackson|Wright|Wilson|Campbell|Smith|Mitchell|Young|Martinez|Perez|Martin|Allen|Garcia|Rodriguez|Hall|Nguyen|White|Nguyen|Anderson|Johnson|Brown|Ramirez|Garcia|Garcia|Moore|Rivera|Lewis|Hall|Lopez|Taylor|Nelson|Baker|Thomas|Rivera|Anderson|Walker|White|Rodriguez|Hill|Allen|Garcia|Nguyen|King|Scott|Ramirez|Clark|Rodriguez|Allen|Lee|Gonzalez|Davis|Smith|Lewis|Taylor|Rodriguez|Adams|Williams|Roberts|Anderson|Clark|Brown|Lee|Allen|Lee|Walker|Green|Harris|Johnson|Moore|Thompson|Adams|Brown|Green|Lopez|Adams|Williams|Hernandez|Roberts|Robinson|Carter|King|Baker|Wright|Mitchell|Gonzalez|Lee|Robinson|Wilson|Wilson|Jackson|Adams|Hall|Flores|Garcia|Martinez|Adams|Allen|Brown|Harris|Nelson|Flores|White|Martinez|Green|Torres|Taylor|Lee|Rodriguez|Rodriguez|Sanchez|Rivera|Thomas|Walker|Green|Martin|Martin|Moore|Flores|Smith|Lewis|Rodriguez|Robinson|Flores|Thompson|Moore|Robinson|Davis|Nguyen|Mitchell|Baker|Lee|Carter|Thomas|Garcia|Scott|Davis|Nelson|Jackson|Taylor|Smith|Wright|Perez|Perez|Gonzalez|Jackson|Taylor|Rodriguez|Lopez|Adams|Martin|Jones|Anderson|Campbell|Hernandez|Smith|Roberts|Taylor|Ramirez|Lopez|Hernandez|Thomas|Clark|King|Walker|Rodriguez|Perez|Gonzalez|Jackson|Hall|Hernandez|Baker|Allen|Taylor|Miller|Roberts|Wright|Thomas|Nguyen|Thomas|Martin|Roberts|Baker|Nelson|Harris|Thomas|Nelson|Hall|Jones|Campbell|Anderson|Lee|Flores|Torres|Hernandez|Rivera|Jones|Martinez|Flores|Perez|Hall|Gonzalez|Nelson|Moore|Perez|Moore|Young|Campbell|Martinez|Sanchez|Harris|Lee|Hill|Hernandez|Perez|Jones|Thompson|Perez|Torres|Adams|Jones|Allen|Wright|Rodriguez|Rodriguez|Lewis|King|Lee|Baker|Lee|Clark|Wright|Rodriguez|Smith|Brown|Garcia|Taylor|Brown|Walker|Brown|Sanchez|Williams|Mitchell|Flores|Torres|Johnson|Thompson|Brown|Robinson|Robinson|King|Williams|Mitchell|Campbell|Young|Nguyen|Walker|Hernandez|Anderson|Williams|Lopez|Davis|Johnson|Baker|Brown|Jackson|Carter|Nelson|Robinson|Hernandez|Davis|Thomas|Hall|Martinez|Harris|Brown|Garcia|Anderson|Wilson|Torres|Harris|Sanchez|King|Lewis|Clark|Robinson|Jones|Nelson|Moore|Hill|Thomas|Harris|Smith|Mitchell|Nguyen|Lee|Garcia|Williams|Rivera|Baker|Brown|Lopez|Williams|Campbell|Hernandez|Moore|Sanchez|Walker|Lopez|Clark|Davis|Ramirez|Johnson|Scott|Martinez|Moore|Thomas|Thomas|Nguyen|Lee|Carter|Wilson|Hall|Roberts|Moore|Allen|Flores|Thompson|Nguyen|Gonzalez|Hernandez|Hernandez|Harris|Campbell|Rivera|Brown|Moore|Hill|Rivera|Smith|Wilson|Wilson|Lewis|Jones|Torres|Scott|Harris|Green|Adams|Walker|Campbell|Rodriguez|Brown|Jones|Brown|Young|Clark|Perez|King|Williams|Torres|Campbell|Mitchell|Lewis|Mitchell|Rivera|Johnson|Roberts|Mitchell|Garcia|Wright|Rivera|Anderson|Martin|Martinez|Wilson|Adams|Mitchell|Nguyen|Miller|Johnson|Flores|Anderson|Lopez|Hall|Clark|Walker|Brown|Williams|Campbell|Lewis|Hernandez|Green|King|Lee|Lewis|Anderson|Sanchez|Anderson|Moore|Robinson|Carter|Nelson|Miller|Martinez|Rivera|Young|Martin|King|Young|Garcia|Lopez|Anderson|Torres|White|Lopez|Wilson|Lewis|Baker|Lewis|Jackson|Jones|Walker|Clark|Martinez|Lee|Martin|Taylor|Hill|Hall|Walker|Flores|Jones|Hall|Walker|Scott|Hill|Nelson|Gonzalez|Adams|Walker|Rodriguez|Lewis|Sanchez|Nguyen|Wilson|Hernandez|Thomas|Carter|Moore|Martinez|Nelson|Hill|Wright|Taylor|White|Lewis|Adams|Flores|Mitchell|Jones|Nelson|Gonzalez|King|Ramirez|Adams|Ramirez|Carter|King|Moore|Nguyen|Mitchell|Scott|Harris|Nguyen|Harris|Baker|Davis|Lee|Adams|Martinez|Rivera|Harris|Thompson|Carter|Perez|Anderson|Walker|Jackson|Williams|Anderson|Moore|Lewis|White|Martinez|Garcia|Anderson|Wilson|Carter|Taylor|Nelson|Hill|Martinez|Young|Wilson|Taylor|Rivera|White|Johnson|Rivera|Rivera|Garcia|Wilson|Nelson|Wilson|Roberts|Roberts|Mitchell|Williams|Adams|Campbell|Moore|Perez|Hernandez|Torres|Hernandez|Robinson|Green|Flores|Moore|Perez|Martin|Harris|Hall|Allen|Jones|Carter|Wilson|Lee|Torres|Campbell|Torres|Smith|Miller|Sanchez|Hall|Adams|Brown|Williams|Flores|Baker|Johnson|Taylor|Miller|Sanchez|Lee|Taylor|Lee|Walker|Adams|Wright|Hall|Lewis|Roberts|Miller|Rivera|Sanchez|Martinez|Wilson|Rivera|Adams|Gonzalez|Flores|Roberts|Nelson|Scott|Miller|Rodriguez|Lewis|Allen|Anderson|Scott|Walker|Mitchell|Lewis|Nguyen|Roberts|Jackson|Hernandez|Young|Jones|Wilson|Johnson|White|Taylor|Rivera|Jones|Wilson|King|Wilson|Mitchell|Perez|Nelson|Nguyen|Carter|Miller|Gonzalez|Smith|Jones|Rivera|Green|White|Hall|Lee|Nelson|Garcia|Torres|Hernandez|Torres|Ramirez|Thomas|Thomas|Young|Lee|Wright|Garcia|Torres|Young|Ramirez|Taylor|Mitchell|Baker|Allen|Nguyen|Mitchell|Walker|King|Scott|Rodriguez|Torres|Nelson|Roberts|Brown|Williams|Garcia|Martinez|Clark|Campbell|Walker|White|Carter|Harris|Hill|Martin|Green|Nguyen|Allen|Mitchell|Thomas|Clark|Hill|Harris|Green|Hall|Lopez|Garcia|Ramirez|Taylor|Walker|Williams|Miller|Moore|Taylor|Carter|Thomas|King|Taylor|Jackson|Lewis|Wilson|Clark|Hernandez|Miller|Rivera|Baker|Wright|Roberts|Allen|Allen|Smith|Flores|Scott|Hernandez|Wright|Nelson|Lopez|Perez|Robinson|Martin|Perez|Gonzalez|Garcia|Johnson|Baker|Miller|Nguyen|Smith|Torres|Williams|Carter|Hernandez|Rivera|Campbell|Davis|Clark|Moore|Ramirez|Baker|Lewis|Perez|Allen|Flores|Thomas|King|Roberts|Gonzalez|Jackson|Wilson|Walker|Walker|Scott|Scott|Robinson|Wright|Smith|Miller|Rivera|Mitchell|Scott|Lewis|Lee|White|Young|Jackson|Mitchell|Rivera|Hall|Moore|Miller|Garcia|Hill|Ramirez|Clark|Wright|Anderson|Robinson|Lee|Mitchell|Garcia|Smith|Nguyen|Rivera|Hall|Clark|Allen|Campbell|Robinson|Hall|Carter|Robinson|Nelson|Ramirez|Thomas|Wright|Green|Hall|Lopez|Moore|Garcia|Miller|Lee|Martin|Thomas|Martin|Young|Perez|Adams|Mitchell|Davis|Walker|Flores|Wright|Sanchez|Williams|Scott|Perez|Campbell|Williams|Robinson|Nguyen|Thomas|Hill|Jones|Moore|Hill|Carter|Hill|Walker|Hill|Nelson|Torres|Scott|Thompson|Carter|Williams|Davis|Torres|Young|Davis|Rivera|Campbell|Davis|Walker|Taylor|Gonzalez|Ramirez|Thomas|Hernandez|Hernandez|Rivera|Perez|Thomas|Jackson|Davis|Gonzalez|Hill|Davis|Hall|Young|Martinez|Anderson|Ramirez|Nelson|Johnson|Miller|Lee|Green|Hernandez|Allen|Flores|Young|Young|Green|Scott|Scott|Scott|Mitchell|Nelson|Adams|Sanchez|Brown|Scott|Walker|Rodriguez|Moore|Nguyen|Young|Johnson|Miller|Green|Green|Walker|Nguyen|Clark|Lopez|Nguyen|Miller|Gonzalez|Campbell|Ramirez|Anderson|Thomas|Baker|Scott|Lewis|Davis|Nguyen|Jackson|Carter|Nguyen|Wilson|Harris|Flores|Hill|Lewis|Ramirez|Davis|Anderson|Thomas|Perez|Robinson|Davis|Allen|Nelson|Anderson|Baker|Torres|Adams|Allen|Smith|Rodriguez|Hernandez|Adams|White|Adams|Lewis|Robinson|King|Perez|Lee|Brown|Hernandez|Thompson|Martin|Rodriguez|Carter|Martinez|Hernandez|Campbell|Wright|Campbell|Lee|Baker|Harris|Walker|Miller|Johnson|Mitchell|Brown|Wright|Martinez|Lewis|Torres|Nguyen|Martinez|Hill|King|Rivera|Smith|Jones|Scott|Ramirez|Sanchez|Allen|Perez|Thomas|Moore|Brown|Wilson|Roberts|Harris|Young|Garcia|Green|Baker|Williams|Miller|Gonzalez|Rivera|Clark|Jackson|Mitchell|Hall|Miller|Young|Carter|Martinez|Young|Roberts|Lewis|Campbell|Mitchell|Clark|Carter|Lewis|Green|Smith|Harris|Campbell|Nguyen|Martinez|Scott|Sanchez|Martinez|Nelson|Lopez|Nelson|Hernandez|Moore|Rivera|Garcia|Thompson|Martin|Adams|Baker|Rivera|Harris|Wilson|Roberts|Baker|Jackson|Hernandez|Hernandez|Carter|Rodriguez|Gonzalez|Campbell|Martinez|Moore|Lopez|Scott|Rodriguez|Robinson|Sanchez|Wilson|Hall|Thompson|Perez|Nelson|Gonzalez|Gonzalez|Lewis|Mitchell|Sanchez|Rodriguez|Robinson|Miller|Lopez|Moore|Hill|Adams|Nguyen|King|Miller|Torres|Roberts|Allen|Nelson|Flores|Hall|Jones|Nguyen|Mitchell|Hill|Williams|Robinson|Perez|Smith|Roberts|Rivera|Martin|Martin|Roberts|Walker|Baker|Brown|Brown|Robinson|Sanchez|Nelson|Hernandez|Moore|Jackson|Young|Perez|Hill|Harris|Green|Jones|Jones|Hill|Rivera|Robinson|Ramirez|Brown|Perez|Baker|Thompson|Lopez|Thomas|Lewis|Smith|Carter|Martin|Campbell|Campbell|Hall|Lewis|Young|Nelson|Allen|Young|Sanchez|Allen|Lewis|Martin|Sanchez|Allen|Rodriguez|Clark|Lewis|Baker|Harris|Taylor|Anderson|Rivera|Davis|Mitchell|Thomas|Rivera|Jones|Sanchez|Robinson|Jones|Clark|Davis|Davis|Clark|Jones|Harris|Mitchell|Wilson|Perez|Young|Rodriguez|Young|Jones|Ramirez|Williams|Davis|Thomas|Lee|Taylor|Green|Hernandez|Hall|Wilson|Thomas|Young|Lewis|Brown|Roberts|Anderson|Flores|Nguyen|Johnson|Wright|Torres|Smith|Jackson|Campbell|Hernandez|Green|Moore|Nguyen|Gonzalez|Davis|Harris|Brown|Lewis|Hernandez|Martinez|Lee|Wright|Thompson|Nelson|Clark|Williams|Davis|Lewis|Thompson|Perez|Mitchell|Allen|Hernandez|Lopez|King|Wright|Allen|Martinez|Clark|Campbell|Baker|Mitchell|Green|Lopez|Allen|Wright|Campbell|King|Green|Torres|Rodriguez|Clark|Ramirez|Anderson|Lee|Roberts|Sanchez|Anderson|Lopez|Garcia|Anderson|Hernandez|Hernandez|Thompson|Wilson|Lopez|Lopez|Clark|Robinson|Martinez|King|Taylor|Perez|Gonzalez|Wright|Smith|Martinez|Roberts|Flores|Wilson|Carter|King|Gonzalez|Nguyen|Hall|Roberts|Thomas|Baker|Garcia|Ramirez|Rivera|Jones|King|Ramirez|Allen|Brown|Clark|Anderson|Green|Sanchez|Williams|Gonzalez|Ramirez|Williams|Lewis|Clark|Moore|Gonzalez|Moore|Adams|Torres|Garcia|Thompson|Carter|Gonzalez|Harris|Lee|Davis|Green|White|Lee|Hernandez|Carter|Campbell|Jones|Flores|Ramirez|Lee|Carter|Rodriguez|White|Lee|Perez|Perez|Taylor|Rodriguez|Ramirez|Hernandez|Martinez|Lee|Nelson|Walker|Green|Lee|Scott|Adams|Hall|Lopez|Clark|Campbell|Johnson|Hill|Roberts|Martin|Taylor|White|Sanchez|Flores|Sanchez|Smith|White|Allen|Martinez|Anderson|Hill|Scott|Rodriguez|Wilson|Flores|Roberts|Martinez|Moore|Harris|Ramirez|Wilson|Garcia|Taylor|Nelson|Green|Williams|Thomas|Martin|Campbell|Mitchell|King|Perez|Anderson|Lopez|Harris|Young|Ramirez|King|Garcia|Jones|Adams|Roberts|Wilson|Roberts|Nelson|Martin|Ramirez|Martinez|Wilson|Moore|Scott|Davis|Baker|Torres|Miller|Nelson|Adams|Walker|Walker|Davis|Gonzalez|Hall|Williams|Smith|Harris|Campbell|Rodriguez|Rivera|Martin|Wright|Martin|King|Perez|Johnson|Mitchell|Carter|Anderson|Rivera|Hill|Young|Carter|Carter|Lee|Wright|Jones|Smith|Brown|Wilson|Martinez|Green|Garcia|White|Sanchez|Walker|Hill|Roberts|Roberts|King|Roberts|Clark|Davis|Miller|Smith|Miller|Adams|Harris|Jones|Baker|Martin|Brown|Lewis|Jones|Rivera|Williams|Ramirez|Walker|Gonzalez|Perez|Williams|Williams|Lewis|Roberts|Martinez|Taylor|Carter|Torres|Gonzalez|Perez|Harris|Roberts|Thompson|Baker|Lopez|Sanchez|Rodriguez|Miller|Lewis|King|Rodriguez|Nguyen|Perez|Williams|Lee|Wright|Gonzalez|Lewis|Adams|Adams|Sanchez|Martinez|Ramirez|Williams|Hernandez|Sanchez|Thomas|Brown|Wilson|Baker|Carter|Martin|Brown|Anderson|White|Wright|Moore|Campbell|Miller|Miller|White|Scott|Miller|Johnson|Nelson|Harris|Nelson|Wilson|Sanchez|Hernandez|Allen|Campbell|Carter|Rivera|Lopez|Hall|White|Torres|Martin|Martin|King|Mitchell|Mitchell|Jackson|Green|Harris|Scott|Jackson|Hernandez|Green|Williams|Anderson|Martin|Lee|Garcia|Harris|Nelson|Campbell|Clark|Garcia|Anderson|Thomas|Brown|Hernandez|Jones|Ramirez|Davis|Lopez|Lopez|Lee|Thompson|Allen|Harris|Garcia|Rodriguez|Nelson|Adams|Brown|Johnson|Flores|Davis|Miller|Scott|Carter|Baker|Campbell|Scott|Harris|Hall|Lewis|White|White|Anderson|Sanchez|White|Davis|Anderson|Smith|Lee|Robinson|Lee|Hernandez|Rodriguez|Wilson|Nelson|Sanchez|Davis|Ramirez|Roberts|Lewis|Ramirez|Wilson|Hill|Nguyen|Martinez|Hill|Taylor|Mitchell|Mitchell|Robinson|Smith|King|Flores|Green|Lopez|Thompson|Wright|Smith|Campbell|Ramirez|Baker|Nguyen|Flores|King|Adams|Smith|Torres|Perez|Adams|Torres|Garcia|King|Mitchell|Hernandez|Rivera|Rivera|Campbell|Martinez|Thomas|Perez|Torres|Adams|Nelson|Scott|Miller|Anderson|Mitchell|Nguyen|Robinson|Gonzalez|Carter|Hill|Davis|Hill|Adams|Miller|Thomas|Lopez|Allen|Roberts|Thompson|Martin|Nguyen|Martinez|White|Thomas|Williams|Campbell|Brown|Moore|Carter|Martin|Torres|Martinez|Jones|Rodriguez|Allen|Carter|Nelson|Baker|Perez|Clark|Martin|Ramirez|Rodriguez|Martin|White|Brown|Rivera|Johnson|Hall|Torres|Young|Wilson|Harris|Smith|Green|Robinson|Martinez|Gonzalez|Brown|Taylor|Anderson|Harris|Wilson|Allen|Clark|Wilson|Smith|Nelson|Jackson|Jones|Hill|Smith|Allen|Roberts|Moore|Moore|Allen|Hernandez|Garcia|Martin|Perez|Ramirez|Hernandez|Baker|Jackson|Robinson|Hill|Gonzalez|Jackson|King|Garcia|Miller|Rodriguez|Adams|Robinson|Carter|Carter|Lee|Hill|Hernandez|Mitchell|Anderson|Wilson|Young|Brown|Wright|Nguyen|Flores|Hill|Lee|Sanchez|Adams|Hernandez|Young|Davis|Lee|Jackson|Rodriguez|Scott|Wilson|Moore|Mitchell|Green|Nelson|Torres|Nelson|White|Taylor|Martin|Brown|Adams|Torres|Adams|Jackson|Martin|Allen|Wilson|Garcia|Sanchez|Roberts|Green|Davis|Gonzalez|Mitchell|Moore|Brown|Thomas|Rivera|Baker|Lee|Clark|Garcia|Young|Davis|Harris|Smith|Lewis|Martinez|Garcia|Moore|Lopez|Green|Young|Jones|Green|Scott|White|Hernandez|Nelson|Nelson|Nelson|Scott|Hill|Baker|Campbell|Roberts|Green|Brown|Gonzalez|Young|Walker|Hall|Jones|Nguyen|Nguyen|Rodriguez|Lewis|Perez|Martin|Baker|Wilson|Taylor|White|Allen|Sanchez|Mitchell|Young|Roberts|Garcia|Campbell|Rivera|Hernandez|Torres|Smith|Martin|Davis|Hill|Rodriguez|Torres|Lewis|Wright|Roberts|Taylor|Johnson|Clark|Moore|Lee|Nguyen|Thompson|Smith|Williams|Lewis|Nguyen|Perez|Anderson|Allen|Hernandez|Sanchez|Thompson|Brown|Taylor|Nguyen|Lopez|Moore|Brown|Flores|Rodriguez|Wilson|Smith|Miller|Ramirez|Nguyen|Miller|Martin|Hall|Perez|Scott|Hill|Martin|Rodriguez|Brown|Jackson|Jones|Lee|Sanchez|Roberts|Gonzalez|Williams|Flores|Hall|Williams|Johnson|Ramirez|Brown|Thomas|Rivera|Hernandez|Lopez|Hill|Nguyen|Lewis|Smith|Moore|Walker|Taylor|Nelson|Lee|Jackson|Jones|Mitchell|Wilson|Smith|Lopez|Lewis|Hill|Clark|Lopez|Lee|Flores|Johnson|Walker|Williams|Moore|Hill|Wilson|Hill|Torres|Perez|Hernandez|Lee|Rivera|Jackson|Garcia|Campbell|White|Wilson|Rivera|Clark|Clark|Taylor|Wright|Sanchez|Walker|Garcia|Robinson|Jones|Perez|Davis|Lopez|Hernandez|Taylor|Miller|Smith|Hill|Nelson|Brown|Clark|Young|Rivera|Ramirez|Allen|Campbell|King|Thompson|Adams|Martinez|Mitchell|Anderson|Hill|Thomas|Clark|Lopez|Harris|Williams|Campbell|Allen|Baker|Garcia|Johnson|Walker|Jones|Perez|Nelson|Walker|Adams|Moore|Lewis|Carter|Torres|Campbell|Roberts|King|Mitchell|Clark|Lopez|Hall|Rodriguez|Lopez|Martinez|Scott|Garcia|Roberts|Rivera|Thomas|Hill|White|Allen|Perez|Wilson|Walker|Campbell|Lee|Campbell|Rivera|Moore|Hernandez|Jones|Johnson|Hill|Walker|Williams|Miller|Taylor|Green|Baker|Hall|Rodriguez|Anderson|Robinson|Davis|Johnson|Hill|King|Rodriguez|Wilson|Miller|Campbell|Brown|Nguyen|Taylor|Nelson|Gonzalez|Sanchez|Roberts|Garcia|Williams|Lopez|Nelson|Jones|Moore|Lewis|Garcia|Baker|Ramirez|Wright|Williams|Jones|Moore|Allen|Torres|Martinez|Johnson|Baker|Campbell|Hernandez|Rivera|Nelson|Torres|Campbell|Moore|Taylor|White|Thompson|Hill|Lopez|Williams|Smith|Wright|Miller|Clark|Martin|Thompson|Lee|Mitchell|Rivera|Harris|Adams|Jones|Clark|Davis|Wright|Wright|Hall|Campbell|Green|Campbell|Miller|Anderson|Anderson|Jones|Green|Wright|Roberts|Hall|King|Thomas|White|Torres|Torres|Taylor|Torres|Hernandez|Nguyen|Clark|Walker|Hill|Jones|Davis|Hill|Wright|Lewis|Hernandez|King|Mitchell|Mitchell|Rodriguez|Young|Lewis|King|Robinson|Anderson|Nguyen|Mitchell|Lewis|White|Rivera|Green|Hall|Hernandez|Wilson|Anderson|Thompson|Gonzalez|Rivera|King|King|Mitchell|Wright|Lee|Rivera|Rodriguez|Flores|Hernandez|Walker|Perez|Hall|Adams|White|Wilson|Robinson|Adams|Wilson|Moore|Johnson|Torres|Roberts|Mitchell|Miller|Hill|Brown|Young|Jackson|Garcia|Johnson|Taylor|Thomas|Mitchell|Walker|Thompson|Lopez|Davis|Ramirez|Clark|Martinez|Flores|Nguyen|Hall|Brown|Flores|Young|Mitchell|Campbell|Perez|Roberts|Moore|Rodriguez|Anderson|Nelson|Davis|Allen|Robinson|Harris|Walker|Baker|Lopez|Green|Scott|Brown|Thompson|Wright|Lewis|Carter|Baker|Rodriguez|Jackson|King|Miller|Flores|Harris|Baker|Nguyen|Torres|White|Lopez|Scott|Carter|Williams|Martinez|Green|Baker|Harris|Nelson|Green|Hall|Wright|Gonzalez|Martinez|Carter|Gonzalez|Davis|Green|Martin|Anderson|Thomas|Allen|Mitchell|Nguyen|Lopez|Walker|Garcia|Smith|Wright|Wright|Wright|Ramirez|Harris|Nguyen|Hernandez|Perez|Anderson|Mitchell|Wilson|King|Johnson|Adams|Hall|Adams|Green|King|Lee|Sanchez|Nguyen|Brown|Harris|Mitchell|Robinson|King|Nelson|Rivera|Allen|Taylor|Sanchez|Anderson|Clark|Thompson|Robinson|Anderson|Walker|Johnson|Ramirez|Ramirez|Thompson|Adams|Sanchez|Garcia|Nelson|Smith|King|Carter|Lee|Clark|Clark|Taylor|Allen|Moore|Jones|Garcia|Ramirez|Campbell|Anderson|Jones|Mitchell|Sanchez|Martin|Davis|Ramirez|Torres|Adams|Roberts|Hill|Rodriguez|Harris|Thomas|Scott|Wilson|Martin|Scott|Miller|Wright|Nguyen|Martin|Young|Rodriguez|Moore|Gonzalez|Lewis|Ramirez|Davis|Green|Thomas|King|Garcia|Lee|Smith|Hernandez|Allen|Williams|Wright|Nelson|Campbell|Martinez|Johnson|Young|Rivera|Sanchez|Ramirez|Jackson|Jones|Torres|Hall|Nelson|Davis|Johnson|Roberts|Flores|Walker|Sanchez|Rivera|Lewis|Young|Lee|Johnson|Mitchell|Moore|Roberts|Baker|Lewis|Perez|Garcia|Nguyen|Thomas|Moore|Baker|Lewis|Anderson|Brown|Wilson|Martinez|Hernandez|Smith|Roberts|Thomas|Thompson|Lewis|Smith|Carter|Smith|Thompson|Flores|Campbell|Roberts|Sanchez|Garcia|Hernandez|Perez|Wright|Roberts|Carter|Smith|Garcia|Hernandez|Allen|Gonzalez|Torres|Baker|Garcia|White|Hall|Campbell|Nelson|Allen|Williams|Miller|Jones|Rodriguez|Lee|Moore|Adams|Clark|Clark|Hill|Thomas|Smith|Allen|Nelson|Moore|Rodriguez|Walker|White|Scott|Harris|White|Jones|Flores|Moore|Thomas|Wilson|Rodriguez|Mitchell|Miller|Davis|Perez|Moore|Garcia|Jackson|Lopez|Carter|Moore|Hernandez|Ramirez|Carter|Clark|Scott|Hernandez|Smith|Adams|Allen|Mitchell|Williams|Garcia|Hall|Thompson|Hernandez|Allen|Smith|Martin|Davis|Jones|Hall|Clark|Rodriguez|Martin|Flores|Harris|Lee|Jones|Thomas|White|Sanchez|Roberts|Hall|Flores|Thompson|Sanchez|Anderson|Allen|Jackson|Green|Thomas|Wilson|Mitchell|Garcia|King|Anderson|Nelson|White|Sanchez|Harris|Jones|Williams|Rodriguez|Roberts|Smith|Young|Hill|Johnson|Allen|Rivera|Smith|Sanchez|Lee|Perez|Wilson|Nelson|Garcia|Lewis|Perez|King|Rodriguez|Green|Scott|Ramirez|Hill|Rivera|Hall|King|Walker|Hernandez|Rivera|Smith|Rodriguez|Roberts|Hill|Wilson|Sanchez|Hernandez|Wilson|Moore|Green|Lopez|Gonzalez|Green|Wilson|Nguyen|Martinez|Rodriguez|Thomas|Campbell|White|Lopez|Flores|Moore|Clark|Torres|Robinson|Mitchell|Carter|Campbell|Williams|Baker|Smith|Johnson|Flores|Hall|Martinez|Miller|Brown|Davis|Campbell|Campbell|King|Brown|Nguyen|Walker|Harris|Wilson|Hill|Mitchell|Carter|Mitchell|Harris|Martin|Robinson|Martinez|Wilson|Ramirez|Wilson|Brown|Campbell|Carter|Hernandez|Johnson|Sanchez|Martinez|Davis|Perez|Roberts|Baker|Lee|King|Martin|Brown|Wilson|Smith|Brown|Lopez|Campbell|Clark|Thomas|Thompson|Roberts|Jones|King|Johnson|Lopez|Smith|King|Smith|Moore|Wilson|Jones|Campbell|Robinson|Martinez|Rodriguez|Davis|Hall|Davis|Carter|Davis|Moore|Wright|Smith|Hall|Brown|Jackson|Anderson|Roberts|Lee|Hernandez|Ramirez|Moore|Thompson|Brown|Martinez|Perez|Scott|Allen|Harris|Flores|Roberts|Garcia|Hall|Harris|Jones|Moore|White|Martin|Hill|Anderson|Smith|Adams|Sanchez|Campbell|Campbell|Torres|Clark|Ramirez|Mitchell|Anderson|Johnson|Moore|Ramirez|Rivera|Roberts|White|Ramirez|Carter|Moore|Lee|Torres|Torres|Harris|Robinson|Campbell|Ramirez|Gonzalez|Miller|Thompson|Scott|Walker|Wright|Rivera|Hill|Rivera|Anderson|Perez|Adams|Green|Scott|Jackson|Nelson|Wright|Mitchell|Jackson|Williams|Campbell|Allen|Rivera|Lopez|Jackson|Nelson|Gonzalez|Martin|Smith|King|Rodriguez|Young|Jones|Robinson|Gonzalez|Johnson|Johnson|Thomas|Thompson|Gonzalez|Thompson|Nelson|Campbell|Davis|Clark|Walker|Lewis|Hill|Roberts|Roberts|Campbell|Rivera|Nguyen|Lewis|Clark|Torres|Mitchell|Moore|Wright|Allen|Torres|Robinson|Wilson|Miller|Nelson|Torres|Thomas|Brown|Robinson|Ramirez|Brown|Smith|Clark|Walker|Clark|Thomas|Allen|White|Lewis|Scott|Rodriguez|Moore|Gonzalez|Campbell|Anderson|Adams|Lee|Carter|Nelson|Carter|White|Jackson|Miller|Williams|Hernandez|Mitchell|Roberts|Torres|Allen|Wilson|Clark|White|Carter|Roberts|Thomas|Davis|Moore|Sanchez|Miller|Anderson|Thompson|Lee|Young|Moore|Rivera|Garcia|Scott|Campbell|Green|Miller|Rodriguez|Jackson|Thompson|Adams|Martin|Rodriguez|Martinez|Jackson|Adams|Hill|Green|Lopez|Jones|Torres|Wilson|Martin|Gonzalez|Young|Nelson|Martin|Young|Thompson|Hernandez|Perez|Williams|Garcia|Jones|Lee|Rivera|Allen|Allen|Hall|Adams|Brown|Robinson|Green|Thomas|Hill|Harris|Torres|Allen|Sanchez|Johnson|Lewis|Perez|Green|Robinson|Miller|Green|Martinez|Roberts|Garcia|Gonzalez|Ramirez|Williams|Nelson|Davis|Smith|Allen|Johnson|Roberts|Wright|Robinson|Garcia|Allen|Jackson|Sanchez|Taylor|Smith|Thompson|Rivera|Anderson|Lewis|Hernandez|Robinson|Lee|Martin|Garcia|Williams|Lee|Sanchez|Nelson|Davis|Mitchell|Hernandez|Rodriguez|Roberts|Rivera|Mitchell|Wilson|Allen|Jackson|Lee|Taylor|Rivera|Torres|Nguyen|Rivera|Sanchez|Jackson|Thompson|Williams|Adams|Johnson|White|Hall|Harris|Miller|White|Martin|Hernandez|Smith|Anderson|Robinson|Thompson|Walker|White|Martin|Perez|Campbell|Hernandez|Thompson|Flores|Harris|Lopez|Roberts|Hernandez|Brown|Martin|Taylor|Williams|Nguyen|Rodriguez|Anderson|Martinez|Jackson|Scott|Nelson|Lopez|Adams|Hill|Wright|Garcia|Moore|Rivera|White|Ramirez|Clark|Johnson|Martin|Scott|Johnson|Wilson|Williams|Hill|Miller|Johnson|Harris|Clark|Martinez|Lopez|Carter|Jackson|Johnson|Sanchez|Thomas|Ramirez|King|Wright|Hall|Young|Wilson|Miller|Anderson|Anderson|Taylor|Martin|Harris|Smith|Mitchell|Moore|Lee|Harris|White|Mitchell|Johnson|Lopez|Sanchez|Clark|Taylor|Lee|Hernandez|Sanchez|Jones|Martinez|Robinson|Rodriguez|Harris|Lee|Harris|Adams|Young|Smith|Hernandez|Walker|Torres|Sanchez|Mitchell|Thomas|Rivera|Anderson|Jones|Roberts|Ramirez|Sanchez|Johnson|Carter|Mitchell|Roberts|Davis|Perez|Rivera|Sanchez|Martinez|Miller|Flores|Jackson|Brown|Thomas|Rivera|Johnson|Allen|Gonzalez|Williams|Lee|Anderson|Nelson|Clark|Rivera|Carter|Lewis|Allen|Baker|Perez|Smith|Hernandez|White|Garcia|Lopez|King|Perez|Martinez|Hill|Nguyen'.split('|')
	return [random.choice(fnames), random.choice(lnames)]

def load_config():
	global config, smtp_pool_array, threads_count
	head_name = 'madcatmailer'
	temp_config = configparser.ConfigParser({
		'smtps_list_file': '',
		'mails_list_file': '',
		'mails_to_verify': '',
		'mail_from': '',
		'mail_reply_to': '',
		'mail_subject': '',
		'mail_body': '',
		'attachment_files': '',
		'redirects_file': '',
		'add_read_receipts': '',
		'add_high_priority': '',
	})
	if len(sys.argv) == 2:
		config['config_file'] = sys.argv[1] if is_file_or_url(sys.argv[1]) else exit(err+'wrong config path or filename: it must be like '+bold('<...>.config'))
	else:
		try:
			config['config_file'] = max([i for i in os.listdir() if re.search(r'.+\.config$', i)], key=os.path.getctime)
		except:
			open('dummy.config','w').write(read(dummy_config_path))
			print(wrn+'nor '+bold('.config')+' files found in current directory, nor provided as a parameter')
			exit( wrn+'sample '+bold('dummy.config')+' file downloaded to the current directory. please check and edit it before next run')
	temp_config.read(config['config_file'])
	if not temp_config.has_section(head_name):
		exit(err+'malformed config file')
	for key, value in temp_config.items(head_name):
		config[key] = value
	if not is_file_or_url(config['smtps_list_file']):
		exit(err+'cannot open smtps list file. does it exist?')
	else:
		config['smtps_errors_file'] = re.sub(r'\.([^.]+)$', r'_error_log.\1', config['smtps_list_file'])
		smtp_pool_array = read_lines(config['smtps_list_file'])
		for smtp_line in smtp_pool_array:
			smtp_pool_tested[smtp_line] = 0
			not re.findall(r'^[\w.+-]+\|\d+\|[@\w.+-]+\|[^|]+$', smtp_line) and exit(err+'"'+smtp_line+'" is not like "host|port|username|password"')
	threads_count = len(smtp_pool_array)*5 if len(smtp_pool_array)*5<40 else 40
	if not is_file_or_url(config['mails_list_file']):
		exit(err+'cannot open mails list file. does it exist?')
	else:
		config['mails_dangerous_file'] = re.sub(r'\.([^.]+)$', r'_dangerous.\1', config['mails_list_file'])
	if len([is_valid_email(mail) for mail in config['mails_to_verify'].split(',')])<config['mails_to_verify'].count(',')+1:
		exit(err+'not all test emails looks valid. check them, please')
	config['mail_from'] or exit(err+'please fulfill '+bold('mail_from')+' parameter with desired name and email')
	config['mail_reply_to'] = config['mail_reply_to'] or config['mail_from']
	config['mail_subject'] or exit(err+'please fulfill '+bold('mail_subject')+' parameter with desired email subject')
	config['mail_body'] or exit(err+'please put the path to email body file or mail body itself as a string into '+bold('mail_body')+' parameter')
	config['attachment_files'] = config['attachment_files'].split(',') if config['attachment_files'] else []
	for file_path in config['attachment_files']:
		if not is_file_or_url(file_path) and not (os.path.isdir(file_path) and rand_file_from_dir(file_path)):
			exit(err+file_path+' file not found or directory is empty')
	if config['redirects_file'] and not is_file_or_url(config['redirects_file']):
		exit(err+'please put the path to the file with redirects into '+bold('redirects_file')+' parameter')
	else:
		config['redirects_list'] = read_lines(config['redirects_file']) if config['redirects_file'] else ['']

def fill_mail_queue():
	global mail_que, total_mails_to_sent, inbox_test_id, test_mail_str, config
	for i in read_lines(config['mails_list_file']):
		i = normalize_delimiters(i)
		if extract_email(i):
			mail_que.put(i)
			if not test_mail_str:
				test_mail_str = i.replace(extract_email(i), f'st-3-{inbox_test_id}@spamtest.glockdb.com')
	if not mail_que.qsize():
		exit(err+'not enough emails. empty file?')
	total_mails_to_sent = mail_que.qsize()

def setup_logs_writer():
	threading.Thread(target=logs_writer, daemon=True).start()

def setup_threads():
	global threads_count, threads_counter, threads_statuses, mail_que, results_que
	sys.stdout.write('\n'*threads_count)
	threading.Thread(target=every_second, daemon=True).start()
	threading.Thread(target=printer, daemon=True).start()
	for i in range(threads_count):
		threading.Thread(name='th'+str(i), target=worker_item, args=(mail_que, results_que), daemon=True).start()
		threads_counter += 1
		threads_statuses['th'+str(i)] = 'no data'

def every_second():
	global total_sent, speed, mem_usage, cpu_usage, net_usage, loop_times, loop_time, no_jobs_left
	total_sent_old = total_sent
	net_usage_old = 0
	time.sleep(1)
	while True:
		try:
			speed.append(total_sent - total_sent_old)
			speed.pop(0) if len(speed)>10 else 0
			total_sent_old = total_sent
			mem_usage = round(psutil.virtual_memory()[2])
			cpu_usage = round(sum(psutil.cpu_percent(percpu=True))/os.cpu_count())
			net_usage = psutil.net_io_counters().bytes_sent - net_usage_old
			net_usage_old += net_usage
			loop_time = round(sum(loop_times)/len(loop_times), 2) if len(loop_times) else 0
		except:
			pass
		time.sleep(0.1)

def logs_writer():
	global config, smtp_errors_que, mails_dangerous_que
	with open(config['smtps_errors_file'], 'a') as smtps_errors_file_handle, open(config['mails_dangerous_file'], 'a') as mails_dangerous_file_handle:
		while True:
			while not smtp_errors_que.empty():
				smtp_str, msg, smtp_sent = smtp_errors_que.get()
				smtps_errors_file_handle.write(now()+' '+smtp_str+' ('+str(smtp_sent)+' emails): '+msg.split('\b')[-1]+'\n')
				smtps_errors_file_handle.flush()
			while not mails_dangerous_que.empty():
				mail_str, is_dangerous = mails_dangerous_que.get()
				mails_dangerous_file_handle.write(now()+' '+mail_str+': '+is_dangerous+'\n')
				mails_dangerous_file_handle.flush()
			time.sleep(0.05)

def printer():
	global total_sent, skipped, total_mails_to_sent, speed, loop_time, cpu_usage, mem_usage, net_usage, threads_count, threads_statuses, smtp_pool_array, time_start, got_updates
	while True:
		clock = sec_to_min(time.time()-time_start).replace(':', (' ', z+':'+b)[int(time.time()*2)%2])
		status_bar = (
			f'{b}['+green('\u2665',int(time.time()*2)%2)+f'{b}]{z}'+
			f'[ {bold(clock)} \xb7 sent/skipped: {bold(num(total_sent))}/{bold(num(skipped))} of {bold(num(total_mails_to_sent))} ({bold(round((total_sent+skipped)/total_mails_to_sent*100))}%) ]'+
			f'[ {bold(num(sum(speed)))} mail/s ({bold(loop_time)}s/loop) ]'+
			f'[ cpu: {bold(cpu_usage)}% \xb7 mem: {bold(mem_usage)}% \xb7 net: {bold(bytes_to_mbit(net_usage*10))}Mbit/s ]'+
			f'[ {bold(num(len(smtp_pool_array)))} smtps left ]'
		)
		if got_updates:
			sys.stdout.write(up*threads_count)
			for name, status in threads_statuses.items():
				print(wl+status)
			got_updates = False
		print(wl+status_bar+up)
		time.sleep(0.05)

signal.signal(signal.SIGINT, quit)

config = {}
threads_counter = 0
total_mails_to_sent = 0
time_start = time.time()
mail_que = queue.Queue()
results_que = queue.Queue()
smtp_errors_que = queue.Queue()
mails_dangerous_que = queue.Queue()
smtp_pool_array = []
smtp_pool_tested = {}
threads_statuses = {}
test_mail_str = ''
threads_count = 40
connection_timeout = 5
total_sent = 0
skipped = 0
speed = []
mem_usage = 0
cpu_usage = 0
net_usage = 0
loop_times = []
loop_time = 0
got_updates = False

window_width = os.get_terminal_size().columns-40
resolver_obj = dns.resolver.Resolver()
inbox_test_id = ''.join(random.choice(string.ascii_lowercase+string.digits) for i in range(8))

show_banner()
tune_network()
check_ipv4()
check_ipv6()
load_config()
fill_mail_queue()
setup_logs_writer()

print(inf+'ipv4 address:                  '+bold(socket.has_ipv4 or '-')+' ('+(socket.ipv4_blacklist or green('clean'))+')')
print(inf+'ipv6 address:                  '+bold(socket.has_ipv6 or '-'))
print(okk+'loading config:                '+bold(config['config_file']))
print(inf+'smtp servers file:             '+bold(config['smtps_list_file']+' ('+num(len(smtp_pool_array))+')'))
print(inf+'smtp errors log:               '+bold(config['smtps_errors_file']))
print(inf+'emails list file:              '+bold(config['mails_list_file']+' ('+num(total_mails_to_sent)+')'))
print(inf+'dangerous emails log:          '+bold(config['mails_dangerous_file']))
print(inf+'verification emails:           '+bold(config['mails_to_verify']))
print(inf+'mail body:                     '+bold(config['mail_body']))
print(inf+'attachments:                   '+bold(config['attachment_files'] or '-'))
print(inf+'file with redirects:           '+bold(config['redirects_file'] or '-'))

test_inbox()

input(npt+'press '+bold('[ Enter ]')+' to start...')

setup_threads()

while True:
	time_takes = round(time.time()-time_start, 1)+0.09
	while not results_que.empty():
		thread_name, thread_status, mails_sent = results_que.get()
		total_sent += 1 if '+\b' in thread_status else 0
		skipped += 1 if '-\b' in thread_status else 0
		mails_per_second = round(mails_sent/time_takes, 1)
		threads_statuses[thread_name] = f'{thread_name}: '.rjust(7)+str_ljust(thread_status, window_width)+f'{mails_sent} sent ({mails_per_second} mail/s)'.rjust(23)
		got_updates = True
	if threads_counter == 0:
		if mail_que.empty():
			mails_per_second = round(total_mails_to_sent/time_takes, 1)
			time.sleep(1)
			exit('\n'+wl+okk+f'all done in {bold(sec_to_min(time_takes))} minutes. speed: {bold(mails_per_second)} mail/sec.')
		if not len(smtp_pool_array):
			time.sleep(1)
			exit('\n'+wl+err+f'smtp list exhausted. all tasks terminated.\a')
	time.sleep(0.05)
