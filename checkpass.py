#Run on cmd
import requests
import hashlib #<--converts into hashed no
import sys
def request_api_data(hashedpass):
	url = 'https://api.pwnedpasswords.com/range/'+hashedpass #<--API 
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error feaching: {res.status_code}, check the api try again')
	return res

'''def read_responce(hashes):
     print(hashes.text)#<-- we get all the hashed password that matched with our password(only 5 characters)'''

def get_password_leaks_count(hashes,hash_to_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())#<--is done to split hashes and count no
	for h,count in hashes:
		if(h==hash_to_check):#<--when rest mathches with hashes tail(leaving the 1st 5 char)
			return count
	return 0

def pwned_api_check(password):
	'''hashlib.sha1-->SHA1 hash generator,encode('utf-8')-->encoding in UTF-8upper()-->converting into uppercase
	    hexdigest()-->returns a string object of double length containing only hexadecimal digits
	print(hashlib.sha1(password.encode('utf-8')).hexdigest().upper())'''
	sha1password=hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first_5,rest=sha1password[:5],sha1password[5:]
	#print(f'{first_5}   {rest}')
	responce=request_api_data(first_5)
	#print(responce)
	return get_password_leaks_count(responce,rest)

def main(args):
	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'{password} is found {count} times probably you should change it')
		else:
			print(f'{password} not found successfull in creating it')
	return 'done'

if __name__ == '__main__':
   sys.exit(main(sys.argv[1:]))
