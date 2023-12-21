STATIC:
User's must be named 'liam', 'daury', or 'nicholas', with emails that are the first name followed by '@email.com' there must exist a public and private key in the same directory as main.py for the user trying to login. They have already been generated, and are included in this github.

The aim of this project is to familiarize us with cryptographic tools by implementing a secure file transfer protocol in Python, similar to the widely-used AirDrop feature in Apple devices.

### Usage
```python3 ./main.py```


### Testing
To test the program, we need to use two containers, to simulate the two clients that will communicate. Generally, I use ```192.168.5.51``` (my machine's docker container) as the "reciever" and ```192.168.5.4``` (Nick's) as the sender. You can access both on port ```2000``` when connected to the VPN with the following commands:

```ssh -p 2000 student@192.168.5.51```
```ssh -p 2000 student@192.168.5.4```

The password for both containers is ```1qazxsW@1```.

Get used to VIM, since I'd wager these containers don't have a GUI even fi we could access it.

Once you've gained access to the containers, create a directory with all the files in the github. On each, register a new user by running ```main.py```. To make things easy, I make the name "Liam" or "Bob", and then make the email their name + "@email.com" (liam@email.com). To shorten things, you can copy one of my directories ```~/liam/liam[number]``` so you don't have to copy and paste every single file.

Once you've registered one user on each machine, login. Use the main program to add a contact on each. After one user has added the other as a contact, it should appear in ```contacts.json```, and there should be a certificate named ```[user's_ip].crt``` in the directory. This having happened without errors 

At my last push, sending and recieving files themselves could not be tested via main, but by using the command line arguments specified by each of the functions.
