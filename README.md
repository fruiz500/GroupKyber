# GroupKyber
Encrypts/decrypts files for a group of users. A typical usage scenario would be adding zero-knowledge encryption to a file sharing service that does not have this feature natively. This app is very similar to GroupEncrypt, but it has a different crypto engine.

This webapp is based on the ML-KEM and ML-DSA standard algorithms for quantum-proof encryption. It uses the following open-source code from GitHub, included in the /lib-opensrc folder:

Noble Post-Quantum cryptography library by Paul Miller. (https://github.com/paulmillr/noble-post-quantum)

Noble Ciphers by Paul Miller. (https://github.com/paulmillr/noble-ciphers)

Noble Hashes by Paul Miller. (https://github.com/paulmillr/noble-hashes)

Four dummy users are built into the demo: Alice, Bob, Carol, and legacy user Adam. Thier respective Passwords are "Hi, I'm Alice" and so forth, each time replacing "Alice" with the corresponding name. No Administrator password is provided.

User access to the encrypted output is controlled by the file GroupKeys.js, which must be edited for each particular implementation, although the page admin.html is designed so it can be done without editing the server code. This file, which should reside in the same folder as the index.html that loads the app, contains a single object GroupKeys with all the settings. First, the name of the group. This is used to salt the user passwords and make rainbow table attacks a little harder. Then the unique header that encrypted files begin with, and which the app uses to determine whether or not a file loaded onto it has been previously encrypted by the app. This entry is an array of numbers 0 to 255 representing bytes. The only important thing is that none of the files to be encrypted should begin with this sequence of bytes. The more bytes, the smaller the likelihood that this will happen. Finally, the file also contains the public keys of all the users in the group, up to a maximum of 255 active users, plus optional lists of users. Example:
First a quick guide on making the GroupKeys.js file:

This file, which should reside in the same folder as the index.html that loads the app, contains a single object GroupKeys with all the settings. First, the name of the group. This is used to salt the user passwords and make rainbow table attacks a little harder. Then the unique header that encrypted files begin with, and which the app uses to determine whether or not a file loaded onto it has been previously encrypted by the app. This entry is an array of numbers 0 to 255 representing bytes. The only important thing is that none of the files to be encrypted should begin with this sequence of bytes. The more bytes, the smaller the likelihood that this will happen. Finally, the file also contains the public keys of all the users in the group, up to a maximum of 255 active users, plus optional lists of users. Example:

var GroupKeys = {

"GroupName": "Sample Group",

"HeadTag": "[81,81,81,81,81,81,81]",

"Alice":
"9kayZjwPWpUgCkK/o/WeRwgHdKMqnQNLpMHONnNZ4fGG6Fso1tlh70BxQdDJvdCC/Dq4JZUOwmzC1ARUnichpxyBz2PNFdxGtsV/QLhIQqRTG6Yy0EMwDvVnStbI/YOyMaksPYJYEBN7n4cBszxrxpxDOMkkSEUB9bai3ZCMQ6rDIagX9iJnmAmosFsFFKGPTDZmRvKe0TJT6zuf2ADBNlkm53OKVPmcWdW//DGVACazcsnOqsNx1exIU4ZXevRdN5rKJeW4iSMV8ZaWnetWRcRgflnGWeXGhcJ98H...",             //(abridged) 4182 base64 characters

"Bob":
"ApQAt4kEODWvqqqsnPjM9BaXAEqDJ1CNdOSYxbnDCRsy83Wd+fxJnLFT3gQQcrO2IOaq6QB5yzp28ieNFpdpmeoWv6tXR7yki2a36PiCZqRODXYplXeRDLqBJoVlXftT+ptfLBwaHTwTBNk8VgCQH/JnmgrDZCsVxgQTnIol2kZln1jLKrUyrYlHCGjBMpir/ZxpmWlAUqm9vuF7TXXB0wLIjyMR3LQ...",

"Carol":
"RLEGRnknL8dkH/OVZqILGah7pMMOk/hz0QlYp5p8SpStJuRhxcECjfyQr9AeUTAJJeXKpvrKzcSRB5I1iaZYM7AsVvQLlmhkyyBFxDYhRLulBvgra3EF0icl1DCekjF9IfGiiLsAdtV71+oM/ZvHlRg1sUNJswZlN4pbUtJ9RLiRmEA7b4tpXnNcVqc1PsdP11J+g5y4t0fLPwMfU7mQ+fqwp9Khbcxlf7g9tFmv/ADHumksJFYW1dOxYXqjBJyMEsFbRBQojlOFcUlhonMBhNwmpQc...",

"$Adam":
"XFyVFnINDRPFoRqo/8CjBZMEgupNFPANY3oIEwEADjG2jfGYtDyqBCvGkZZ8WhwAcXhV3lx4HcShpNtZCbR6cBGwojyp2di9g5iy2UcndHNGFwK95BdvjBi9hyWGV5HOlJC0ApYk42caU+CTohQ6h1yXqCUl+tRArtCb1dkXYOx4TKXHaWR55rSfiYAlXqtn8BI1H7JB+EAR2TZWCy...",

"=Girls=":
"Alice, Carol, Diana",

"=Lovers=":
"Alice, Bob",

"=AllGroups=":
"==Admin==, =Girls=, =Lovers=",

"==Admin==":
"Alice"

}
Notes: Special group "==Admin==" lists the names of the users whose public keys will be used if no particular recipients are selected. "$Adam" is a former user, kept so that files encrypted by this user can still be decrypted; the name begins with $. "=Girls=" and "=Lovers=" are lists containing some active users. "=AllGroups=" is a list of lists; there is no practical limit to how lists can be nested. User "Diana" is listed in group "=Girls=" but won't be included in any encryption or decryption since the individual entry does not exist.

During the app rollout period, each one of the users must load the app and enter a unique Password in the box, which won't be accepted if the matching public key is not in the database file. This displays his/her public key below it, which then he/she copies and sends to a system administrator by the most convenient means. Public keys are not secret, but if group members are going to run the app from file rather than from a server, you get a little extra security by sending those keys to the administrator through secure channels.

The administrator then composes the permanent GroupKeys.js file with any text editor and distributes it to the users or uploads it to the server, or edits it via the special Administrator page loaded by clicking near the top of the user page, giving each user an identifying name, followed by a colon, and then his/her public key within quotes. Some entries can contain a list of user names instead. There must be a comma between entries, but spaces and carriage returns don't affect the result. Make sure to edit the entry named "GroupName" to something other than the default, since this string is used as a salt for generating the public keys.

When encryption of a file takes place, the input file is encrypted so that each one of the selected users (default: users listed in the ==Admin== group) can decrypt the output file, plus the user encrypting, and nobody else. This involves first doing symmetric encryption of the file with a random 32-byte "message key", plus a random 24-byte nonce. A signature made with the ML-DSA algorithm is made for the resulting ciphertext, and prepended to it. Then the message key is encrypted with a secret derived from each recipient's public key using the ML-KEM algorithm, and the result plus the corresponding nonce, plus the KEM-encrypted secret is again prepended to the signature and ciphertext. Decryption by a particular user involves finding that user's encryted message key in the encrypted file, decrypting the KEM secret with his/her private key, then decrypting the message key, and finally using the message key to decrypt the main file content. The signature of the ciphertext is validated with the sender's public DSA key prior to decrypting the KEM secret for the recipient.

In the event that a message has been encrypted by a user that has left the group, decryption is still possible if the former user's public key is still included in GroupKeys.js, with the name prefaced by a '$' character so this entry can be differentiated. In this case, the public key is never used for encryption, and the user's name cannot be listed as a recipient, but the public key is available for validating sender signatures.

In addition to the File by File mode described above, there is a Folder mode where the encryption of a particular file is done with a random symmetric key, and this key is also the message Key of a special file, encrypted as described above, that contains no plaintext. The Folder Key should be present in memory before encryption or decryption can proceed in this mode. Upon decryption, the message key is stored in memory to serve as Folder Key for files loaded after.

GroupKyber is based on the post-quantum public key cryptography algorithms of the Noble suite, by Paul Miller and other libraries by the same author. The user-supplied Password is analyzed for strength, and the parameters of the SCRYPT key-generating algorithm are varied so that weaker Passwords are subjected to more rounds of key stretching. We call this the WiseHash algorithm, which makes the keyspace quite resistant to dictionary attack, since attackers are penalized for including weak Passwords in their search, or otherwise risk missing them. The encryption algorithm is similar to the Signed mode in KyberLock, also by F. Ruiz, except that it uses no extra data such as user email, there is no padding that might contain a secret message, and the first 8 bytes of the sender's public key are added to speed up decryption. Files encrypted by this app cannot be decrypted in KyberLock, and vice-versa.

Processing is done by the browser's built-in JavaScript engine, which makes the app very fast and cross-browser compatible. It can run on mobile devices as well. Files up to 1 GB in size can be handled, subject to memory availability. In this implementation, the data is input and output as local files, but it is easy to modify the code so the data is exchanged with a server instead. The format for the file data is uint8 arrays, each element containing one binary byte. The name of the input file data is fileInBin, that of the output data is fileOutBin.
