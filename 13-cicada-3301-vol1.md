# 13 - Cicada-3301 Vol1

Room Link --> [https://tryhackme.com/room/cicada3301vol1](https://tryhackme.com/room/cicada3301vol1)

### Link inside the Audio

We use `sonic-visualizer` - to analyze audio files.

Import the ".wav" file, we can now start adding filters on it.  On the "Layer Tab" click "Add Spectogram" , Then, zoom in into the picture. Lastly, change the color scheme into **White on Black** and set the **Scale** as **dB^2:**

<figure><img src=".gitbook/assets/image (125).png" alt=""><figcaption><p>1</p></figcaption></figure>

Scan QR code with Phone and get the link.

### Decode the Passphrase

Visit the Link --> decode using base64.

<figure><img src=".gitbook/assets/image (126).png" alt=""><figcaption></figcaption></figure>

When we look at the hint on **Question 4,** It says **French Diplomat Cipher.** When we google it, we came accross some online **"Vigenere Cipher"** encrypter, so we just used one of them to encrypt the funny "H....".

### Gather Metadata

The hint suggested we use **"steghide"**.

`steghide info welcome.jpg` - we discover a hidded text on the image.

<figure><img src=".gitbook/assets/image (127).png" alt=""><figcaption></figcaption></figure>

`steghide extract -sf welcome.jpg` - to extract the hidden text.

### Find Hidden Files

The tool used to extract data in the original Cicada challenges is --> [**outguess**](https://github.com/crorvick/outguess/blob/master/README)

Follow the link on the previous question, download the image, use **outguess** on it.

`outguess -r undefined.jpg undefined` - usage: outguess \<option> \<input\_file> \<output\_file>

We check the output file:

<figure><img src=".gitbook/assets/image (128).png" alt=""><figcaption></figcaption></figure>

Obviously the 1st pair looks like "https://"

<figure><img src="https://marcorei7.files.wordpress.com/2020/09/image-64.png?w=62" alt="Book cipher" height="146" width="62"><figcaption></figcaption></figure>

For the first letter we have to go to the first line of the book and move 6 characters to the right…

<figure><img src="https://marcorei7.files.wordpress.com/2020/09/image-65.png?w=651" alt="Excerpt from the book to use" height="328" width="651"><figcaption></figcaption></figure>

… and should be able to solve the first part.

Follow the link to get the song tittle: but the link is dead, so i used a youtube walkthrough to get the answer :)

