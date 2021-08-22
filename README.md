# Encryption

## How encryption works
> The basic idea of encryption is to convert data into a form in which the original meaning is masked, and only those who are properly authorized can decipher it. This is done by scrambling the information using mathematical functions based on a number called a key. An inverse process, using the same or a different key, is used to unscramble (or decrypt) the information. If the same key is used for both encryption and decryption, the process is said to be symmetric. If different keys are used the process is defined as asymmetric.

Two of the most widely used encryption algorithms today are AES and RSA. Both are highly effective and secure, but they are typically used in different ways.

## AES encryption
> AES (Advanced Encryption Standard) has become the encryption algorithm of choice for governments, financial institutions, and security-conscious enterprises around the world. The U.S. National Security Agency (NSC) uses it to protect the country’s “top secret” information.

> The AES algorithm successively applies a series of mathematical transformations to each 128-bit block of data. Because the computational requirements of this approach are low, AES can be used with consumer computing devices such as laptops and smartphones, as well as for quickly encrypting large amounts of data. 

> AES is a symmetric algorithm which uses the same 128, 192, or 256 bit key for both encryption and decryption (the security of an AES system increases exponentially with key length).

## RSA encryption
> RSA is named for the MIT scientists (Rivest, Shamir, and Adleman) who first described it in 1977. It is an asymmetric algorithm that uses a publicly known key for encryption, but requires a different key, known only to the intended recipient, for decryption. In this system, appropriately called public key cryptography (PKC), the public key is the product of multiplying two huge prime numbers together.

> RSA is more computationally intensive than AES, and much slower. It’s normally used to encrypt only small amounts of data.



# Resources
* [RSA Encryption](https://www.sohamkamani.com/golang/rsa-encryption/)
* [AES Encryption](https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial)
* [AES vs RSA](https://www.precisely.com/blog/data-security/aes-vs-rsa-encryption-differences)