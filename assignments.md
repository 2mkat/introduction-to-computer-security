# Assignments

## Part 1: Basics
1. Develop an attack tree describing ways to realize a chosen computer security threat. You may use [draw.io](https://michenriksen.com/blog/drawio-for-threat-modeling/).
2. Develop a DFD describing a trivial web application. You may use [draw.io](https://michenriksen.com/blog/drawio-for-threat-modeling/) .
3. Calculate scores for 3 popular and known vulnerabilities within [DREAD](https://msdn.microsoft.com/en-us/library/aa302419.aspx) and [CVSSv3](https://www.first.org/cvss/calculator/3.0) models.
4. Analyze the code snippets below and find weaknesses and vulnerabilities.
   
   Code snippet 1.
   ```
   <?php
    if (isset($_GET['redirect'])) {
        header('Location: '.$_GET['redirect']);
    }
    header('Set-Cookie: _afUserId='. $_GET['userId']);
    header('Set-Cookie: _afGroupId='. $_GET['groupId']);
    ?>
    <html>
    <head>
        <meta http-equiv="refresh" content="5;url=<?=$_GET['url']?>"></meta>
    </head>
    <body>
          <?php
              $roleId = explode(":", base64_decode($_COOKIE['roleId']))[0];
              if ($roleId == 'admin') {
                  include 'admin_interface.php';
              }
              elseif ($roleId == 'user') {
                  include 'user_interface.php'
              }
              else {
                  echo '<h2>Unknown role '.$roleId.'\n</h2>';
              }
          ?>

    </body>
    </html>
   ```
   Code snippet 2.
   ```
   private static bool IsValidSignature(string data, string signature) {
     var bytes = Encoding.ASCII.GetBytes("eCTR4rhYQVNwn78j" + data);
     var hash = MD5.Create().ComputeHash(bytes);
     return BitConverter.ToString(hash) == signature;
   }
   ...
   if (IsValidSignature(Request["data"], Request["signature"])) {
     var decryptor = Aes.Create() { 
        BlockSize = 128;
        Key = Encoding.ASCII.GetBytes("YtGDn6mvAHbp5X7C");
        IV = Encoding.ASCII.GetBytes("mHMUYSjiVxo4wp9R");
      }.CreateDecryptor();
   }
   ```
5. Develop a timing covert channel application on an arbitrary programming language exploiting one of the following mechanism:
    * Socket
    * Hard link
    * Soft link
    * File system attributes
    * proc file system
    * Network protocol field

## Part 2: Introduction to Cryptography
1. AES in ECB mode. The Base64-encoded content in [this](https://github.com/tsu-iscd/introduction-to-computer-security/blob/master/data/1.txt) file has been encrypted via AES-128 in ECB mode under the key `YELLOW SUBMARINE`.
Decrypt it with code. You know the key, after all. Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
Source: [the cryptopals crypto challenges](https://cryptopals.com/sets/1/challenges/7).

2. Implement a string comparisons algorithm on your own and then implement secure one comparing strings in constant time.
To understand why it is necessary and where it is used see this [link](https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time).

3. Implement fixed XOR on Rust. Write a function that takes two equal-length buffers and produces their XOR combination.
If your function works properly, then when you feed it the string `1c0111001f010100061a024b53535009181c` after hex decoding, and when XOR'd against `686974207468652062756c6c277320657965` should produce `746865206b696420646f6e277420706c6179`.
Source: [the cryptopals crypto challenges](https://cryptopals.com/sets/1/challenges/2).

4. Alice and Bob have a shared long-term symmetric key `k`. Alice wants to send a message `m` to Bob using one-time established key `sk`.  Find vulnerabilities in the following key transport protocol: 

   ```
   Alice -> Bob: r
   Bob -> Alice: E(k, sk, r)
   ...
   Alice -> Bob: E(sk, m)
   ```

## Part 3: Network Security
1. Find webcams on the Internet using Shodan or Censys search engines.
2. Develop an [Nmap NSE](https://nmap.org/nsedoc/) script able to discover F5 BIG-IP load balancers via HTTP `Server: BIG-IP` header.

## Part 4: Web Application Security
1. Attack and defence. [Damn Small Vulnerable Web (DSVW)](https://github.com/stamparm/DSVW) is supposed to be used, but you can use any other vulnerable web application you want ([WackoPicko](https://github.com/adamdoupe/WackoPicko) on PHP, [Gruyere](https://google-gruyere.appspot.com/) on Python, [vulnerable-app](https://github.com/clarkio/vulnerable-app) on Node.js, etc.). Choose an attack class you are interested in. It can be `SQL injection`, `XSS`, `XXE`, or any other supported by chosen vulnerable application. First, provide a proof of concept that the application is vulnerable to this attack. Second, fix the vulnerability in the source code and ensure, that the bug has been fixed.

2. Bug Hunting. Find bugs as much as you can in one of the following special web applications:
* [Acuart](http://testphp.vulnweb.com/)
* [Juice shop](https://juice-shop.herokuapp.com/#/search)
* [SecurityTweets](http://testhtml5.vulnweb.com)
