# Assignments

## Part 1: Basics
1. Develop an attack tree describing ways to realize a chosen computer security threat. You may use [draw.io](https://michenriksen.com/blog/drawio-for-threat-modeling/).
2. Develop a DFD describing a trivial web application. You may use [draw.io](https://michenriksen.com/blog/drawio-for-threat-modeling/) .
3. Calculate scores for 3 popular and known vulnerabilities within [DREAD](https://msdn.microsoft.com/en-us/library/aa302419.aspx) and [CVSSv3](https://www.first.org/cvss/calculator/3.0) models.
4. Analyze the code snippets below, find and derive threats, weaknesses, vulnerabilities and attacks.
   
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
    * Network protocol fields
6. Solve all challenges in [Cryptopals Set 1](https://cryptopals.com/sets/1).

7. Implement a string comparisons algorithm on your own and then implement secure one comparing strings in constant time.
To understand why it is necessary and where it is used see this [link](https://cryptocoding.net/index.php/Coding_rules#Compare_secret_strings_in_constant_time).

8. Prepare an executive summary for a scientific paper related to computer security in a broad sense.
   Some questions you have to answer are as follows:
   - What problem is this paper tackling?
   - How security is defined? What an adversary is assumed?  
   - What is the potential impact of the results?
   - What advances over the previous state of knowledge are made?
   - What are the main results; what do the security bounds “say”?
   - Do the hardness assumptions that are used to support proofs seem reasonable?
   - What open problems are surfaced by the authors, for future work?
