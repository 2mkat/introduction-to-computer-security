# Assignments

## Part 1: Basics
1. Develop an attack tree describing ways to realize a chosen computer security threat.
2. Develop a DFD describing a trivial web application. "Microsoft Threat Modeling Tool" should be used.
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
