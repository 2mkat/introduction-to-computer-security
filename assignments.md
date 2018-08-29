# Assignments

1. Develop an attack tree describing ways to realize an arbitrary computer security threat.
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
5. Написать приложение, содержащее какую-либо очевидную уязвимость, необнаруживаемую сканером безопасности (false negative), а также приводящее к генерации сканером сообщения о наличии уязвимости, отсутствующей на самом деле (false positive). Пример: веб-приложение, содержащее [недостатки предварительной обработки данных в SQL-запросах](http://cwe.mitre.org/data/definitions/89.html), приводящие к возникновению уязвимости к атаке [SQL-injection](https://capec.mitre.org/data/definitions/66.html) необнаруживаемой сканером [Sqlmap](http://sqlmap.org/) и не содержащее [недостатки предварительной обработки данных, выводящихся пользователю](http://cwe.mitre.org/data/definitions/79.html), но ошибочно считаемое уязвимым к атаке [XSS](https://capec.mitre.org/data/definitions/18.html) сканером [ZAP](https://code.google.com/p/zaproxy/).
[Примеры](https://github.com/client9/libinjection/blob/e1cd4e447c1352f1b3cd2169299b6b67556eb922/data/false_positives.txt) false positive в модуле WAF libinjection.

7. Написать [регулярное выражение](https://en.wikipedia.org/wiki/Regular_expression), обнаруживающее какую-либо атаку типа "инъекция" на веб-приложение, связанную с [недостаточной обработкой данных](https://cwe.mitre.org/data/definitions/20.html). Качество регулярного выражения определяется покрытием множеством векторов атаки из выбранного класса и множеством обрабатываемых запросов, не являющимися векторами атака (иначе говоря соотношением false negative и false positive).

8. Develop a timing covert channel application on an arbitrary programming language exploiting one of the following mechanism:
    * Socket
    * Hard link
    * Soft link
    * File system attributes
    * proc file system
    * Network protocol field
