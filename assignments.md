# Assignments

1. Построить дерево атак для реализации некоторой угрозы в компьютерной системе.
2. Построить модель угроз в виде DFD для простейшего веб-приложения, используя Microsoft Threat Modeling Tool.
3. Самостоятельно вычислить оценку для 3-х наиболее известных (популярных) уязвимостей, обнаруженных за последний год, используя методики моделей [DREAD](https://msdn.microsoft.com/en-us/library/aa302419.aspx) и [CVSSv3](https://www.first.org/cvss/calculator/3.0).
4. Проанализировать следующие фрагменты кода веб-приложений и найти в них недостатки и уязвимости, если таковые имеются:
   
   Фрагмент 1.
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
   Фрагмент 2.
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

6. Устранить, выбранный класс уязвимостей (например, класс уязвимостей к атаке LDAP Injection) в приложении [Gruyere](https://google-gruyere.appspot.com/), [DVWA](http://www.dvwa.co.uk/) или в любом другом приложении подобного класса путем изменения его исходного кода.

7. Написать [регулярное выражение](https://en.wikipedia.org/wiki/Regular_expression), обнаруживающее какую-либо атаку типа "инъекция" на веб-приложение, связанную с [недостаточной обработкой данных](https://cwe.mitre.org/data/definitions/20.html). Качество регулярного выражения определяется покрытием множеством векторов атаки из выбранного класса и множеством обрабатываемых запросов, не являющимися векторами атака (иначе говоря соотношением false negative и false positive).

8. На произвольном языке программирования написать код для клиента и сервера, реализующий [скрытый канал](https://en.wikipedia.org/wiki/Covert_channel) по времени с использованием любого механизма операционной системы, например:
    * создание сокета
    * доступ к файлу
    * жесткие ссылки
    * символические ссылки
    * файловая система /proc
    * загрузка процессора
    * наличие установленного сетевого соединения
