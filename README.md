# Введение в компьютерную безопасность

## Описание курса

Программа и материалы курса «Введение в компьютерную безопасность»
образовательной программы по направлению подготовки (специальности)
10.05.01 «Компьютерная безопасность», преподаваемого в [Национальном исследовательском Томском государственном университете](http://www.tsu.ru) на [кафедре защиты информации и киптографии](http://isc.tsu.ru)

## Вопросы

1. Введение в предмет компьютерной безопасности
    * подходы к определению безопасности
    * базовое определение защищенной информационной системы (ИС)
    * направления в компьютерной безопасности
    * соотношение информационной, кибер и компьютерной безопасности
    * роль криптографии в компьютерной безопасности
    * мифы компьютерной безопасности
    * [классические принципы защищенности Зальцера и Шредера](http://www.cs.virginia.edu/~evans/cs551/saltzer/)
1. Основные термины компьютерной безопасности
    * политика безопасности
    * угроза
    * недостаток
    * уязвимость
    * атака
    * безопасность
    * защищенность
    * модель угроз
    * механизм защиты
1. Уязвимости
    * неформальное определение уязвимости
    * формальное определение уязвимости в модели [Engle-Whalen-Bishop] (http://nob.cs.ucdavis.edu/bishop/notes/2008-cse-14/2008-cse-14.pdf)
    * оценка уязвимостей [CVSSv3.0](https://habrahabr.ru/company/pt/blog/266485/)
    * каталоги [CWE] (http://cwe.mitre.org/), [CVE] (http://cve.mitre.org/) и [CAPEC] (http://capec.mitre.org/) 
1. Политика безопасности и механизмы защиты
    * Превентивные (preventive), смягчающие (mitigative), детективные (detective) и коррективные (corrective) механизмы защиты
    * Многоуровневая защита
    * Безопасность через сокрытие (security by obscurity)
1. Моделирование
    * Модели угроз 
        * модель [CIA] (http://en.wikipedia.org/wiki/Information_security)
        * модель [STRIDE] (http://msdn.microsoft.com/en-us/library/ee823899(v=cs.20).aspx)
        * модель МакКамбера
        * модель Паркера
   * Модели оценки уязвимостей
        * модель [DREAD] (http://msdn.microsoft.com/en-us/library/ff648644.aspx)
        * модель [CVSS] (https://www.first.org/cvss/calculator/3.0)
        * [примеры оценки уязвимостей](https://www.first.org/cvss/examples)
   * Модели атак
         * [графы атак](http://www.securitylab.ru/contest/299868.php)
         * [деревья атак Шнайера](https://en.wikipedia.org/wiki/Attack_tree)
   * Модели угроз приложений
         * [DFD](https://www.owasp.org/index.php/Application_Threat_Modeling)
1. Управление доступом и информационными потоками
   * Идентификация, аутентификация и авторизация
   * Основные политики управления доступом и информационными потоками
       * дискреционное управление доступом (DAC)
       * мандатное управление доступом ([LBAC] (http://en.wikipedia.org/wiki/Lattice-based_access_control), [MLS] (http://en.wikipedia.org/wiki/Multilevel_security), [TE] (http://en.wikipedia.org/wiki/Type_enforcement))
       * ролевое управление доступом (RBAC)
       * атрибутное управление доступом (ABAC)
   * Обзор классических моделей безопасности
       * [модель Харрисона-Руззо-Ульмана](http://dl.acm.org/citation.cfm?doid=360303.360333)
       * [модель Take-Grant](http://www.cs.nmt.edu/~doshin/t/s06/cs589/pub/2.JLS-TG.pdf)
       * модель [Белла-ЛаПадулы] (http://en.wikipedia.org/wiki/Bell%E2%80%93LaPadula_model)
   * Скрытые каналы
       * определение, назначание и виды скрытых каналов
       * общая схема функционирования скрытых каналов
       * примеры скрытых каналов по памяти и по времени
1. Безопасность TCP/IP
   * Основные принципы функционирования компьютерных сетей
   * [Одна секунда из жизни пакета](http://habrahabr.ru/post/191954/)
   * Классические сетевые атаки
       * [Атака Митника](http://wiki.cas.mcmaster.ca/index.php/The_Mitnick_attack)
       * [DoS-](http://en.wikipedia.org/wiki/Denial-of-service_attack), [DDoS-](http://www.cisco.com/web/about/security/intelligence/guide_ddos_defense.html), [DRDoS-](http://blog.cloudflare.com/deep-inside-a-dns-amplification-ddos-attack/)атаки
       * ARP-spoofing
   * Классические сетевые механизмы защиты 
       * Межсетевые экраны
       * Системы обнаружения вторжений
       * Виртуальные частные сети (VPN)
1. Элементы криптографических протоколов
   * Виды протоколов 
   * Протоколы SSL/TLS
   * PKI
1. Анализ защищенности
   * тестирование безопасности
   * [тестирование на проникновение](http://www.youtube.com/watch?v=X0ilODBepU8&feature=youtu.be)
   * технологии [SAST](http://sgordey.blogspot.ru/2013/08/blog-post_13.html), [DAST] (http://sgordey.blogspot.ru/2013/08/0day-11.html) и [IAST](http://www.youtube.com/watch?v=sUNsPBb6NPA)
   
   
## Задания
1. Построить дерево атак для похищения номера кредитной через веб-приложение.
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
5. Написать приложение, содержащее какую-либо очевидную уязвимость, необнаруживаемую сканером безопасности (false negative), а также приводящее к генерации сканером сообщения о наличии уязвимости, отсутствующей на самом деле (false positive). Пример: веб-приложение содержащее [недостатки предварительной обработки данных в SQL-запросах](http://cwe.mitre.org/data/definitions/89.html), приводящие к возникновению уязвимости к атаке [SQL-injection] (https://capec.mitre.org/data/definitions/66.html), необнаруживаемой сканером [Sqlmap](http://sqlmap.org/) и не содержащее [недостатки предварительной обработки данных, выводящихся пользователю](http://cwe.mitre.org/data/definitions/79.html), но ошибочно считаемое уязвимым к атаке [XSS] (https://capec.mitre.org/data/definitions/18.html) сканером [ZAP](https://code.google.com/p/zaproxy/) .
6. Устранить, выбранный класс уязвимостей в приложении [Gruyere](https://google-gruyere.appspot.com/) или [DVWA](http://www.dvwa.co.uk/) путем изменения его исходного кода.
7. Написать [регулярное выражение](https://en.wikipedia.org/wiki/Regular_expression), обнаруживающее какую-либо атаку типа "инъекция" на веб-приложение, связанную с [недостаточной обработкой данных](https://cwe.mitre.org/data/definitions/20.html). Качество регулярного выражения определяется покрытием атак из выбранного класса.  
8. На произвольном языке программирования написать код для клиента и сервера, реализующих [скрытый канал](https://en.wikipedia.org/wiki/Covert_channel) по времени с использованием любого механизма операционной системы, например:
    * создание сокета
    * доступ к файлу
    * жесткие ссылки
    * символические ссылки
    * файловая система /proc
    * загрузка процессора
    * наличие установленного сетевого соединения
9. В Банке, где работает Алиса используется следующая политика управления доступом к данным по зарплате сотрудников. Рядовые бухгалтера (такие, как Алиса) могут видеть только данные по зарплате сотрудников, которые по должности не выше начальника отдела, старшие бухгалтера могут видеть данные по зарплате сотрудников до начальников управления включительно. Главный бухгалтер может получать доступ к данным по зарплате всех сотрудников, включая управляющего и его заместителей. Определить наиболее подходящий вид управления доступом для данного процесса и построить формальную модель политики управления доступом.     
10. Какие из нижеперечисленных высказываний являются некорректными и почему:
   ```
   A. Уязвимость XSS основана на недостаточной предварительной обработке входных данных. 
   
   Б. Большинство угроз используют уязвимости, возникающие вследствие ошибок разработчиков.
   
   В. Угроза переполнения буфера актуальна только для бинарных приложений.
   
   Г. Язык программирования HTML неуязвим к угрозе XSS.
   
   Д. Одним из первых шагов в разработке защищенного программного обеспечения - моделирование уязвимостей.
   
   Е. Уязвимость - это возможность выполнения атаки.
   
   Ж. Подходы к обеспечению безопасности, основанные на "Security by obscurity", не должны быть использованы в защищенной компьютерной системе. 
   
   З. Роль - это именованный набор прав доступа пользователя.
   
   И. Уязвимость к атаке XSS позволяет выполнить произвольный HTML-код в контексте веб-приложения.  
   
   К. Угроза - это цель злоумышленника.
   
   ```
11\*. Какие уязвимости содержатся в следующем фрагменте кода? Каким образом можно воспользоваться данными уязвимостями для проведения атаки на систему? Описать последовательность выполняемых действий.
   ```
<?php
/*
CREATE TABLE `message` (
`remote_addr` TEXT NOT NULL ,
`user_agent` TEXT NOT NULL ,
`name` TEXT NOT NULL ,
`text` TEXT NOT NULL
) ENGINE = MYISAM ;
INSERT INTO `message` (`remote_addr`, `user_agent`, `name`, `text`) VALUES('127.0.0.0', 'Fire Walk With Me', 'test name', 'test text');
INSERT INTO `message` (`remote_addr`, `user_agent`, `name`, `text`) VALUES('127.0.0.0', 'Abandon all hope, ye who enter here', 'test name2', 'test text2');
*/

$link = mysql_connect("localhost", "root", "");
mysql_select_db("positive", $link);
$ip = $_SERVER["REMOTE_ADDR"];
if(isset($_SERVER["HTTP_X_REAL_IP"])) {
   $ip = $_SERVER["HTTP_X_REAL_IP"];
}
$ip = addslashes($ip);
$user_agent = addslashes($_SERVER["HTTP_USER_AGENT"]);
$ip = substr($ip, 0, 15); // max length 15
if(isset($_POST["name"]) && isset($_POST["text"])) {
   $text = addslashes($_POST["text"]);
   $name = addslashes($_POST["name"]);
   $query = mysql_query("INSERT INTO `message` (`remote_addr`, `user_agent`, `name`, `text`) VALUES('{$ip}', '{$user_agent}', '{$name}', '{$text}');", $link);
}
$query = mysql_query("SELECT * FROM `message`;", $link);
echo("<table>");
while($row = mysql_fetch_assoc($query)) {
   echo("<tr><td>{$row["name"]}</td><td>{$row["text"]}</td></tr>");
}
echo("</table>");
?>
   ```
12\*. Для упрощенной грамматики фильтров LDAP, основанной на [RFC 2254](https://tools.ietf.org/html/rfc2254), реализовать парсер на [ANTLR](https://github.com/tsu-iscd/getting-started-with-antlr4), а также построить грамматику и парсер для обнаружения LDAP-инъекций.

Грамматика:

```
        filter     = "(" filtercomp ")"
        filtercomp = and / or / not / item
        and        = "&" filterlist
        or         = "|" filterlist
        not        = "!" filter
        filterlist = 1*filter
        item       = simple / present
        simple     = attr filtertype value
        filtertype = equal / approx / greater / less
        equal      = "="
        approx     = "~="
        greater    = ">="
        less       = "<="
        
        present    = attr "=*"
        final      = value
        attr       = 1*letter
        value      = 1*(letter | digit)
        
        digit = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" ;
        
        letter = "a" | "b" | "c" | "d" | "e" | "f" | "g" 
               | "h" | "i" | "j" | "k" | "l" | "m" | "n" 
               | "o" | "p" | "q" | "r" | "s" | "t" | "u"
               | "v" | "w" | "x" | "y" | "z" ;
```

## Материалы

### Обязательные
* [В. Кочетков. Философия Application Security](https://www.youtube.com/watch?v=mb7tcT-9VXk)
* [В. Кочетков. Прикладная теория безопасности приложений](https://my.webinar.ru/record/622509/?i=574d3d07f32978b0ae039c8604b45409)
* [Matt Bishop. Introduction to Computer Security.](http://nob.cs.ucdavis.edu/book/book-intro/) Chapter 1
* [L.Sassaman, M. Patterson, S. Bratus, M. Locasto, A. Shubina. Security Applications of Formal Language Theory](http://www.langsec.org/papers/langsec-tr.pdf)

### Книги
* [Matt Bishop. Introduction to Computer Security.](http://nob.cs.ucdavis.edu/book/book-intro/)

### Видео
* [В. Кочетков. Как разработать защищенное веб-приложение и не сойти при этом с ума? ](http://my.webinar.ru/record/140584/)
* [А. Петухов. Обзор ограничений современных технологий в области ИБ] (https://events.yandex.ru/lib/talks/2692/)
* [Код Верченко](https://www.youtube.com/watch?v=pFl5KxSNHBo)

### Аудио
* [Подкаст Noise Security Bit. Об образовании в области ИБ](http://noisebit.podster.fm/6)
* [Подкаст Noise Security Bit. О практической безопасности](http://noisebit.podster.fm/3)

### Блоги
* [Information Security Interview Questions](http://danielmiessler.com/study/infosec_interview_questions/)
* [Security Related Interview Questions for all Engineers](https://www.netmeister.org/blog/security-questions.html)
* [Application security related questions for developers](https://teamquiz.aspectsecurity.com)
* [В. Кочетков. Информационная угрозология, уязвимоведение и рисководство](http://habrahabr.ru/post/129386/)

## Архив
* [Курс 2015 года](2015.md)
