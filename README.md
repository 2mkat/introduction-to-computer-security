# Введение в компьютерную безопасность

## Описание курса

Программа и материалы курса «Введение в компьютерную безопасность»
образовательной программы по направлению подготовки (специальности)
10.05.01 «Компьютерная безопасность», преподаваемого в [Национальном исследовательском Томском государственном университете](http://www.tsu.ru) на [кафедре защиты информации и киптографии](http://isc.tsu.ru)

## Вопросы

1. Введение в предмет компьютерной безопасности
    * определение безопасности
    * мифы компьютерной безопасности
    * направления компьютерной безопасности
    * соотношение информационной и компьютерной безопасности
    * соотношение компьютерной безопасности и криптографии
1. Основные термины компьютерной безопасности
    * угроза
    * недостаток
    * уязвимость
    * атака
    * безопасность
    * защищенность
1. Моделирование угроз
    * Основные модели угроз 
        * модель CIA
        * модель STRIDE
        * модель МакКамбера
        * модель Паркера
   * Риск-ориентированный подход к компьютерной безопасности
        * модель DREAD
        * модель CVSS
    * Построение модели угроз
1. Уязвимости
    * формальное определение уязвимости
    * классификация уязвимостей
    * каталоги CWE, CVE и CAPEC 
1. Политика безопасности и механизмы защиты
    * Превентивные, детективные и коррективные механизмы
    * Многоуровневая защита
    * Безопасность через сокрытие 
    * Безопасность систем с открытым исходным кодом
1. Управление доступом
    * Идентификация, аутентификация и авторизация
    * Аутентификация
        * парольная защита
        * двухфакторная аутентификация
        * технологии AAA и SSO
    * Управление доступом и информационными потоками
        * дискреционное управление доступом
        * мандатное управление доступом
        * ролевое управление доступом
        * атрибутное управление доступом 
        * элементы формального моделирования
        * модель Харрисона-Руззо-Ульмана
        * модель Белла-ЛаПадулы
    * Скрытые каналы
1. Защищенность сетей
    * Элементы функционирования компьютерных сетей
    * Классические сетевые атаки (TCP hijacking)
    * DoS- и DDoS-атаки
1. Элементы криптографических протоколов
    * Виды протоколов 
    * Протоколы SSL/TLS
    * PKI
1. Анализ защищенности
    * тестирование
    * технологии SAST, DAST и IAST
    * тестирование на проникновение
1. Практические аспекты
    * ответственное разглашение и программы Bug Bounty
    * соревнования по защите информации CTF
1. Дружелюбная безопасность (Usable security)
   * Модели взаимодействия
   * [NEAT](http://blogs.msdn.com/b/sdl/archive/2011/05/04/adding-usable-security-to-the-sdl.aspx)
   
## Задания
1. Построить модель угроз для простейшего веб-приложения, используя Microsoft Threat Modeling Tool
1. Для выбранного класса атак предложить методы обеспечения защищенности на всех логических уровнях (рисков, угроз, недостатков, уязвимостей, атак) модели безопасности
1. Написать приложение, содержащее какую-либо уязвимость, необнаруживаемую сканером безопасности (false negative), а также приводящее к генерации сканером сообщения о наличии уязвимости, отсутствующей на самом деле (false positive). Например, веб-приложение содержащее [недостатки предварительной обработки данных в SQL-запросах](http://cwe.mitre.org/data/definitions/89.html), приводящих к возниконовению уязвимости к атаке [SQL-injection] (https://capec.mitre.org/data/definitions/66.html), необнаруживаемой сканером [Sqlmap](http://sqlmap.org/) и не содержащее [недостатки предварительной обработки данных, выводящихся пользователю](http://cwe.mitre.org/data/definitions/79.html), но ошибочно считаемое уязвимым к атаке [XSS] (https://capec.mitre.org/data/definitions/18.html) сканером [ZAP](https://code.google.com/p/zaproxy/)
1. Устранить, выбранный класс уязвимостей в коде приложения [Gruyere](https://google-gruyere.appspot.com/). Устранить этот же класс уязвимостей, но путем написания правил для [ModSecurity](https://www.modsecurity.org/) и без изменения первоначального исходного кода приложения
1. Реализовать информационный поток по времени, используя (или)
    * сокеты
    * доступ к файлу
    * время доступа к файлу
    * файловую систему /proc
1. Описать, как можно подробнее (чем подробнее, тем лучше), что произойдет когда вы наберете в адресной строке браузера https://google.com и нажмете Enter
1. Проанализировать и сравнить защищенность конфигураций SSL/TLS любых 10 популярных веб-ресурсов с помощью [сканера ssllabs.com](http://www.ssllabs.com)

## Материалы

### Обязательные
* [Matt Bishop. Introduction to Computer Security.](http://nob.cs.ucdavis.edu/book/book-intro/) Chapter 1 
* [Подкаст Noise Security Bit. Об образовании в области ИБ](http://noisebit.podster.fm/6)
* [Подкаст Noise Security Bit. О практической безопасности](http://noisebit.podster.fm/3)
* [В.Кочетков. Как разработать защищенное веб-приложение и не сойти при этом с ума](http://my.webinar.ru/record/140584/)
* [В. Кочетков. Информационная угрозология, уязвимоведение и рисководство](http://habrahabr.ru/post/129386/)
* [А. Масалович. Конкурентная разведка в Интернет](http://www.youtube.com/watch?v=HcwASJCk16k)
* [Н.А. Гайдамакин. Теоретические основы компьютерной безопасности.](http://elar.urfu.ru/bitstream/10995/1778/5/1335332_schoolbook.pdf) Глава 1.
* [А. Гостев. Особенности национальной охоты](https://www.youtube.com/watch?v=Canud1V4Fww)
* [В. Дубровин. Ошибки использования безопасных протоколов и их эксплуатация](http://live.digitaloctober.ru/embed/2996#time1400752650)

### Рекомендуемые
* П.Н. Девянин. Модели безопасности компьютерных систем. Управление доступом и информационными потоками. 2-е изд.
* С.П. Расторгуев. Информационная война. Проблемы и модели. Экзистенциальная математика
* К. Касперски. Техника сетевых атак

### Справочные
* [Matt Bishop. Computer Security: Art and Sciense](http://nob.cs.ucdavis.edu/book/book-aands/)
* [А.В. Лукацкий. Моделирование угроз](http://www.slideshare.net/lukatsky/ss-13257562)

## Оценка уровня знаний по компьютерной безопасности
* [Information Security Interview Questions](http://danielmiessler.com/study/infosec_interview_questions/)
* [Security Related Interview Questions for all Engineers](https://www.netmeister.org/blog/security-questions.html)
* [Application security related questions for developers](https://teamquiz.aspectsecurity.com)
* [XSS Game](https://xss-game.appspot.com/)
* [Gruyere codelab](https://google-gruyere.appspot.com/)
* [The Matasano Crypto Challenges](http://cryptopals.com/)
