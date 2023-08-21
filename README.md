# <span style="color:blue">Сервис для работы с сертификатами и подписью документов</span>
[Открыть Swagger UI](http://localhost:8080/swagger-ui.html#)

Данный <span style="font-family:Courier New">сервис</span> предоставляет <span style="font-weight:bold">API</span> для выполнения операций связанных с <span style="font-style:italic">созданием</span>, <span style="text-decoration:underline">подписью</span> и <span style="text-decoration:underline;font-style:italic">проверкой</span> сертификатов, а также подписью и валидацией <span style="font-family:Courier New">PDF</span> документов. Он использует библиотеки <span style="color:green">Bouncy Castle</span> и <span style="color:purple">iTextPDF</span> для обеспечения функциональности.

## <span style="font-family:Courier New">API Методы</span>

### <span style="font-family:Courier New">POST /certificate</span>
Создание нового сертификата.

**Описание:**
Этот метод позволяет создать новый сертификат с указанным именем и паролем.

**Параметры запроса:**
- <span style="color:red">`name`</span> (обязательный) - Имя для нового сертификата.
- <span style="color:red">`password`</span> (обязательный) - Пароль для нового сертификата.

**Ответ:**
- Код статуса <span style="color:purple">200</span>: Сертификат успешно создан.
- Код статуса <span style="color:purple">500</span>: Внутренняя ошибка сервера.

### <span style="font-family:Courier New">POST /revoke</span>
Отзыв сертификата.

**Описание:**
Этот метод позволяет отозвать сертификат по указанному имени.

**Параметры запроса:**
- <span style="color:red">`name`</span> (обязательный) - Имя сертификата для отзыва.

**Ответ:**
- Код статуса <span style="color:purple">200</span>: Сертификат успешно отозван.
- Код статуса <span style="color:purple">500</span>: Внутренняя ошибка сервера.

### <span style="font-family:Courier New">POST /sign</span>
Подписание PDF документа.

**Описание:**
Этот метод позволяет подписать загруженный <span style="font-family:Courier New">PDF</span> документ с использованием указанного сертификата и типа подписи.

**Параметры запроса:**
- <span style="color:red">`certificateId`</span> (обязательный) - Идентификатор сертификата.
- <span style="color:red">`file`</span> (обязательный) - <span style="font-family:Courier New">PDF</span> файл для подписи.
- <span style="color:red">`type`</span> (обязательный) - Тип подписи.

**Ответ:**
- Код статуса <span style="color:purple">200</span>: Подписанный <span style="font-family:Courier New">PDF</span> документ.
- Код статуса <span style="color:purple">400</span>: Некорректные входные данные.
- Код статуса <span style="color:purple">500</span>: Внутренняя ошибка сервера.

### <span style="font-family:Courier New">GET /checkValidCert</span>
Проверка валидности сертификата.

**Описание:**
Этот метод позволяет проверить валидность сертификата по указанной дате.

**Параметры запроса:**
- <span style="color:red">`certificateId`</span> (обязательный) - Идентификатор сертификата.
- <span style="color:red">`dateString`</span> (обязательный) - Дата для проверки в формате 'yyyy-MM-dd'.

**Ответ:**
- Код статуса <span style="color:purple">200</span>: Сертификат валиден.
- Код статуса <span style="color:purple">400</span>: Некорректные входные данные.
- Код статуса <span style="color:purple">500</span>: Внутренняя ошибка сервера.

## <span style="font-family:Courier New">Требования</span>
- Java 8 или выше.
- Зависимости на библиотеки <span style="color:green">Bouncy Castle</span> и <span style="color:purple">iTextPDF</span>.

## <span style="font-family:Courier New">Примечание</span>
Данный файл представляет собой обобщенное описание функциональности сервиса и методов. Вам необходимо адаптировать код и описания к вашему проекту, учитывая фактические имена классов, методов и параметров.
idateCertificate: Проверка валидности сертификата на указанную дату.