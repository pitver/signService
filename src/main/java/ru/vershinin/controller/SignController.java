package ru.vershinin.controller;

import ru.vershinin.dto.CertificateValidationResultDto;
import ru.vershinin.service.SignService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@RestController
@RequiredArgsConstructor
public class SignController {

    private final SignService signService;
    @ApiOperation(value = "Загрузка и подписание PDF документа",
            notes = "Этот метод позволяет загрузить PDF документ, подписать его и вернуть подписанный документ.",
            consumes = "multipart/form-data",
            produces = "application/pdf")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Успешно подписанный документ", response = ByteArrayResource.class),
            @ApiResponse(code = 400, message = "Некорректные входные данные"),
            @ApiResponse(code = 500, message = "Внутренняя ошибка сервера")
    })
    @PostMapping("/sign")
    public ResponseEntity<ByteArrayResource> signDocument(
            @ApiParam(value = "Идентификатор сертификата", required = true, example = "1")
            @RequestParam Long certificateId,
            @ApiParam(value = "PDF файл для подписи", required = true)
            @RequestParam MultipartFile file,
            @ApiParam(value = "Тип подписи: 1-искать сертификаты в системе(windows), 2 -сгенерированный в бд", required = true, example = "1")
            @RequestParam int type){
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=encoded.pdf");
        byte[] res = signService.signDocument(certificateId, file,type);
        // Create a ByteArrayResource from the file contents
        ByteArrayResource resource = new ByteArrayResource(res);

        // Return the response with the file contents
        return ResponseEntity.ok()
                .headers(headers)
                .contentLength(res.length)
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);

    }
    @ApiOperation(value = "Проверка валидности сертификата",
            notes = "Этот метод позволяет проверить валидность сертификата по указанной дате.",
            produces = "text/plain")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Сертификат валиден"),
            @ApiResponse(code = 400, message = "Некорректные входные данные"),
            @ApiResponse(code = 500, message = "Внутренняя ошибка сервера")
    })
    @GetMapping("/checkValidCert")
    public ResponseEntity<String> validateCertificate(
            @ApiParam(value = "Идентификатор сертификата", required = true, example = "1")
            @RequestParam Long certificateId,
            @ApiParam(value = "Дата для проверки в формате 'yyyy-MM-dd'", required = true, example = "2023-08-21")
            @RequestParam(required = true) String dateString) {

        Date date ;
        try {
            date = new SimpleDateFormat("yyyy-MM-dd").parse(dateString);
        } catch (ParseException e) {
            return ResponseEntity.badRequest().body("Invalid date format");
        }
        // Вызов метода сервиса
        CertificateValidationResultDto result = signService.validateCertificate(certificateId, date);

        // Создание объекта ResponseEntity
        if (result.isValid()) {
            return ResponseEntity.ok(result.getMessage());
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(result.getMessage());
        }

    }
}
