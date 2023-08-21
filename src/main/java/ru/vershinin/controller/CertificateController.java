package ru.vershinin.controller;

import ru.vershinin.service.CertificateService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

@RestController
public class CertificateController {

    @Autowired
    private CertificateService certificateService;
    @ApiOperation(value = "Создание сертификата",
            notes = "Этот метод позволяет создать новый сертификат с указанным именем и паролем.",
            produces = "text/plain")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Сертификат успешно создан"),
            @ApiResponse(code = 500, message = "Внутренняя ошибка сервера")
    })
    @PostMapping("/certificate")
    public String createCertificate(
            @ApiParam(value = "Имя для нового сертификата", required = true)
            @RequestParam String name,
            @ApiParam(value = "Пароль для нового сертификата", required = true)
            @RequestParam String password)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        return certificateService.createCertificate(name, password);
    }
    @ApiOperation(value = "Отзыв сертификата",
            notes = "Этот метод позволяет отозвать сертификат по указанному имени.",
            produces = "text/plain")
    @ApiResponses(value = {
            @ApiResponse(code = 200, message = "Сертификат успешно отозван"),
            @ApiResponse(code = 500, message = "Внутренняя ошибка сервера")
    })
    @PostMapping("/revoke")
    public String createCertificate(
            @ApiParam(value = "Имя сертификата для отзыва", required = true)
            @RequestParam String name)
            throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, InvalidKeySpecException, OperatorCreationException, CRLException {
        certificateService.revokeCertificate(name);
        return HttpStatus.OK.toString();
    }
}
