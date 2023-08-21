package ru.vershinin.service;

import ru.vershinin.dto.CertificateValidationResultDto;
import ru.vershinin.exeption.SignServiceException;
import ru.vershinin.model.CertificateEntity;
import ru.vershinin.model.CrlEntity;
import ru.vershinin.repository.CertificateRepository;
import ru.vershinin.repository.CrlEntityRepository;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.*;
import javassist.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import sun.security.mscapi.SunMSCAPI;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Enumeration;


@Service
@RequiredArgsConstructor
public class SignService {


    private final CertificateRepository certificateRepository;
    private final CrlEntityRepository crlRepository;

    public byte[] signDocument(Long certificateId, MultipartFile file, int type) {
        try {
            String nameCN = null;
            PrivateKey privateKey = null;
            Certificate[] chain = null;
            if (type == 2) {
                Security.addProvider(new BouncyCastleProvider());
                // Получение закрытого ключа подписи из базы данных
                CertificateEntity certificateEntity = certificateRepository.findById(certificateId)
                        .orElseThrow(() -> new NotFoundException("Certificate not found"));
                privateKey = getPrivateKey(certificateEntity.getPrivateKey());
                //получение цепочки сертификатов
                chain = getCertificates(certificateEntity);
            } else {
                // Получение экземпляра хранилища сертификатов типа "Windows-MY"
                KeyStore ks = KeyStore.getInstance("Windows-MY");
                ks.load(null, null);


                // Получение списка алиасов всех сертификатов в хранилище
                Enumeration<String> aliases = ks.aliases();

                // Перебор всех сертификатов и вывод их информации
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    Certificate cert = ks.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        X509Certificate x509Cert = (X509Certificate) cert;
                        // Получение закрытого ключа для сертификата
                        Key key = ks.getKey(alias, null);
                        if (key instanceof PrivateKey) {
                            privateKey = getPrivateKey((PrivateKey) key);
                            // Установить имя владельца сертификата в качестве имени подписи
                            X500Name x500name = new JcaX509CertificateHolder(x509Cert).getSubject();
                            nameCN = x500name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
                            // Получение цепочки сертификатов для сертификата
                            chain = getCertificates(x509Cert);

                        }

                    }
                }
            }

            // Подписание PDF документа
            // Расшифруйте PDF-документ из file и создайте PdfStamper для применения цифровой подписи к документу
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            PdfReader reader = new PdfReader(file.getInputStream());
            PdfStamper stamper = PdfStamper.createSignature(reader, outputStream, '\0');
            //становить имя владельца сертификата в качестве имени подписи
            X509Certificate cert = (X509Certificate) chain[0];
            X500Name x500name = new JcaX509CertificateHolder(cert).getSubject();
            nameCN = x500name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
            // Настройка внешнего вида цифровой подписи
            // Задайте причину, местоположение и видимый прямоугольник подписи для цифровой подписи
            PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
            appearance.setReason("Подпись документа");
            appearance.setLocation("Москва");
            appearance.setLayer2Text(("Подпись\n" + nameCN + "\n" + LocalDateTime.now().withNano(0)));
            appearance.setVisibleSignature(new Rectangle(36, 748, 144, 780), 1, "signature");

            //  Сгенерируйте цифровую подпись, используя закрытый ключ и BouncyCastleProvider или SunMSCAPI
            assert privateKey != null;
            ExternalSignature signature = new PrivateKeySignature(privateKey, "SHA-256", getProvider(type));
            ExternalDigest digest = new BouncyCastleDigest();
            MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, MakeSignature.CryptoStandard.CMS);
            stamper.close();

            // Сохранение подписанного документа и возвращение его в base64 кодировке
            // Сохраните подписанный документ в массив байтов и закодируйте его в Base64 перед возвратом
            return outputStream.toByteArray();
        } catch (IOException | DocumentException | GeneralSecurityException ex) {
            throw new SignServiceException("Failed to sign the document", ex);
        } catch (NotFoundException ex) {
            throw new SignServiceException("Certificate not found", ex);
        }

    }

    private String getProvider(int type) {
        if (type == 1) {
            Provider sunMSCAPI = Security.getProvider("SunMSCAPI");
            return sunMSCAPI.getName();
        } else {
            return "BC";
        }
    }

    private Certificate[] getCertificates(CertificateEntity certificateEntity) throws CertificateException {
        byte[] certData = certificateEntity.getCertificate();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certData));
        Certificate[] chain = new Certificate[1];
        chain[0] = certificate;
        return chain;
    }

    private Certificate[] getCertificates(X509Certificate certificate) {

        Certificate[] chain = new Certificate[1];
        chain[0] = certificate;
        return chain;
    }


    public CertificateValidationResultDto validateCertificate(Long certificateId, Date date) {

        try {
            // Получение сертификата из базы данных
            CertificateEntity certificateEntity = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new NotFoundException("Certificate not found"));

            // Создание объекта X509Certificate из байтового массива сертификата
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateEntity.getCertificate()));
            CrlEntity crlEntity = crlRepository.findByName(certificateEntity.getName());
            if (crlEntity != null) {
                byte[] crlBytes = crlEntity.getCrl();
                X509CRL crl = (X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(crlBytes));
                if (crl.isRevoked(certificate)) {
                    return new CertificateValidationResultDto(false,"The certificate is revoked");
                }
            }
            // Проверка действительности сертификата для указанной даты
            certificate.checkValidity(date);
            certificate.verify(certificate.getPublicKey()); // Проверка подписи

            return new CertificateValidationResultDto(true,"Certificate is valid");
        } catch (CertificateException e) {
            return new CertificateValidationResultDto(false,"Certificate has expired: " + e.getMessage());
        } catch (NotFoundException e) {
            return new CertificateValidationResultDto(false,"Certificate not found: " + e.getMessage());
        } catch (CRLException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            return new CertificateValidationResultDto(false,"Certificate validation failed: " + ex.getMessage());
        }

    }


    private PrivateKey getPrivateKey(byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Здесь RSA может быть заменено на другой алгоритм, если используется другой алгоритм ключа.
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new SignServiceException("Failed to get private key", ex);
        }
    }

    private static PrivateKey getPrivateKey(PrivateKey privateKey) {
        try {
            if (privateKey instanceof RSAPrivateKey) {
                Security.addProvider(new BouncyCastleProvider());
                KeyFactory keyFactory = KeyFactory.getInstance(privateKey.getAlgorithm()); // Здесь RSA может быть заменено на другой алгоритм, если используется другой алгоритм ключа.
                PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKey.toString().getBytes(StandardCharsets.UTF_8));
                return keyFactory.generatePrivate(privateKeySpec);
            } else {
                Security.addProvider(new SunMSCAPI());
                return privateKey;
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new SignServiceException("Failed to get private key", ex);
        }
    }

}