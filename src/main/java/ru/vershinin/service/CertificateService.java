package ru.vershinin.service;

import ru.vershinin.model.CertificateEntity;
import ru.vershinin.model.CrlEntity;
import ru.vershinin.repository.CertificateRepository;
import ru.vershinin.repository.CrlEntityRepository;
import lombok.RequiredArgsConstructor;
import lombok.var;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;

@Service
@RequiredArgsConstructor
public class CertificateService {


    private final CertificateRepository certificateRepository;
    private final CrlEntityRepository crlRepository;


    public String createCertificate(String name, String password) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException {
        // Генерация ключа подписи и создание сертификата
        KeyPair keyPair = generateKeyPair();
        // генерируем сертификат на основе публичного и приватного ключей и владельца
        X509Certificate certificate = generateCertificate(keyPair.getPublic(), keyPair.getPrivate(), name);
       // addCertificateToKeyStore(certificate);

        // Сохранение сертификата и ключа в базу данных или файловую систему
        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        byte[] certificateBytes = certificate.getEncoded();
        CertificateEntity certificateEntity = new CertificateEntity();
        certificateEntity.setName(name);
        certificateEntity.setPrivateKey(privateKeyBytes);
        certificateEntity.setCertificate(certificateBytes);
        certificateEntity.setRevoked(false);
        certificateRepository.save(certificateEntity);

        // Возвращение публичного ключа сертификата
        return Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded());
    }

    private KeyPair generateKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateCertificate(PublicKey publicKey, PrivateKey privateKey, String name) {
        try {
            // добавляем Bouncy Castle провайдер для подписания сертификата
            Security.addProvider(new BouncyCastleProvider());

            // создаем объект, представляющий владельца сертификата
            X500Name dnName = new X500Name("CN=" + name);

            // создаем серийный номер для сертификата
            BigInteger certSerialNumber = new BigInteger(64, new SecureRandom());

            // задаем дату начала действия сертификата (вчера)
            Date validityStartDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);

            // задаем дату окончания действия сертификата (через 2 года)
            Date validityEndDate = new Date(System.currentTimeMillis() + 2L * 365 * 24 * 60 * 60 * 1000);

            // создаем объект, представляющий строитель сертификата
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber,
                    validityStartDate, validityEndDate, dnName, publicKey);

           /*создаем объект ContentSigner с использованием алгоритма SHA256WithRSA и приватного ключа
             который будет использоваться для подписи сертификата.
             Мы используем JcaContentSignerBuilder для создания объекта ContentSigner,
             указывая алгоритм подписи SHA256WithRSA и приватный ключ, который мы передаем методу build().*/
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);

            // создаем объект, представляющий подписанный сертификат
            X509CertificateHolder certHolder = certBuilder.build(contentSigner);

            // создаем экземпляр класса X509Certificate из X509CertificateHolder
            return new JcaX509CertificateConverter().getCertificate(certHolder);
        } catch (Exception ex) {
            // обрабатываем исключение
            throw new RuntimeException(ex);
        }
    }

    public void revokeCertificate(String name) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException, KeyStoreException, IOException, CRLException, InvalidKeySpecException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());
        // Load the certificate from the database or file system
        CertificateEntity certificateEntity = certificateRepository.findByName(name);
        byte[] certificateBytes = certificateEntity.getCertificate();
        byte[] privateKeyBytes = certificateEntity.getPrivateKey();
        // Преобразование закодированных данных в объекты Java
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));

        // Создание CRL
        X500Name issuer = new X500Name(certificate.getSubjectX500Principal().getName());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuer, new Date());
        crlBuilder.addCRLEntry(certificate.getSerialNumber(), new Date(), 1);
        var crl =
                crlBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey));


        // Save the CRL to a file or database
        byte[] crlBytes = crl.getEncoded();
        CrlEntity crlEntity = new CrlEntity();
        crlEntity.setName(name);
        crlEntity.setCrl(crlBytes);
        crlRepository.save(crlEntity);

        // Update the certificate entity in the database or file system to reflect the revocation
        certificateEntity.setRevoked(true);
        certificateRepository.save(certificateEntity);
    }






    public void viewKeystore(String keystoreFilename, String keystorePassword) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystoreFilename), keystorePassword.toCharArray());
        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            var cert =  keystore.getCertificate(alias);
            System.out.println("Alias: " + alias);
            System.out.println("Type: " + cert.getType());
        }
    }

    public void viewKeystore() throws Exception {
        // Получение экземпляра хранилища сертификатов типа "Windows-MY"
        KeyStore ks = KeyStore.getInstance("Windows-MY");
        ks.load(null, null);

        // Получение списка алиасов всех сертификатов в хранилище
        Enumeration<String> aliases = ks.aliases();
        // Перебор всех сертификатов и вывод их информации
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.getCertificate(alias);
            System.out.println("Alias: " + alias);
            System.out.println("Type: " + cert.getType());
        }
    }


}